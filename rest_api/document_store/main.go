package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"vhsm.document_store/minio_utils"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
)

// ---------------------------------------------------------------------------
// HSM service
//
// The PKCS#11 module is initialized ONCE at application startup (not per
// incoming HTTP request). The symmetric key handle is resolved once as
// well. For each encryption we open a dedicated session (cheap operation)
// so concurrent requests do not interfere. The PKCS#11 module is never
// Finalize()'d while other goroutines may still use it.
// ---------------------------------------------------------------------------

const (
	gcmIVSize    = 12       // recommended IV size for AES-GCM (96 bits)
	gcmTagBits   = 128      // authentication tag size for GCM
	maxBodyBytes = 50 << 20 // 50 MiB, adjust according to your needs
)

type HSMService struct {
	ctx   *pkcs11.Ctx
	slot  uint
	pin   string
	label string
	// PKCS#11 implementations differ in their concurrency guarantees.
	// This mutex serializes sensitive operations if the underlying token
	// does not support safe concurrent use across sessions.
	mu sync.Mutex
}

// NewHSMService initializes the PKCS#11 module and locates the slot that
// contains the token with the requested token label. This initialization
// should be performed only once during the process lifetime.
func NewHSMService(modulePath, tokenLabel, pin, keyLabel string) (*HSMService, error) {
	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, fmt.Errorf("impossible de charger le module PKCS#11 : %s", modulePath)
	}
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("initialisation PKCS#11 échouée : %w", err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		p.Finalize()
		return nil, fmt.Errorf("GetSlotList échoué : %w", err)
	}

	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimSpace(tokenInfo.Label) == tokenLabel {
			return &HSMService{
				ctx:   p,
				slot:  slot,
				pin:   pin,
				label: keyLabel,
			}, nil
		}
	}

	p.Finalize()
	return nil, fmt.Errorf("aucun slot trouvé avec le token %q", tokenLabel)
}

// Close finalizes the PKCS#11 module. Call once during application shutdown.
func (h *HSMService) Close() {
	if h.ctx != nil {
		h.ctx.Finalize()
	}
}

// Encrypt performs AES-GCM encryption inside the HSM and returns the IV and
// the ciphertext (which includes the authentication tag as produced by the
// PKCS#11 API). The IV is randomly generated per call; it is not secret and
// must be stored/transmitted with the ciphertext for later decryption.
func (h *HSMService) Encrypt(plaintext []byte) (iv []byte, ciphertext []byte, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	session, err := h.ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, nil, fmt.Errorf("ouverture de session échouée : %w", err)
	}
	defer h.ctx.CloseSession(session)

	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		return nil, nil, fmt.Errorf("login échoué : %w", err)
	}
	defer h.ctx.Logout(session)

	// Explicitly filter for objects of class CKO_SECRET_KEY to avoid
	// accidentally matching other object types (certificates, public
	// keys, etc.) that may have the same label.
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.label),
	}
	if err := h.ctx.FindObjectsInit(session, template); err != nil {
		return nil, nil, fmt.Errorf("FindObjectsInit échoué : %w", err)
	}
	objs, _, err := h.ctx.FindObjects(session, 1)
	if ferr := h.ctx.FindObjectsFinal(session); ferr != nil {
		log.Printf("FindObjectsFinal: %v", ferr)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("FindObjects échoué : %w", err)
	}
	if len(objs) == 0 {
		return nil, nil, fmt.Errorf("clé secrète avec label %q introuvable", h.label)
	}

	// Generate a fresh, unique IV for this operation. NEVER reuse an IV
	// with the same key.
	iv = make([]byte, gcmIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("génération de l'IV échouée : %w", err)
	}

	gcmParams := pkcs11.NewGCMParams(iv, nil, gcmTagBits)
	defer gcmParams.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)}
	if err := h.ctx.EncryptInit(session, mech, objs[0]); err != nil {
		return nil, nil, fmt.Errorf("EncryptInit échoué : %w", err)
	}

	ciphertext, err = h.ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("Encrypt échoué : %w", err)
	}

	// Some HSMs ignore the provided IV and generate their own; read back the
	// actual IV used to ensure we store the correct value.
	if actualIV := gcmParams.IV(); len(actualIV) > 0 {
		iv = actualIV
	}

	return iv, ciphertext, nil
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

var thesisIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func validateThesisID(id string) error {
	if !thesisIDPattern.MatchString(id) {
		return errors.New("thesisId invalide : caractères alphanumériques, '-' et '_' uniquement, 128 caractères max")
	}
	return nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("variable d'environnement requise manquante : %s", key)
	}
	return v
}

func main() {
	minioUser := os.Getenv("MINIO_ROOT_USER")
	minioPass := os.Getenv("MINIO_ROOT_PASSWORD")
	hsmPin := os.Getenv("HSM_PIN")
	hsmLabel := os.Getenv("HSM_LABEL")
	hsmTokenLabel := os.Getenv("HSM_TOKEN_LABEL")
	if hsmTokenLabel == "" {
		hsmTokenLabel = "MonToken"
	}
	hsmModulePath := os.Getenv("HSM_MODULE_PATH")
	if hsmModulePath == "" {
		hsmModulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}
	bucketName := os.Getenv("MINIO_BUCKET")
	if bucketName == "" {
		bucketName = "thesis"
	}

	minioService, err := minio_utils.NewMinioService("minio:9000", minioUser, minioPass)
	if err != nil {
		log.Fatalf("connexion MinIO échouée : %v", err)
	}

	hsmService, err := NewHSMService(hsmModulePath, hsmTokenLabel, hsmPin, hsmLabel)
	if err != nil {
		log.Fatalf("initialisation HSM échouée : %v", err)
	}
	defer hsmService.Close()

	r := gin.Default()
	// Limit the request body size to prevent a large upload from exhausting
	// server memory.
	r.MaxMultipartMemory = maxBodyBytes

	r.POST("/api/v1/encrypt", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

		thesisID := c.PostForm("thesisId")
		if err := validateThesisID(thesisID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		file, header, err := c.Request.FormFile("document")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Aucun fichier fourni"})
			return
		}
		defer file.Close()

		plaintext, err := io.ReadAll(file)
		if err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Fichier illisible ou trop volumineux : " + err.Error()})
			return
		}

		// Hash the original plaintext. This hash is meaningful for ledger
		// anchoring (it proves the integrity of the original document after
		// decryption without revealing its content). Hashing the ciphertext
		// would not be suitable because the IV changes per encryption.
		plaintextHash := sha256.Sum256(plaintext)

		iv, ciphertext, err := hsmService.Encrypt(plaintext)
		if err != nil {
			log.Printf("erreur de chiffrement : %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Échec du chiffrement"})
			return
		}

		// Prefix the IV to the stored ciphertext. The IV is not secret but is
		// required to decrypt later.
		payload := append(append([]byte{}, iv...), ciphertext...)

		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()

		err = minioService.UploadThesis(ctx, bucketName, header.Filename, bytes.NewReader(payload), int64(len(payload)), thesisID)
		if err != nil {
			log.Printf("erreur d'upload MinIO : %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Échec de l'envoi vers le stockage"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "Success",
			"ledger": map[string]interface{}{
				"thesisId":      thesisID,
				"plaintextHash": hex.EncodeToString(plaintextHash[:]),
				"time":          time.Now().Unix(),
			},
		})
	})

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("le serveur HTTP s'est arrêté de façon inattendue : %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("arrêt du serveur en cours...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("arrêt forcé du serveur : %v", err)
	}
}
