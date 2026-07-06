package internal

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

const (
	gcmIVSize    = 12       // recommended IV size for AES-GCM (96 bits)
	gcmTagBits   = 128      // authentication tag size for GCM
	maxBodyBytes = 50 << 20 // 50 MiB, adjust according to your needs
)

type HSMService struct {
	ctx       *pkcs11.Ctx
	slot      uint
	pin       string
	mu        sync.Mutex
	label     string
	signLabel string
}

// NewHSMService initializes the PKCS#11 module and locates the slot that
// contains the token with the requested token label. This initialization
// should be performed only once during the process lifetime.
func NewHSMService(modulePath, tokenLabel, pin, keyLabel string, signKeyLabel string) (*HSMService, error) {
	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("PKCS#11 initialization failed: %w", err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		p.Finalize()
		return nil, fmt.Errorf("GetSlotList failed: %w", err)
	}

	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimSpace(tokenInfo.Label) == tokenLabel {
			return &HSMService{
				ctx:       p,
				slot:      slot,
				pin:       pin,
				label:     keyLabel,
				signLabel: signKeyLabel,
			}, nil
		}
	}

	p.Finalize()
	return nil, fmt.Errorf("no slot found with token %q", tokenLabel)
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
		return nil, nil, fmt.Errorf("session open failed: %w", err)
	}
	defer h.ctx.CloseSession(session)

	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		return nil, nil, fmt.Errorf("login failed: %w", err)
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
		return nil, nil, fmt.Errorf("FindObjectsInit failed: %w", err)
	}
	objs, _, err := h.ctx.FindObjects(session, 1)
	if ferr := h.ctx.FindObjectsFinal(session); ferr != nil {
		log.Printf("FindObjectsFinal: %v", ferr)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("FindObjects failed: %w", err)
	}
	if len(objs) == 0 {
		return nil, nil, fmt.Errorf("secret key with label %q not found", h.label)
	}

	// Generate a fresh, unique IV for this operation. NEVER reuse an IV
	// with the same key.
	iv = make([]byte, gcmIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("IV generation failed: %w", err)
	}

	gcmParams := pkcs11.NewGCMParams(iv, nil, gcmTagBits)
	defer gcmParams.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)}
	if err := h.ctx.EncryptInit(session, mech, objs[0]); err != nil {
		return nil, nil, fmt.Errorf("EncryptInit failed: %w", err)
	}

	ciphertext, err = h.ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("Encrypt failed: %w", err)
	}

	// Some HSMs ignore the provided IV and generate their own; read back the
	// actual IV used to ensure we store the correct value.
	if actualIV := gcmParams.IV(); len(actualIV) > 0 {
		iv = actualIV
	}

	return iv, ciphertext, nil
}

// signHash signs an already-computed SHA256 digest (given as hex) using the
// long-lived HSM session. The caller is responsible for ensuring hashHex is
// the exact hash that should be reported alongside the signature, so the
// signed value and the displayed hash are provably the same bytes.
// Ajoutez cette méthode à votre struct HSMService dans hsm.go
func (h *HSMService) Sign(data []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 1. Ouvrir session
	session, err := h.ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	defer h.ctx.CloseSession(session)
	h.ctx.Login(session, pkcs11.CKU_USER, h.pin)
	defer h.ctx.Logout(session)

	// 2. Trouver la clé privée (Attention : utiliser CKO_PRIVATE_KEY)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.signLabel),
	}
	h.ctx.FindObjectsInit(session, template)
	objs, _, _ := h.ctx.FindObjects(session, 1)
	h.ctx.FindObjectsFinal(session)
	if len(objs) == 0 {
		return nil, fmt.Errorf("private key not found")
	}

	// 3. Signer (CKM_SHA256_RSA_PKCS ou CKM_ECDSA selon votre clé)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}
	h.ctx.SignInit(session, mech, objs[0])
	return h.ctx.Sign(session, data)
}
