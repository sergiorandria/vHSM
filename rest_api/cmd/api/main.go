package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"electronic_signature/rest_api/gateway_sdk"
	"electronic_signature/rest_api/internal"
	"electronic_signature/rest_api/utils"

	"github.com/gin-gonic/gin"
)

const maxUploadSize = 50 << 20 // 50 MiB

const defaultTokenTTL = time.Hour

// storedFile describes the outcome of encrypting, uploading and hashing a
// single defense-time document (the thesis PDF, or — on first upload only —
// the PV).
type storedFile struct {
	ObjectName string
	Hash       string
	IV         string
}

// thesisLedgerView is a minimal, local decode of the on-chain
// ThesisPayload (see chaincode.go). We only pull the fields the API needs
// to decide things server-side (has the PV already been established? what
// hash must a new co-signer sign over?) — it deliberately does not try to
// mirror the full ledger schema, so it won't need updating every time an
// unrelated field is added on the chaincode side.
type thesisLedgerView struct {
	Status string `json:"status"`
	HashPv string `json:"hashPv"`
}

// readUploadedFile reads a multipart file capped at maxUploadSize. label is
// only used to make error messages identify which upload failed.
func readUploadedFile(fh *multipart.FileHeader, label string) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file: %w", label, err)
	}
	defer f.Close()

	lr := io.LimitReader(f, maxUploadSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s file: %w", label, err)
	}
	if int64(len(data)) > maxUploadSize {
		return nil, fmt.Errorf("%s file too large", label)
	}
	return data, nil
}

// encryptSignAndStore reads an uploaded file, encrypts it inside the HSM,
// uploads the resulting blob to MinIO, then hashes and signs the stored
// blob. Used for the thesis document, which — unlike the PV — is a single-
// signature artifact with no cross-juror hash agreement to preserve.
func encryptSignAndStore(
	ctx context.Context,
	minioSvc *internal.MinioService,
	hsmSvc *internal.HSMService,
	bucket string,
	thesisID string,
	label string,
	fh *multipart.FileHeader,
) (*storedFile, string, error) {
	data, err := readUploadedFile(fh, label)
	if err != nil {
		return nil, "", err
	}

	iv, ciphertext, err := hsmSvc.Encrypt(data)
	if err != nil {
		return nil, "", fmt.Errorf("HSM encrypt error (%s): %w", label, err)
	}

	objectName := fmt.Sprintf("%s-%s-%s", thesisID, label, fh.Filename)
	blob := append(iv, ciphertext...)
	if err := minioSvc.UploadThesis(ctx, bucket, objectName, bytes.NewReader(blob), int64(len(blob)), thesisID); err != nil {
		return nil, "", fmt.Errorf("upload failed (%s): %w", label, err)
	}

	h := sha256.Sum256(blob)
	hashHex := hex.EncodeToString(h[:])

	sigBytes, err := hsmSvc.Sign(h[:])
	if err != nil {
		return nil, "", fmt.Errorf("HSM sign error (%s): %w", label, err)
	}
	sig := hex.EncodeToString(sigBytes)

	return &storedFile{ObjectName: objectName, Hash: hashHex, IV: hex.EncodeToString(iv)}, sig, nil
}

// signHashHex asks the HSM to sign a hash that's already on record
// (hex-encoded), returning the hex-encoded signature. Used by the PV
// co-signing endpoint: every signer after the first signs the same
// previously-recorded hash rather than a freshly computed one.
func signHashHex(hsmSvc *internal.HSMService, hashHex string) (string, error) {
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("invalid stored pv hash: %w", err)
	}
	sigBytes, err := hsmSvc.Sign(hashBytes)
	if err != nil {
		return "", fmt.Errorf("HSM sign error (pv): %w", err)
	}
	return hex.EncodeToString(sigBytes), nil
}

func main() {
	// Env
	minioEndpoint := os.Getenv("MINIO_ENDPOINT")
	minioAccess := os.Getenv("MINIO_ACCESS_KEY")
	minioSecret := os.Getenv("MINIO_SECRET_KEY")
	minioBucket := os.Getenv("MINIO_BUCKET")

	if minioBucket == "" {
		minioBucket = "thesis"
	}

	hsmModule := os.Getenv("HSM_MODULE_PATH")
	hsmToken := os.Getenv("HSM_TOKEN_LABEL")
	hsmPin := os.Getenv("HSM_PIN")
	hsmKeyLabel := os.Getenv("HSM_LABEL")
	hsmSignKeyLabel := os.Getenv("HSM_SIGN_LABEL")

	// JWT
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("JWT_SECRET must be set")
	}
	tokenTTL := defaultTokenTTL
	if v := os.Getenv("JWT_TTL_MINUTES"); v != "" {
		if mins, err := strconv.Atoi(v); err == nil && mins > 0 {
			tokenTTL = time.Duration(mins) * time.Minute
		} else {
			log.Printf("invalid JWT_TTL_MINUTES=%q, using default of %s", v, defaultTokenTTL)
		}
	}

	// LDAP
	ldapCfg := internal.LDAPConfig{
		URL:          os.Getenv("LDAP_URL"),
		BindDN:       os.Getenv("LDAP_BIND_DN"),
		BindPassword: os.Getenv("LDAP_BIND_PASSWORD"),
		UserBaseDN:   os.Getenv("LDAP_USER_BASE_DN"),
		UserFilter:   os.Getenv("LDAP_USER_FILTER"),
		GroupBaseDN:  os.Getenv("LDAP_GROUP_BASE_DN"),
		GroupFilter:  os.Getenv("LDAP_GROUP_FILTER"),
		RoleAttr:     os.Getenv("LDAP_ROLE_ATTR"),
		UseTLS:       os.Getenv("LDAP_USE_TLS") == "true",
		InsecureSkip: os.Getenv("LDAP_INSECURE_SKIP_VERIFY") == "true",
	}
	if ldapCfg.RoleAttr == "" {
		ldapCfg.RoleAttr = "cn"
	}
	ldapSvc := internal.NewLDAPAuthService(ldapCfg)

	// Loads configuration file from
	// /etc/vhsmd/default-fabric.conf
	cfg, err := utils.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	grpcConn, err := utils.NewGrpcConnection(cfg)
	if err != nil {
		log.Fatalf("failed to create grpc connection: %v", err)
	}

	id, err := utils.NewIdentity(cfg)
	if err != nil {
		log.Fatalf("failed to create identity: %v", err)
	}

	sign, err := utils.NewSign(cfg)
	if err != nil {
		log.Fatalf("failed to create signer: %v", err)
	}

	// cfg.ChannelName and cfg.ChaincodeName replace the old constants
	fabricClient, err := gateway_sdk.NewGatewayClient(grpcConn, cfg.ChannelName, cfg.ChaincodeName, id, sign)
	if err != nil {
		log.Fatalf("failed to create gateway client: %v", err)
	}
	defer fabricClient.Close()

	// HSM
	hsmSvc, err := internal.NewHSMService(hsmModule, hsmToken, hsmPin, hsmKeyLabel, hsmSignKeyLabel)
	if err != nil {
		log.Fatalf("failed to init HSM service: %v", err)
	}
	defer hsmSvc.Close()

	// MinIO
	minioSvc, err := internal.NewMinioService(minioEndpoint, minioAccess, minioSecret)
	if err != nil {
		log.Fatalf("failed to init MinIO service: %v", err)
	}

	// Ensure bucket exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := internal.CreateBuckets(ctx, minioSvc.Client, []string{minioBucket}); err != nil {
		log.Fatalf("failed to ensure buckets: %v", err)
	}

	// Notary
	notarySvc := internal.NewNotaryService(fabricClient, hsmSvc, cfg.ChannelName)

	// HTTP server
	r := gin.Default()

	r.MaxMultipartMemory = maxUploadSize

	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// --- Auth ---

	r.POST("/api/v1/login", func(c *gin.Context) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
			return
		}

		user, err := ldapSvc.Authenticate(body.Username, body.Password)
		if err != nil {
			log.Printf("login failed for %q: %v", body.Username, err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}

		token, err := internal.IssueToken(user, []byte(jwtSecret), tokenTTL)
		if err != nil {
			log.Printf("token issuance failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"username":   user.Username,
			"roles":      user.Roles,
			"expires_in": int(tokenTTL.Seconds()),
		})
	})

	// authRequired parses and validates the bearer JWT, stashing the
	// claims in the request context for downstream handlers/permission
	// checks. It does NOT enforce any particular role — see
	// requirePermission for that.
	authRequired := func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed authorization header"})
			return
		}

		claims, err := internal.ParseToken(parts[1], []byte(jwtSecret))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		c.Set("claims", claims)
		c.Next()
	}

	// requirePermission builds middleware that denies the request unless
	// the authenticated user holds a role allowed to perform action
	// (per roles.go's actionPermissions map — fail closed on anything
	// not explicitly listed there).
	//
	// NOTE: the action names below now include SubmitJuryGrade, SignPv
	// and NotarizeDocument, replacing the old SubmitDocument action.
	// roles.go's actionPermissions map needs entries for these three or
	// every jury member will get a 403 the first time they try to use
	// them.
	requirePermission := func(action string) gin.HandlerFunc {
		return func(c *gin.Context) {
			raw, ok := c.Get("claims")
			if !ok {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
				return
			}
			claims, ok := raw.(*internal.SessionClaims)
			if !ok {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "corrupt session"})
				return
			}
			if !internal.HasPermission(claims.Roles, action) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("role(s) %v not permitted to %s", claims.Roles, action)})
				return
			}
			c.Next()
		}
	}

	// --- Protected routes ---
	r.GET("/api/v1/theses/:thesisId", authRequired, requirePermission("ReadThesis"), func(c *gin.Context) {
		thesisID := c.Param("thesisId")
		if thesisID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
			return
		}

		result, err := notarySvc.GetThesis(thesisID)
		if err != nil {
			log.Printf("get thesis failed: %v", err)
			c.JSON(http.StatusNotFound, gin.H{"error": "thesis not found"})
			return
		}

		c.Data(http.StatusOK, "application/json", result)
	})

	r.GET("/api/v1/theses", authRequired, requirePermission("ReadThesis"), func(c *gin.Context) {
		result, err := notarySvc.GetAllTheses()
		if err != nil {
			log.Printf("get all theses failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query theses"})
			return
		}

		c.Data(http.StatusOK, "application/json", result)
	})

	// GetJuryStatus progress readout — "3 of 4 graded, 2 of 4 signed" —
	// without the caller needing to fetch and diff the full thesis
	// record. Same read permission as GET /theses/:thesisId since it's
	// no more sensitive.
	r.GET("/api/v1/theses/:thesisId/jury-status", authRequired, requirePermission("ReadThesis"), func(c *gin.Context) {
		thesisID := c.Param("thesisId")
		if thesisID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
			return
		}

		result, err := notarySvc.GetJuryStatus(thesisID)
		if err != nil {
			log.Printf("get jury status failed: %v", err)
			c.JSON(http.StatusNotFound, gin.H{"error": "thesis not found"})
			return
		}

		c.Data(http.StatusOK, "application/json", result)
	})

	// Superadmin defines a thesis record up front — student identity,
	// administrative info (including the assigned jury) and document
	// metadata are all known at this point, but the grade is not: that
	// field stays empty on the ledger until every jury member has
	// graded the defense (see /grades below).
	r.POST("/api/v1/theses",
		authRequired,
		requirePermission("CreateThesis"),
		func(c *gin.Context) {
			var req internal.CreateThesisRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
				return
			}

			initialData := struct {
				Student        internal.StudentInfo        `json:"student"`
				Administrative internal.AdministrativeInfo `json:"administrative"`
				Metadata       internal.ThesisMetadata     `json:"metadata"`
			}{
				Student:        req.Student,
				Administrative: req.Administrative,
				Metadata:       req.Metadata,
			}
			initialDataJSON, err := json.Marshal(initialData)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode thesis data"})
				return
			}

			claims := c.MustGet("claims").(*internal.SessionClaims)
			if err := notarySvc.CreateThesis(req.ThesisID, req.StudentID, string(initialDataJSON), claims.Username); err != nil {
				log.Printf("create thesis failed: %v", err)
				c.JSON(http.StatusConflict, gin.H{"error": "failed to create thesis on ledger"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"status": "created", "thesisId": req.ThesisID})
		})

	// One jury member, one grade, one request. jurorID is taken from the
	// authenticated session rather than the request body, so nobody can
	// submit a grade on another juror's behalf — assumes the LDAP
	// username matches the identifiers listed in
	// Administrative.JuryMembers (that's what the chaincode checks
	// against). The thesis only flips DRAFT -> DEFENDED, and
	// ThesisGrade only gets computed, once every assigned juror has
	// called this.
	r.POST("/api/v1/theses/:thesisId/grades",
		authRequired,
		requirePermission("SubmitJuryGrade"),
		func(c *gin.Context) {
			thesisID := c.Param("thesisId")
			if thesisID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
				return
			}

			var body struct {
				Grade   string `json:"grade"`
				Comment string `json:"comment"`
			}
			if err := c.ShouldBindJSON(&body); err != nil || body.Grade == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "grade is required"})
				return
			}

			claims := c.MustGet("claims").(*internal.SessionClaims)
			jurorID := claims.Username

			if err := notarySvc.SubmitJuryGrade(thesisID, jurorID, body.Grade, body.Comment); err != nil {
				log.Printf("submit jury grade failed: %v", err)
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}

			status, err := notarySvc.GetJuryStatus(thesisID)
			if err != nil {
				log.Printf("get jury status failed: %v", err)
				c.JSON(http.StatusCreated, gin.H{"status": "graded"})
				return
			}
			c.Data(http.StatusCreated, "application/json", status)
		})

	// Transaction history for a thesis: one entry per committed ledger
	// transaction that touched the record (txId, block timestamp,
	// isDelete, and the record's value as of that transaction). This is
	// what powers the "transaction details" view on the frontend — unlike
	// GET /theses/:thesisId, which only ever returns the current state.
	// Same read permission as the rest of the thesis-read endpoints.
	r.GET("/api/v1/theses/:thesisId/history", authRequired, requirePermission("ReadThesis"), func(c *gin.Context) {
		thesisID := c.Param("thesisId")
		if thesisID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
			return
		}

		history, err := notarySvc.GetThesisHistory(thesisID)
		if err != nil {
			log.Printf("get thesis history failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve transaction history"})
			return
		}

		c.Data(http.StatusOK, "application/json", history)
	})

	// Co-signing the PV. Only reachable once the thesis has been fully
	// graded (chaincode enforces Status == DEFENDED — this handler
	// doesn't need to duplicate that check, it just surfaces whatever
	// error SignPv returns).
	//
	// The FIRST juror to sign must attach the PV file itself (multipart
	// field "Pv"): the server hashes the plaintext, encrypts and stores
	// it once in MinIO, and that hash becomes the thesis's permanent
	// HashPv. Every juror after that can call this endpoint with no file
	// at all — the server reads the already-recorded hash off the
	// ledger and has the HSM sign it fresh for them. If a later caller
	// does attach a file, it's checked against the recorded hash and
	// rejected on mismatch, rather than silently accepted, so nobody can
	// swap in a different document mid-signature-collection.
	r.POST("/api/v1/theses/:thesisId/pv-signature",
		authRequired,
		requirePermission("SignPv"),
		func(c *gin.Context) {
			thesisID := c.Param("thesisId")
			if thesisID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
				return
			}

			claims := c.MustGet("claims").(*internal.SessionClaims)
			jurorID := claims.Username

			rawThesis, err := notarySvc.GetThesis(thesisID)
			if err != nil {
				log.Printf("pv-signature: get thesis failed: %v", err)
				c.JSON(http.StatusNotFound, gin.H{"error": "thesis not found"})
				return
			}
			var view thesisLedgerView
			if err := json.Unmarshal(rawThesis, &view); err != nil {
				log.Printf("pv-signature: failed to parse thesis state: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read thesis state"})
				return
			}

			ctx := context.Background()
			var hashHex string

			if fh, ferr := c.FormFile("Pv"); ferr == nil {
				data, rerr := readUploadedFile(fh, "pv")
				if rerr != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": rerr.Error()})
					return
				}

				h := sha256.Sum256(data)
				uploadedHashHex := hex.EncodeToString(h[:])

				if view.HashPv != "" && view.HashPv != uploadedHashHex {
					c.JSON(http.StatusConflict, gin.H{"error": "uploaded pv does not match the pv already on record for this thesis"})
					return
				}

				if view.HashPv == "" {
					iv, ciphertext, eerr := hsmSvc.Encrypt(data)
					if eerr != nil {
						log.Printf("pv-signature: HSM encrypt failed: %v", eerr)
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt pv"})
						return
					}
					blob := append(iv, ciphertext...)
					objectName := fmt.Sprintf("%s-pv", thesisID)
					if uerr := minioSvc.UploadThesis(ctx, minioBucket, objectName, bytes.NewReader(blob), int64(len(blob)), thesisID); uerr != nil {
						log.Printf("pv-signature: upload failed: %v", uerr)
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store pv"})
						return
					}
				}

				hashHex = uploadedHashHex
			} else {
				if view.HashPv == "" {
					c.JSON(http.StatusBadRequest, gin.H{"error": "pv not yet uploaded — the first signer must attach the Pv file"})
					return
				}
				hashHex = view.HashPv
			}

			sigHex, serr := signHashHex(hsmSvc, hashHex)
			if serr != nil {
				log.Printf("pv-signature: %v", serr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": serr.Error()})
				return
			}

			if err := notarySvc.SignPv(thesisID, jurorID, hashHex, sigHex); err != nil {
				log.Printf("sign pv failed: %v", err)
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}

			status, serr := notarySvc.GetJuryStatus(thesisID)
			if serr != nil {
				log.Printf("get jury status failed: %v", serr)
				c.JSON(http.StatusCreated, gin.H{"status": "signed", "hashPv": hashHex})
				return
			}
			c.Data(http.StatusCreated, "application/json", status)
		})

	// Notarizing the thesis document itself: a single hash+signature
	// pair, no co-signing required. Same DEFENDED gate as PV signing,
	// enforced chaincode-side. Typically called once, by whoever holds
	// the final PDF (superadmin or a designated juror) — calling it
	// twice just re-notarizes with a new hash/signature, which the
	// chaincode currently allows.
	r.POST("/api/v1/theses/:thesisId/document",
		authRequired,
		requirePermission("NotarizeDocument"),
		func(c *gin.Context) {
			thesisID := c.Param("thesisId")
			if thesisID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
				return
			}

			docHeader, err := c.FormFile("Document")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "document file required"})
				return
			}

			ctx := context.Background()

			docStored, docSig, err := encryptSignAndStore(ctx, minioSvc, hsmSvc, minioBucket, thesisID, "document", docHeader)
			if err != nil {
				log.Printf("document processing failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			if err := notarySvc.NotarizeDocument(thesisID, docStored.Hash, docSig); err != nil {
				log.Printf("notarize document failed: %v", err)
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"status": "notarized_document",
				"document": gin.H{
					"object": docStored.ObjectName,
					"hash":   docStored.Hash,
					"iv":     docStored.IV,
				},
			})
		})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := fmt.Sprintf(":%s", port)
	log.Printf("starting api on %s", addr)
	r.Run(addr)
}
