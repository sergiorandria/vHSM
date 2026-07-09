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
// single defense-time document (either the PV or the thesis PDF).
type storedFile struct {
	ObjectName string
	Hash       string
	IV         string
}

// encryptSignAndStore reads an uploaded file (capped at maxUploadSize),
// encrypts it inside the HSM, uploads the resulting blob to MinIO, then
// hashes and signs the stored blob. label is used both to namespace the
// MinIO object name and to make error messages identify which of the two
// defense documents (pv/document) failed.
func encryptSignAndStore(
	ctx context.Context,
	minioSvc *internal.MinioService,
	hsmSvc *internal.HSMService,
	bucket string,
	thesisID string,
	label string,
	fh *multipart.FileHeader,
) (*storedFile, string, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, "", fmt.Errorf("failed to open %s file: %w", label, err)
	}
	defer f.Close()

	lr := io.LimitReader(f, maxUploadSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read %s file: %w", label, err)
	}
	if int64(len(data)) > maxUploadSize {
		return nil, "", fmt.Errorf("%s file too large", label)
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
	notarySvc := internal.NewNotaryService(fabricClient, hsmSvc)

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

	// Superadmin defines a thesis record up front — student identity,
	// administrative info and document metadata are all known at this
	// point, but the grade is not: that field stays empty on the ledger
	// until the defense happens (see /api/v1/submissions below).
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

	// Submitting a defense appends the grade to an existing thesis record
	// and notarizes the two documents produced at defense time: the PV
	// (defense minutes) and the thesis PDF itself. Both are encrypted with
	// the HSM, stored in MinIO, hashed and signed independently, since the
	// chaincode tracks their hash/signature pairs separately.
	r.POST("/api/v1/submissions",
		authRequired,
		requirePermission("SubmitDocument"),
		func(c *gin.Context) {
			thesisID := c.PostForm("ThesisId")
			grade := c.PostForm("Grade")

			if thesisID == "" || grade == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId and grade are required"})
				return
			}

			pvHeader, err := c.FormFile("Pv")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "pv file required"})
				return
			}

			docHeader, err := c.FormFile("Document")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "document file required"})
				return
			}

			// Append the grade first — fails fast if the thesis doesn't
			// exist yet (it must have been created by a superadmin).
			if err := notarySvc.SubmitGrade(thesisID, grade); err != nil {
				log.Printf("submit grade failed: %v", err)
				c.JSON(http.StatusConflict, gin.H{"error": "failed to submit grade on ledger"})
				return
			}

			ctx := context.Background()

			pvStored, pvSig, err := encryptSignAndStore(ctx, minioSvc, hsmSvc, minioBucket, thesisID, "pv", pvHeader)
			if err != nil {
				log.Printf("pv processing failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			docStored, docSig, err := encryptSignAndStore(ctx, minioSvc, hsmSvc, minioBucket, thesisID, "document", docHeader)
			if err != nil {
				log.Printf("document processing failed: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}

			if err := notarySvc.NotarizePv(thesisID, pvStored.Hash, pvSig); err != nil {
				log.Printf("notarize pv failed: %v", err)
			}
			if err := notarySvc.NotarizeDocument(thesisID, docStored.Hash, docSig); err != nil {
				log.Printf("notarize document failed: %v", err)
			}

			c.JSON(http.StatusCreated, gin.H{
				"status": "stored",
				"pv": gin.H{
					"object": pvStored.ObjectName,
					"hash":   pvStored.Hash,
					"iv":     pvStored.IV,
				},
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
