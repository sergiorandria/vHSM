package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"electronic_signature/rest_api/gateway_sdk"
	"electronic_signature/rest_api/internal/hsm"
	"electronic_signature/rest_api/internal/notary"
	"electronic_signature/rest_api/internal/storage"
	"electronic_signature/rest_api/utils"

	"github.com/gin-gonic/gin"
)

const maxUploadSize = 50 << 20 // 50 MiB

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

	// 1) Fabric Gateway
	grpcConn, err := utils.NewGrpcConnection()
	if err != nil {
		log.Fatalf("Fabric Conn error: %v", err)
	}
	defer grpcConn.Close()

	id, err := utils.NewIdentity()
	if err != nil {
		log.Fatalf("failed to build identity: %v", err)
	}
	sign, err := utils.NewSign()
	if err != nil {
		log.Fatalf("failed to build signer: %v", err)
	}

	fabricClient, err := gateway_sdk.NewGatewayClient(grpcConn, utils.ChannelName, utils.ChaincodeName, id, sign)
	if err != nil {
		log.Fatalf("failed to create gateway client: %v", err)
	}
	defer fabricClient.Close()

	// 2) HSM
	hsmSvc, err := hsm.NewHSMService(hsmModule, hsmToken, hsmPin, hsmKeyLabel)
	if err != nil {
		log.Fatalf("failed to init HSM service: %v", err)
	}
	defer hsmSvc.Close()

	// 3) MinIO
	minioSvc, err := storage.NewMinioService(minioEndpoint, minioAccess, minioSecret)
	if err != nil {
		log.Fatalf("failed to init MinIO service: %v", err)
	}

	// Ensure bucket exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := storage.CreateBuckets(ctx, minioSvc.Client, []string{minioBucket}); err != nil {
		log.Fatalf("failed to ensure buckets: %v", err)
	}

	// 4) Notary
	notarySvc := notary.NewNotaryService(fabricClient, hsmSvc)

	// 5) HTTP server
	r := gin.Default()

	r.MaxMultipartMemory = maxUploadSize

	r.POST("/api/v1/submissions", func(c *gin.Context) {
		thesisID := c.PostForm("thesisId")
		if thesisID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "thesisId required"})
			return
		}

		fileHeader, err := c.FormFile("document")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "document file required"})
			return
		}

		f, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open uploaded file"})
			return
		}
		defer f.Close()

		// Read with cap
		lr := io.LimitReader(f, maxUploadSize+1)
		data, err := io.ReadAll(lr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read uploaded file"})
			return
		}
		if int64(len(data)) > maxUploadSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file too large"})
			return
		}

		// Encrypt with HSM (performed inside the token)
		iv, ciphertext, err := hsmSvc.Encrypt(data)
		if err != nil {
			log.Printf("HSM encrypt error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
			return
		}

		// Upload ciphertext to MinIO
		objectName := fmt.Sprintf("%s-%s", thesisID, fileHeader.Filename)
		ctx := context.Background()
		// store IV concatenated with ciphertext or as part of filename/metadata; here we prefix IV to object bytes
		blob := append(iv, ciphertext...)
		err = minioSvc.UploadThesis(ctx, minioBucket, objectName, bytes.NewReader(blob), int64(len(blob)), thesisID)
		if err != nil {
			log.Printf("upload failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload to storage"})
			return
		}

		// Compute hash of stored ciphertext for notarisation
		h := sha256.Sum256(blob)
		hashHex := hex.EncodeToString(h[:])

		// Au lieu de : sig := "TODO-HSM-SIGNATURE"
		// Utilisez :
		sigBytes, err := hsmSvc.Sign(h[:]) // Signe le hash (ou le JSON de la preuve)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "signature failed"})
			return
		}
		sig := hex.EncodeToString(sigBytes)
		if err := notarySvc.Notarize(thesisID, hashHex, sig); err != nil {
			log.Printf("notarize failed: %v", err)
		}

		c.JSON(http.StatusCreated, gin.H{"status": "stored", "object": objectName, "hash": hashHex, "iv": hex.EncodeToString(iv)})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf(":%s", port)
	log.Printf("starting api on %s", addr)
	r.Run(addr)
}
