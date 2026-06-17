package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"vhsm.document_store/minio_utils"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
)

func EncryptWithHSM(plaintext []byte, pin string, label string) ([]byte, error) {
	p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	if err := p.Initialize(); err != nil {
		return nil, err
	}
	defer p.Finalize()

	slots, _ := p.GetSlotList(true)
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	defer p.CloseSession(session)

	p.Login(session, pkcs11.CKU_USER, pin)
	defer p.Logout(session)

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	p.FindObjectsInit(session, template)
	obj, _, _ := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)

	iv := make([]byte, 16)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}
	p.EncryptInit(session, mech, obj[0])

	return p.Encrypt(session, plaintext)
}

func main() {
	minioService, err := minio_utils.NewMinioService("localhost:9000", "minioadmin", "minioadmin")
	if err != nil {
		panic(err)
	}

	r := gin.Default()

	r.POST("/api/v1/encrypt", func(c *gin.Context) {
		thesisID := c.PostForm("thesisId")
		file, header, err := c.Request.FormFile("document")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Fichier manquant"})
			return
		}
		defer file.Close()

		plaintext, _ := io.ReadAll(file)
		encryptedData, err := EncryptWithHSM(plaintext, "1234", "MaCleThesis")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = minioService.UploadThesis(c.Request.Context(), "thesis", header.Filename, bytes.NewReader(encryptedData), int64(len(encryptedData)), thesisID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		hash := sha256.Sum256(encryptedData)
		c.JSON(http.StatusOK, gin.H{
			"status": "Succès",
			"ledger": map[string]interface{}{
				"thesisId": thesisID,
				"fileHash": hex.EncodeToString(hash[:]),
				"time":     time.Now().Unix(),
			},
		})
	})
	r.Run(":8080")
}
