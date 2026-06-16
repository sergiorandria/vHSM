package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
	"github.com/minio/minio-go/v7"
	"vhsm.document_store/minio_utils"
)

// Native encryption using PKCS#11
//
// This function performs symmetric encryption inside an HSM or PKCS#11-compatible
// token (for example SoftHSM). It expects a key to be present on the token and
// identified by its label. The steps performed are:
// 1) Initialize the PKCS#11 library and open a session on the first available slot.
// 2) Log in to the token using the provided PIN.
// 3) Locate the key object by its CKA_LABEL attribute.
// 4) Initialize the AES-CBC-PAD encryption mechanism with an IV.
// 5) Execute the encryption operation and return the ciphertext.
//
// Security notes and caveats:
//   - In production, the IV must be randomly generated for every encryption and
//     stored or transmitted alongside the ciphertext. Re-using a fixed IV is insecure.
//   - AES-CBC is not authenticated; combine it with an HMAC or prefer an AEAD mode
//     (e.g. AES-GCM) if available on the token.
//   - Error handling here is minimal and should be hardened for real deployments.
func EncryptWithHSM(plaintext []byte, pin string, label string) ([]byte, error) {
	p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
	if err := p.Initialize(); err != nil {
		return nil, err
	}
	defer p.Finalize()

	// Retrieve available slots that have tokens present.
	slots, _ := p.GetSlotList(true)
	// Open a read-write session on the first slot found.
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	defer p.CloseSession(session)

	// Log in as a user to be able to access private key objects.
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, err
	}
	defer p.Logout(session)

	// 1. Find the key object on the token using its label attribute.
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	p.FindObjectsInit(session, template)
	obj, _, err := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)
	if err != nil || len(obj) == 0 {
		return nil, fmt.Errorf("key not found")
	}

	// 2. Initialize the encryption mechanism. AES-CBC requires a 16-byte IV.
	// Note: In this example a zero IV is used for simplicity, but this is NOT
	// secure for real data. Always use a cryptographically-random IV per message.
	iv := make([]byte, 16) // In production, generate a random IV and store/transmit it.
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}

	if err := p.EncryptInit(session, mech, obj[0]); err != nil {
		return nil, fmt.Errorf("EncryptInit failed: %v", err)
	}

	// 3. Perform the encryption operation inside the token and return ciphertext.
	return p.Encrypt(session, plaintext)
}

func main() {
	// Create a default Gin router.
	r := gin.Default()

	// Connect to MinIO and create a context for operations.
	minioClient, _ := minio_utils.ConnectMinio()
	ctx := context.Background()

	// Ensure required buckets exist at startup. This creates the buckets if they don't exist.
	err := minio_utils.CreateBuckets(ctx, minioClient, []string{"thesis"})
	if err != nil {
		panic("Impossible de préparer le bucket MinIO : " + err.Error())
	}

	// HTTP endpoint to accept a file, encrypt it using the HSM, store the ciphertext
	// in MinIO and return a ledger-friendly JSON response containing a SHA-256 hash.
	r.POST("/api/v1/encrypt", func(c *gin.Context) {
		thesisID := c.PostForm("thesisId")
		file, header, _ := c.Request.FormFile("document")
		defer file.Close()
		plaintext, _ := io.ReadAll(file)

		// 1. Encrypt the file using the HSM-backed function.
		encryptedData, err := EncryptWithHSM(plaintext, "1234", "MaCleThesis")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// 2. Store the encrypted bytes in MinIO under the 'thesis' bucket.
		_, err = minioClient.PutObject(context.Background(), "thesis", header.Filename,
			bytes.NewReader(encryptedData), int64(len(encryptedData)),
			minio.PutObjectOptions{ContentType: "application/octet-stream"})

		if err != nil {
			// Return the MinIO error message to help diagnose issues (e.g. bucket missing, access denied).
			c.JSON(http.StatusInternalServerError, gin.H{"error": "MinIO Error: " + err.Error()})
			return
		}

		// 3. Build a response suitable for submitting to a ledger: include a SHA-256 of the ciphertext.
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
