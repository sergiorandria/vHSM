package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"vHSM/minio_utils" // Votre package utilitaire
	"vHSM/models"

	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
)

func main() {
	// 1. Initialization
	minioClient, err := minio_utils.ConnectMinio()
	if err != nil {
		log.Fatalf("Échec de connexion MinIO: %v", err)
	}

	r := gin.Default()

	// 2. Define routes
	r.POST("/api/v1/submissions", handleSubmission(minioClient))

	// 3. Start server
	r.Run(":8080")
}

// handleSubmission encapsulates the business logic
func handleSubmission(minioClient *minio.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		// A. Bind request data (using separate models)
		var req models.SubmissionRequest
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Donnée"})
			return
		}

		// B. File handling
		file, header, err := c.Request.FormFile("document")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Fichier manquant"})
			return
		}
		defer file.Close()

		// C. JSON metadata processing
		var meta models.Metadata
		if err := json.Unmarshal([]byte(req.Metadata), &meta); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "JSON Metadata invalide"})
			return
		}

		// D. MinIO storage
		_, err = minioClient.PutObject(context.Background(), "thesis_store", header.Filename, file, header.Size, minio.PutObjectOptions{
			ContentType: header.Header.Get("Content-Type"),
			UserMetadata: map[string]string{
				"ThesisID": req.ThesisID,
			},
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Échec stockage"})
			return
		}

		// E. Final response
		c.JSON(http.StatusOK, gin.H{"message": "Soumission traitée avec succès"})
	}
}
