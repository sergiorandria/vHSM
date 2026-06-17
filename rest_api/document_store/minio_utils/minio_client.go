package minio_utils

import (
	"context"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type MinioService struct {
	Client *minio.Client
}

func NewMinioService(endpoint, accessKey, secretKey string) (*MinioService, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	if err != nil {
		return nil, err
	}
	return &MinioService{Client: client}, nil
}

func (s *MinioService) UploadThesis(ctx context.Context, bucket, name string, file io.Reader, size int64, thesisID string) error {
	_, err := s.Client.PutObject(ctx, bucket, name, file, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		UserMetadata: map[string]string{
			"ThesisID": thesisID,
		},
	})
	return err
}
