package internal

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

// CreateBuckets ensures that each bucket in the provided list exists on the MinIO
// server. If a bucket does not exist, it will be created with the specified
// region. The function returns an error if any MinIO operation fails.
func CreateBuckets(ctx context.Context, client *minio.Client, buckets []string) error {
	for _, bucket := range buckets {
		// Check whether the bucket already exists.
		exists, err := client.BucketExists(ctx, bucket)
		if err != nil {
			return err
		}
		// If the bucket does not exist, create it.
		if !exists {
			err = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
