package minio_utils

import (
	"context"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func ConnectMinio() (*minio.Client, error) {

	return minio.New(
		"localhost:9000",
		&minio.Options{
			Creds: credentials.NewStaticV4(
				"minioadmin",
				"minioadmin",
				"",
			),
			Secure: false,
		},
	)
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
