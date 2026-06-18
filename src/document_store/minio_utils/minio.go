package minio_utils

import (
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

func CreateBuckets(client *minio.Client, buckets []string) error {
	for _, bucket := range buckets {
		err := client.MakeBucket(
			ctx,
			bucket,
			minio.MakeBucketOptions{Region: "us-east-1"},
		)
		if err != nil {
			return err
		}
	}
	return nil
}
