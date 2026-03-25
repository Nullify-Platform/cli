package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ContextEnvelope wraps the uploaded payload with metadata.
type ContextEnvelope struct {
	Metadata ContextMetadata `json:"metadata"`
	Payload  json.RawMessage `json:"payload"`
}

// ContextMetadata contains metadata about the context upload.
type ContextMetadata struct {
	ContextType string `json:"contextType"`
	Repository  string `json:"repository"`
	Branch      string `json:"branch,omitempty"`
	Environment string `json:"environment,omitempty"`
	Name        string `json:"name"`
	PRNumber    int    `json:"prNumber,omitempty"`
	FromPR      int    `json:"fromPR,omitempty"`
	CommitSHA   string `json:"commitSha,omitempty"`
	UploadedAt  string `json:"uploadedAt"`
	CLIVersion  string `json:"cliVersion"`
}

// S3Uploader uploads context data to S3 using temporary credentials.
type S3Uploader struct {
	client    *s3.Client
	bucket    string
	keyPrefix string
	kmsKeyARN string
}

// NewS3Uploader creates a new S3 uploader with the given temporary credentials.
func NewS3Uploader(accessKeyID, secretAccessKey, sessionToken, region, bucket, keyPrefix, kmsKeyARN string) *S3Uploader {
	creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
	client := s3.New(s3.Options{
		Region:      region,
		Credentials: creds,
	})
	return &S3Uploader{
		client:    client,
		bucket:    bucket,
		keyPrefix: keyPrefix,
		kmsKeyARN: kmsKeyARN,
	}
}

// Upload reads the file, wraps it in an envelope, and uploads to S3 as latest.json
// and history/{timestamp}.json.
func (u *S3Uploader) Upload(ctx context.Context, filePath string, metadata ContextMetadata) error {
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Validate that the payload is valid JSON
	if !json.Valid(payload) {
		return fmt.Errorf("file %s is not valid JSON", filePath)
	}

	metadata.UploadedAt = time.Now().UTC().Format(time.RFC3339)

	envelope := ContextEnvelope{
		Metadata: metadata,
		Payload:  json.RawMessage(payload),
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Upload latest.json (current state — overwritten each time)
	latestKey := u.keyPrefix + "latest.json"
	if err := u.putObject(ctx, latestKey, envelopeJSON); err != nil {
		return fmt.Errorf("failed to upload %s: %w", latestKey, err)
	}

	// Upload history/{timestamp}.json (immutable historical copy)
	historyKey := u.keyPrefix + "history/" + time.Now().UTC().Format("2006-01-02T15-04-05Z") + ".json"
	if err := u.putObject(ctx, historyKey, envelopeJSON); err != nil {
		return fmt.Errorf("failed to upload %s: %w", historyKey, err)
	}

	return nil
}

func (u *S3Uploader) putObject(ctx context.Context, key string, data []byte) error {
	input := &s3.PutObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	}

	if u.kmsKeyARN != "" {
		input.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		input.SSEKMSKeyId = aws.String(u.kmsKeyARN)
	}

	_, err := u.client.PutObject(ctx, input)
	return err
}
