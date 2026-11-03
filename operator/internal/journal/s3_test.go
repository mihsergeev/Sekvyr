package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type testS3 struct {
	versions []s3types.ObjectVersion
	markers  []s3types.DeleteMarkerEntry
	raw      []byte
	put      *s3.PutObjectInput
	mode     s3types.ObjectLockMode
	retain   *time.Time
	version  string
	loseAck  bool
	putCalls int
}

func (s *testS3) ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	return &s3.ListObjectVersionsOutput{Versions: s.versions, DeleteMarkers: s.markers, IsTruncated: aws.Bool(false)}, nil
}
func (s *testS3) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(s.raw)), VersionId: aws.String(s.version), ObjectLockMode: s.mode, ObjectLockRetainUntilDate: s.retain}, nil
}
func (s *testS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.putCalls++
	s.put = in
	s.raw, _ = io.ReadAll(in.Body)
	s.versions = []s3types.ObjectVersion{{Key: in.Key, VersionId: aws.String(s.version)}}
	if s.loseAck {
		return nil, errors.New("public-test-response-loss")
	}
	return &s3.PutObjectOutput{VersionId: aws.String(s.version)}, nil
}
func (s *testS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled}, nil
}
func (s *testS3) GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &s3types.ObjectLockConfiguration{ObjectLockEnabled: s3types.ObjectLockEnabledEnabled}}, nil
}
func TestS3AdapterForcesConditionalComplianceAndVersionReceipt(t *testing.T) {
	f := setupJournal(t)
	until := time.Now().Add(time.Hour)
	sdk := &testS3{version: "public-version", mode: s3types.ObjectLockModeCompliance, retain: &until}
	storage := &S3Storage{client: sdk, config: S3Config{Bucket: "trial", Prefix: "journal/", RetainSeconds: 3600}}
	raw, _ := EncodeRecord(f.genesis)
	receipt, err := storage.PutIfAbsent(context.Background(), f.state.Scope.LogID, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if aws.ToString(sdk.put.IfNoneMatch) != "*" || sdk.put.ObjectLockMode != s3types.ObjectLockModeCompliance || aws.ToString(sdk.put.ChecksumSHA256) != base64.StdEncoding.EncodeToString(sum[:]) || receipt.VersionID != "public-version" {
		t.Fatal("SDK request was not append-only")
	}
}
func TestS3AdapterResolvesExactPersistedSlotAfterResponseLoss(t *testing.T) {
	f := setupJournal(t)
	until := time.Now().Add(time.Hour)
	sdk := &testS3{version: "public-version", mode: s3types.ObjectLockModeCompliance, retain: &until, loseAck: true}
	storage := &S3Storage{client: sdk, config: S3Config{Bucket: "trial", Prefix: "journal/", RetainSeconds: 3600}}
	raw, _ := EncodeRecord(f.genesis)
	receipt, err := storage.PutIfAbsent(context.Background(), f.state.Scope.LogID, 0, raw)
	if err != nil || receipt.VersionID != "public-version" || sdk.putCalls != 1 {
		t.Fatal("response-loss resolution rebased/retried", err)
	}
}
func TestS3AdapterRejectsVersionAmbiguityMarkersAndExpiredRetention(t *testing.T) {
	for _, kind := range []string{"duplicate-version", "delete-marker", "gap", "expired", "wrong-version", "governance"} {
		t.Run(kind, func(t *testing.T) {
			f := setupJournal(t)
			until := time.Now().Add(time.Hour)
			raw, _ := EncodeRecord(f.genesis)
			sdk := &testS3{version: "public-version", raw: raw, mode: s3types.ObjectLockModeCompliance, retain: &until}
			storage := &S3Storage{client: sdk, config: S3Config{Bucket: "trial", Prefix: "journal/", RetainSeconds: 3600}}
			sdk.versions = []s3types.ObjectVersion{{Key: aws.String(storage.key(f.state.Scope.LogID, 0)), VersionId: aws.String("public-version")}}
			switch kind {
			case "duplicate-version":
				sdk.versions = append(sdk.versions, sdk.versions[0])
			case "delete-marker":
				sdk.markers = []s3types.DeleteMarkerEntry{{Key: sdk.versions[0].Key}}
			case "gap":
				sdk.versions[0].Key = aws.String(storage.key(f.state.Scope.LogID, 1))
			case "expired":
				past := time.Now().Add(-time.Hour)
				sdk.retain = &past
			case "wrong-version":
				sdk.version = "different-version"
			case "governance":
				sdk.mode = s3types.ObjectLockModeGovernance
			}
			if _, err := storage.ReadAll(context.Background(), f.state.Scope.LogID); err == nil {
				t.Fatal("unsafe S3 history accepted")
			}
		})
	}
}
