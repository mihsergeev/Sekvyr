package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type S3Config struct {
	Bucket              string `json:"bucket"`
	Prefix              string `json:"prefix"`
	Region              string `json:"region"`
	Endpoint            string `json:"endpoint"`
	CAFile              string `json:"ca_file"`
	ExpectedBucketOwner string `json:"expected_bucket_owner"`
	RetainSeconds       int64  `json:"retain_seconds"`
	AllowHTTPTrial      bool   `json:"allow_http_trial"`
}
type S3API interface {
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
}
type S3Storage struct {
	client S3API
	config S3Config
	Now    func() time.Time
}

func (*S3Storage) String() string   { return "trial S3 journal storage [redacted]" }
func (*S3Storage) GoString() string { return "trial S3 journal storage [redacted]" }
func NewS3Storage(ctx context.Context, cfg S3Config) (*S3Storage, error) {
	if !validName(cfg.Bucket) || cfg.Prefix == "" || len(cfg.Prefix) > 256 || strings.HasPrefix(cfg.Prefix, "/") || strings.Contains(cfg.Prefix, "..") || strings.ContainsAny(cfg.Prefix, "\\\x00\r\n") || !strings.HasSuffix(cfg.Prefix, "/") || cfg.Region == "" || len(cfg.Region) > 64 || cfg.RetainSeconds < 60 || cfg.RetainSeconds > 100*365*86400 {
		return nil, Failure("StorageConfigInvalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		raw, err := os.ReadFile(cfg.CAFile)
		if err != nil || len(raw) > 64<<10 {
			return nil, Failure("StorageCAInvalid")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, Failure("StorageCAInvalid")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	if cfg.Endpoint != "" {
		u, err := url.Parse(cfg.Endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowHTTPTrial)) {
			return nil, Failure("StorageEndpointInvalid")
		}
	}
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region), awsconfig.WithRetryMaxAttempts(1), awsconfig.WithHTTPClient(httpClient))
	if err != nil {
		return nil, Failure("StorageCredentialsUnavailable")
	}
	client := s3.NewFromConfig(loaded, func(o *s3.Options) {
		o.UsePathStyle = cfg.Endpoint != ""
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	})
	storage := &S3Storage{client: client, config: cfg}
	if err = storage.CheckConfiguration(ctx); err != nil {
		return nil, err
	}
	return storage, nil
}
func (s *S3Storage) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
func (s *S3Storage) owner() *string {
	if s.config.ExpectedBucketOwner == "" {
		return nil
	}
	return aws.String(s.config.ExpectedBucketOwner)
}
func (s *S3Storage) CheckConfiguration(ctx context.Context) error {
	versioning, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(s.config.Bucket), ExpectedBucketOwner: s.owner()})
	if err != nil || versioning.Status != s3types.BucketVersioningStatusEnabled {
		return Failure("StorageVersioningRequired")
	}
	lock, err := s.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(s.config.Bucket), ExpectedBucketOwner: s.owner()})
	if err != nil || lock.ObjectLockConfiguration == nil || lock.ObjectLockConfiguration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
		return Failure("StorageObjectLockRequired")
	}
	return nil
}
func (s *S3Storage) prefix(log string) string { return s.config.Prefix + log + "/" }
func (s *S3Storage) key(log string, sequence uint64) string {
	return s.prefix(log) + fmt.Sprintf("%020d.json", sequence)
}
func storageFailure(err error) error {
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NotFound", "NoSuchVersion":
			return Failure("SlotMissing")
		case "PreconditionFailed", "ConditionalRequestConflict":
			return Failure("CASConflict")
		case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch":
			return Failure("StorageDenied")
		}
	}
	return Failure("StorageUnavailable")
}

type versionRef struct {
	sequence     uint64
	key, version string
}

func (s *S3Storage) inventory(ctx context.Context, log string) ([]versionRef, error) {
	if !validUUID(log) {
		return nil, Failure("LogUnknown")
	}
	prefix := s.prefix(log)
	var refs []versionRef
	seen := map[string]bool{}
	var keyMarker, versionMarker *string
	for page := 0; page < MaxRecords+1; page++ {
		out, err := s.client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(s.config.Bucket), Prefix: aws.String(prefix), KeyMarker: keyMarker, VersionIdMarker: versionMarker, MaxKeys: aws.Int32(1000), ExpectedBucketOwner: s.owner()})
		if err != nil {
			return nil, storageFailure(err)
		}
		if len(out.DeleteMarkers) != 0 {
			return nil, Failure("StorageVersionConflict")
		}
		for _, v := range out.Versions {
			key := aws.ToString(v.Key)
			name := strings.TrimPrefix(key, prefix)
			if len(name) != 25 || !strings.HasSuffix(name, ".json") {
				return nil, Failure("StorageUnexpectedObject")
			}
			seq, err := strconv.ParseUint(name[:20], 10, 64)
			if err != nil || key != s.key(log, seq) || seq >= MaxRecords || aws.ToString(v.VersionId) == "" || seen[key] {
				return nil, Failure("StorageVersionConflict")
			}
			seen[key] = true
			refs = append(refs, versionRef{seq, key, aws.ToString(v.VersionId)})
			if len(refs) > MaxRecords {
				return nil, Failure("JournalCapacity")
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			sort.Slice(refs, func(i, j int) bool { return refs[i].sequence < refs[j].sequence })
			for n, ref := range refs {
				if ref.sequence != uint64(n) {
					return nil, Failure("JournalGap")
				}
			}
			return refs, nil
		}
		if out.NextKeyMarker == nil || out.NextVersionIdMarker == nil || (aws.ToString(out.NextKeyMarker) == aws.ToString(keyMarker) && aws.ToString(out.NextVersionIdMarker) == aws.ToString(versionMarker)) {
			return nil, Failure("StoragePaginationInvalid")
		}
		keyMarker = out.NextKeyMarker
		versionMarker = out.NextVersionIdMarker
	}
	return nil, Failure("JournalCapacity")
}
func (s *S3Storage) readVersion(ctx context.Context, ref versionRef) (StoredSlot, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(ref.key), VersionId: aws.String(ref.version), ExpectedBucketOwner: s.owner()})
	if err != nil {
		return StoredSlot{}, storageFailure(err)
	}
	if out.Body == nil {
		return StoredSlot{}, Failure("StorageResponseInvalid")
	}
	defer out.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(out.Body, MaxRecordBytes+1))
	if err != nil || len(raw) < 1 || len(raw) > MaxRecordBytes {
		return StoredSlot{}, Failure("StorageResponseInvalid")
	}
	if aws.ToBool(out.DeleteMarker) || aws.ToString(out.VersionId) != ref.version || out.ObjectLockMode != s3types.ObjectLockModeCompliance || out.ObjectLockRetainUntilDate == nil || !out.ObjectLockRetainUntilDate.After(s.now()) {
		return StoredSlot{}, Failure("RetentionInvalid")
	}
	return StoredSlot{Raw: raw, Receipt: RetentionReceipt{VersionID: ref.version, Mode: "COMPLIANCE", RetainUntil: out.ObjectLockRetainUntilDate.UTC().Format(time.RFC3339Nano)}}, nil
}
func (s *S3Storage) ReadAll(ctx context.Context, log string) ([]StoredSlot, error) {
	// An online full inventory is bracketed by another full inventory. Only an
	// unchanged immutable prefix is returned, never a restored mutable head.
	for attempt := 0; attempt < 3; attempt++ {
		refs, err := s.inventory(ctx, log)
		if err != nil {
			return nil, err
		}
		slots := make([]StoredSlot, 0, len(refs))
		total := 0
		for _, ref := range refs {
			slot, err := s.readVersion(ctx, ref)
			if err != nil {
				return nil, err
			}
			if len(slot.Raw) > MaxReplayBytes-total {
				return nil, Failure("JournalCapacity")
			}
			total += len(slot.Raw)
			slots = append(slots, slot)
		}
		after, err := s.inventory(ctx, log)
		if err != nil {
			return nil, err
		}
		if same(refs, after) {
			return slots, nil
		}
	}
	return nil, Failure("JournalBusy")
}
func (s *S3Storage) PutIfAbsent(ctx context.Context, log string, sequence uint64, raw []byte) (RetentionReceipt, error) {
	if !validUUID(log) || sequence >= MaxRecords || len(raw) < 1 || len(raw) > MaxRecordBytes {
		return RetentionReceipt{}, Failure("RecordInvalid")
	}
	record, err := DecodeRecord(raw)
	if err != nil || record.LogID != log || record.JournalSequence != fmtCounter(sequence) {
		return RetentionReceipt{}, Failure("RecordInvalid")
	}
	sum := sha256.Sum256(raw)
	until := s.now().UTC().Add(time.Duration(s.config.RetainSeconds) * time.Second)
	out, err := s.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(s.key(log, sequence)), Body: bytes.NewReader(raw), ContentLength: aws.Int64(int64(len(raw))), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*"), ObjectLockMode: s3types.ObjectLockModeCompliance, ObjectLockRetainUntilDate: &until, ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])), ExpectedBucketOwner: s.owner()})
	if err != nil {
		safe := storageFailure(err)
		if Reason(safe) == "CASConflict" || Reason(safe) == "StorageUnavailable" {
			slots, readErr := s.ReadAll(ctx, log)
			if readErr != nil {
				return RetentionReceipt{}, readErr
			}
			if sequence < uint64(len(slots)) && bytes.Equal(slots[sequence].Raw, raw) {
				return slots[sequence].Receipt, nil
			}
		}
		return RetentionReceipt{}, safe
	}
	version := aws.ToString(out.VersionId)
	if version == "" {
		return RetentionReceipt{}, Failure("StorageResponseInvalid")
	}
	slot, err := s.readVersion(ctx, versionRef{sequence, s.key(log, sequence), version})
	if err != nil {
		return RetentionReceipt{}, err
	}
	if !bytes.Equal(slot.Raw, raw) {
		return RetentionReceipt{}, Failure("StorageVersionConflict")
	}
	return slot.Receipt, nil
}
