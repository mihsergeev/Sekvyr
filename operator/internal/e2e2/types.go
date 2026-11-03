package e2e2

type Scope struct {
	RealmID       string `json:"realm_id"`
	ProjectID     string `json:"project_id"`
	EnvironmentID string `json:"environment_id"`
	ViewID        string `json:"view_id"`
	LogID         string `json:"log_id"`
}
type Parent struct {
	Scope
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelope_hash"`
}
type Header struct {
	Protocol string `json:"protocol"`
	Suite    string `json:"suite"`
	Intent   string `json:"intent"`
	Scope
	Sequence             string   `json:"sequence"`
	PreviousHash         string   `json:"previous_hash"`
	ReadKeyEpoch         string   `json:"read_key_epoch"`
	PublisherPolicyEpoch string   `json:"publisher_policy_epoch"`
	PublisherKeyID       string   `json:"publisher_key_id"`
	SnapshotSalt         string   `json:"snapshot_salt"`
	EntryCount           int      `json:"entry_count"`
	Action               string   `json:"action"`
	RestoredFrom         *string  `json:"restored_from"`
	Parents              []Parent `json:"parents"`
}
type EnvelopeBody struct {
	Header     Header `json:"header"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}
type Envelope struct {
	Body      EnvelopeBody `json:"body"`
	Signature string       `json:"signature"`
}
type Entry struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Plaintext struct {
	Format  string  `json:"format"`
	Context Scope   `json:"context"`
	Entries []Entry `json:"entries"`
}
type WrapContext struct {
	Protocol string `json:"protocol"`
	Scope
	ReadKeyEpoch         string `json:"read_key_epoch"`
	PublisherPolicyEpoch string `json:"publisher_policy_epoch"`
	PublisherKeyID       string `json:"publisher_key_id"`
	RecipientFingerprint string `json:"recipient_fingerprint"`
}
type ReaderWrapBody struct {
	Context         WrapContext `json:"context"`
	EphemeralPublic string      `json:"ephemeral_public"`
	Salt            string      `json:"salt"`
	Nonce           string      `json:"nonce"`
	Ciphertext      string      `json:"ciphertext"`
}
type ReaderWrap struct {
	Body      ReaderWrapBody `json:"body"`
	Signature string         `json:"signature"`
}
type ReaderPayload struct {
	Format  string      `json:"format"`
	Context WrapContext `json:"context"`
	ReadKey string      `json:"read_key"`
}
type HeadBody struct {
	Format string `json:"format"`
	Scope
	WitnessEpoch         string `json:"witness_epoch"`
	Sequence             string `json:"sequence"`
	EnvelopeHash         string `json:"envelope_hash"`
	ReadKeyEpoch         string `json:"read_key_epoch"`
	PublisherPolicyEpoch string `json:"publisher_policy_epoch"`
	RequestNonce         string `json:"request_nonce"`
	WitnessKeyID         string `json:"witness_key_id"`
	FloorSequence        string `json:"floor_sequence"`
	FloorHash            string `json:"floor_hash"`
}
type HeadProof struct {
	Body      HeadBody `json:"body"`
	Signature string   `json:"signature"`
}
