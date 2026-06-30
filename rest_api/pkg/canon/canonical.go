package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Canonicalize takes arbitrary JSON bytes and returns a canonical form:
// object keys sorted alphabetically at every nesting level, no insignificant
// whitespace. This ensures two semantically identical payloads always
// produce the same byte sequence (and therefore the same hash), regardless
// of how the frontend originally serialized them.
func Canonicalize(raw []byte) ([]byte, error) {
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Go's json.Marshal sorts map[string]interface{} keys alphabetically
	// since Go 1.12. Unmarshaling into interface{} and re-marshaling is
	// sufficient to get canonical key ordering at every level, since nested
	// objects also decode into map[string]interface{}.
	canonical, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal canonical form: %w", err)
	}

	return canonical, nil
}

// HashJSON canonicalizes the given raw JSON and returns its SHA256 hash
// as a lowercase hex string, along with the canonical bytes used to
// produce it (useful for logging/audit purposes).
func HashJSON(raw []byte) (hashHex string, canonicalBytes []byte, err error) {
	canonical, err := Canonicalize(raw)
	if err != nil {
		return "", nil, err
	}

	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), canonical, nil
}
