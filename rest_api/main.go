package main

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/HOKK-FINANCE-FZCO/crypto11"
	"github.com/sergiorandria/go-rest-api/canon"
)

// SubmissionRequest is the expected shape of the incoming payload. Grade is
// decoded as json.Number (not float64) so malformed/out-of-range values can
// be rejected explicitly in ValidateSubmission rather than silently coerced.
type SubmissionRequest struct {
	ThesisID string                 `json:"thesisId"`
	Grade    json.Number            `json:"grade"`
	Metadata map[string]interface{} `json:"metadata"`
}

type SubmissionResponse struct {
	ThesisID      string `json:"thesisId"`
	DocHash       string `json:"docHash"`
	Signature     string `json:"signature"`
	CanonicalJSON string `json:"canonicalJson"`
	ReceivedAt    string `json:"receivedAt"`
}

// hsmCtx is opened once at startup and reused across requests, rather than
// opening a new PKCS#11 session per submission.
var hsmCtx *crypto11.Context

func initHSM() error {
	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		return fmt.Errorf("HSM_PIN environment variable not set")
	}

	config := &crypto11.Config{
		Path:       "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "FabricToken",
		Pin:        pin,
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return fmt.Errorf("failed to configure HSM: %w", err)
	}
	hsmCtx = ctx
	return nil
}

// signHash signs an already-computed SHA256 digest (given as hex) using the
// long-lived HSM session. The caller is responsible for ensuring hashHex is
// the exact hash that should be reported alongside the signature, so the
// signed value and the displayed hash are provably the same bytes.
func signHash(hashHex string) (string, error) {
	hashed, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("invalid hash hex: %w", err)
	}

	signer, err := hsmCtx.FindKeyPair(nil, []byte("MyKey"))
	if err != nil {
		return "", fmt.Errorf("failed to find key pair: %w", err)
	}

	signature, err := signer.Sign(nil, hashed, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	return hex.EncodeToString(signature), nil
}

// Adding CORS middleware
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set(
			"Access-Control-Allow-Origin",
			"http://localhost:5173",
		)

		w.Header().Set(
			"Access-Control-Allow-Methods",
			"POST, OPTIONS",
		)

		w.Header().Set(
			"Access-Control-Allow-Headers",
			"Content-Type",
		)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleSubmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(raw) == 0 {
		http.Error(w, "empty request body", http.StatusBadRequest)
		return
	}

	// Decode using json.Number for Grade so numeric validation is explicit
	// (see ValidateSubmission) rather than relying on lossy/implicit
	// float64 coercion.
	var req SubmissionRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := ValidateSubmission(req); err != nil {
		http.Error(w, "validation failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Hashing operates on the raw bytes (canonicalized), not the decoded
	// struct, so the hash reflects exactly what was received before any
	// reserialization could subtly change it.
	hashHex, canonicalBytes, err := canon.HashJSON(raw)
	if err != nil {
		http.Error(w, "failed to hash payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	signature, err := signHash(hashHex)
	if err != nil {
		http.Error(w, "failed to sign payload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := SubmissionResponse{
		ThesisID:      req.ThesisID,
		DocHash:       hashHex,
		Signature:     signature,
		CanonicalJSON: string(canonicalBytes),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

func main() {
	if err := initHSM(); err != nil {
		log.Fatalf("HSM initialization failed: %v", err)
	}
	defer hsmCtx.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/submissions", handleSubmission)

	addr := ":8080"
	log.Printf("jury-backend listening on %s", addr)
	if err := http.ListenAndServe(addr, cors(mux)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
