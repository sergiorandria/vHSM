package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/sergiorandria/go-rest-api/canon"
)

// SubmissionRequest is the expected shape of the incoming payload, though
// note that hashing operates on the raw JSON bytes (not this struct) so
// that the hash reflects exactly what the frontend sent, before any
// reserialization on our side could subtly change it.
type SubmissionRequest struct {
	ThesisID string                 `json:"thesisId"`
	Grade    json.Number            `json:"grade"`
	Metadata map[string]interface{} `json:"metadata"`
}

type SubmissionResponse struct {
	ThesisID      string `json:"thesisId"`
	DocHash       string `json:"docHash"`
	CanonicalJSON string `json:"canonicalJson"`
	ReceivedAt    string `json:"receivedAt"`
}

func handleSubmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(raw) == 0 {
		http.Error(w, "empty request body", http.StatusBadRequest)
		return
	}

	// Parse just enough to extract thesisId for the response / logging.
	// Hashing itself happens on the raw bytes via canon.HashJSON, not on
	// this struct, to avoid any lossy reserialization before hashing.
	var parsedForID struct {
		ThesisID string `json:"thesisId"`
	}
	if err := json.Unmarshal(raw, &parsedForID); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if parsedForID.ThesisID == "" {
		http.Error(w, "thesisId is required", http.StatusBadRequest)
		return
	}

	hashHex, canonicalBytes, err := canon.HashJSON(raw)
	if err != nil {
		http.Error(w, "failed to hash payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp := SubmissionResponse{
		ThesisID:      parsedForID.ThesisID,
		DocHash:       hashHex,
		CanonicalJSON: string(canonicalBytes),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	// At this point, hashHex is what gets handed to the SoftHSM signing
	// step (next stage in the pipeline) and eventually to the Fabric
	// chaincode submission. This handler's job ends at "JSON in, hash out."
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/submissions", handleSubmission)

	addr := ":8080"
	log.Printf("jury-backend listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
