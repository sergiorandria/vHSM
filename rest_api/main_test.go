package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleSubmission_Success(t *testing.T) {
	// Create a valid request
	payload := map[string]interface{}{
		"thesisId": "thesis-123",
		"grade":    95.5,
		"metadata": map[string]interface{}{
			"department": "CS",
			"semester":   "Fall 2026",
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handleSubmission(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", w.Code)
	}

	var resp SubmissionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify fields
	if resp.ThesisID != "thesis-123" {
		t.Errorf("expected thesisId 'thesis-123', got '%s'", resp.ThesisID)
	}
	if resp.DocHash == "" {
		t.Error("expected non-empty docHash")
	}
	if resp.ReceivedAt == "" {
		t.Error("expected non-empty ReceivedAt")
	}

	// Verify hash is deterministic
	resp2 := SubmissionResponse{}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(body))
	handleSubmission(w2, req2)
	json.Unmarshal(w2.Body.Bytes(), &resp2)

	if resp.DocHash != resp2.DocHash {
		t.Errorf("hash not deterministic: %s vs %s", resp.DocHash, resp2.DocHash)
	}
}

func TestHandleSubmission_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	w := httptest.NewRecorder()

	handleSubmission(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %v", w.Code)
	}
}

func TestHandleSubmission_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", nil)
	w := httptest.NewRecorder()

	handleSubmission(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %v", w.Code)
	}
}

func TestHandleSubmission_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions",
		bytes.NewReader([]byte(`{"thesisId": "test", "grade": broken}`)))
	w := httptest.NewRecorder()

	handleSubmission(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %v", w.Code)
	}
}

func TestHandleSubmission_MissingThesisID(t *testing.T) {
	payload := map[string]interface{}{
		"grade": 95.5,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handleSubmission(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %v", w.Code)
	}
}
