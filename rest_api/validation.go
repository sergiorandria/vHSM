/*package main

import (
	"fmt"
	"regexp"
	"electronic_signature/internal/models"
)

const (
	maxBodyBytes = 1 << 20 // 1 MiB cap on incoming JSON
	minGrade     = 0.0
	maxGrade     = 20.0 // adjust to your grading scale
)

var thesisIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidateSubmission checks structural and business-rule constraints on a
// parsed submission before it is hashed and signed. Returns a descriptive
// error on the first failed check.
func ValidateSubmission(req models.SubmissionRequest) error {
	if !thesisIDPattern.MatchString(req.ThesisID) {
		return fmt.Errorf("thesisId must be 1-64 chars, alphanumeric/dash/underscore only")
	}

	if req.Grade == "" {
		return fmt.Errorf("grade is required")
	}
	gradeVal, err := req.Grade.Float64()
	if err != nil {
		return fmt.Errorf("grade must be a valid number: %w", err)
	}
	if gradeVal < minGrade || gradeVal > maxGrade {
		return fmt.Errorf("grade must be between %.1f and %.1f, got %.2f", minGrade, maxGrade, gradeVal)
	}

	if len(req.Metadata) == 0 {
		return fmt.Errorf("metadata is required and must not be empty")
	}

	// Require specific expected fields in metadata. Adjust to match
	// whatever the frontend actually sends.
	requiredFields := []string{"thesisTitle", "defenseDate"}
	for _, field := range requiredFields {
		if _, ok := req.Metadata[field]; !ok {
			return fmt.Errorf("metadata missing required field %q", field)
		}
	}

	return nil
}
*/