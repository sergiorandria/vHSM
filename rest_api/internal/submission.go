package internal

import "time"

// --- On-chain-mirrored structs -------------------------------------------------
// These mirror the chaincode's StudentInfo / AdministrativeInfo / ThesisMetadata
// so the REST API can build the same JSON payload the chaincode expects for
// CreateThesis's initialDataJSON argument.

type StudentInfo struct {
	FullName       string `json:"fullName"`
	NationalID     string `json:"nationalId,omitempty"`
	Email          string `json:"email"`
	EnrollmentYear int    `json:"enrollmentYear"`
	Program        string `json:"program"`
	Department     string `json:"department"`
}

type AdministrativeInfo struct {
	Institution      string    `json:"institution"`
	Faculty          string    `json:"faculty"`
	AcademicYear     string    `json:"academicYear"`
	SupervisorName   string    `json:"supervisorName"`
	SupervisorID     string    `json:"supervisorId,omitempty"`
	JuryMembers      []string  `json:"juryMembers,omitempty"`
	DefenseDate      time.Time `json:"defenseDate"`
	RegistrationDate time.Time `json:"registrationDate"`
}

type ThesisMetadata struct {
	Title        string    `json:"title"`
	Abstract     string    `json:"abstract,omitempty"`
	Keywords     []string  `json:"keywords,omitempty"`
	Language     string    `json:"language"`
	PageCount    int       `json:"pageCount,omitempty"`
	FileRef      string    `json:"fileRef,omitempty"`
	FileChecksum string    `json:"fileChecksum,omitempty"`
	SubmittedAt  time.Time `json:"submittedAt,omitempty"`
}

// --- API request bodies --------------------------------------------------------

// CreateThesisRequest is submitted by a superadmin to define a thesis record
// up front. No grade is included: that field is only known once the defense
// has taken place, and is appended later via DefenseSubmissionRequest.
type CreateThesisRequest struct {
	ThesisID       string             `json:"thesisId" binding:"required"`
	StudentID      string             `json:"studentId" binding:"required"`
	Student        StudentInfo        `json:"student"`
	Administrative AdministrativeInfo `json:"administrative"`
	Metadata       ThesisMetadata     `json:"metadata"`
}

// DefenseSubmissionRequest carries the defense-time form fields. It is sent
// as multipart/form-data alongside two files: "Pv" (the defense minutes) and
// "Document" (the thesis PDF itself).
type DefenseSubmissionRequest struct {
	ThesisID string `json:"thesisId" form:"ThesisId" binding:"required"`
	Grade    string `json:"grade" form:"Grade" binding:"required"`
}
