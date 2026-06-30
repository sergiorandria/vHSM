package internal

type Metadata struct {
	ThesisTitle string `json:"thesisTitle" form:"thesisTitle"`
	DefenseDate string `json:"defenseDate" form:"defenseDate"`
}

type SubmissionRequest struct {
	ThesisID string  `json:"thesisId" form:"thesisId"`
	Grade    float64 `json:"grade" form:"grade"`
	Metadata string  `json:"metadata" form:"metadata"`
}
