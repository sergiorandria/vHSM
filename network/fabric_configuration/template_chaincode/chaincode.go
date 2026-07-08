package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ThesisContract regroupe les fonctions du smart contract (CRUD basique).
type ThesisContract struct {
	contractapi.Contract
}

// ThesisStatus represents the lifecycle state of a thesis record on the ledger
type ThesisStatus string

const (
	StatusDraft     ThesisStatus = "DRAFT"     // Created by superadmin, awaiting defense
	StatusDefended  ThesisStatus = "DEFENDED"  // Grade submitted, pending notarization
	StatusNotarized ThesisStatus = "NOTARIZED" // Hash + signature committed
	StatusArchived  ThesisStatus = "ARCHIVED"
)

// ThesisPayload is the on-chain representation of a thesis record.
// Superadmin creates it with StudentInfo + AdministrativeInfo populated,
// leaving AcademicPerformance empty until the defense occurs.
type ThesisPayload struct {
	ThesisID  string `json:"thesisId"`
	StudentID string `json:"studentId"`

	// --- Identity & administrative data (filled by superadmin at creation) ---
	Student        StudentInfo        `json:"student"`
	Administrative AdministrativeInfo `json:"administrative"`

	// --- Academic performance (filled later, after defense) ---
	AcademicPerformance AcademicPerformance `json:"academicPerformance,omitempty"`

	// --- Thesis metadata ---
	Metadata    ThesisMetadata `json:"metadata"`
	ThesisGrade string         `json:"grade"`

	// --- Jury members information

	// --- Lifecycle ---
	Status    ThesisStatus `json:"status"`
	CreatedBy string       `json:"createdBy"` // superadmin ID
	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt,omitempty"`

	// --- Integrity / HSM-signed proof, empty until notarization ---
	HashDocument      string `json:"hashDocument,omitempty"`      // dev-only for now
	SignatureDocument string `json:"signatureDocument,omitempty"` // dev-only for now
	HashPv            string `json:"hashPv"`
	SignaturePv       string `json:"signaturePv"`
}

// StudentInfo holds identity data, set once at record creation
type StudentInfo struct {
	FullName       string `json:"fullName"`
	NationalID     string `json:"nationalId,omitempty"` // consider hashing/omitting on-chain for privacy
	Email          string `json:"email"`
	EnrollmentYear int    `json:"enrollmentYear"`
	Program        string `json:"program"`
	Department     string `json:"department"`
}

// AdministrativeInfo covers institutional/registrar-level data
type AdministrativeInfo struct {
	Institution      string    `json:"institution"`
	Faculty          string    `json:"faculty"`
	AcademicYear     string    `json:"academicYear"`
	SupervisorName   string    `json:"supervisorName"`
	SupervisorID     string    `json:"supervisorId,omitempty"`
	JuryMembers      []string  `json:"juryMembers,omitempty"`
	DefenseDate      time.Time `json:"defenseDate,omitempty"` // empty until scheduled
	RegistrationDate time.Time `json:"registrationDate"`
}

// AcademicPerformance holds the parts filled in only after defense
type AcademicPerformance struct {
	Grade        float64 `json:"grade,omitempty"`
	Mention      string  `json:"mention,omitempty"`
	JuryComments string  `json:"juryComments,omitempty"`
	Passed       bool    `json:"passed,omitempty"`
}

// ThesisMetadata describes the document itself
type ThesisMetadata struct {
	Title        string    `json:"title"`
	Abstract     string    `json:"abstract,omitempty"`
	Keywords     []string  `json:"keywords,omitempty"`
	Language     string    `json:"language"`
	PageCount    int       `json:"pageCount,omitempty"`
	FileRef      string    `json:"fileRef"`                // MinIO object reference, not the file itself
	FileChecksum string    `json:"fileChecksum,omitempty"` // sha256 of the raw file in MinIO
	SubmittedAt  time.Time `json:"submittedAt,omitempty"`
}

// NotarizeThesis attaches a document hash and HSM signature to an existing thesis record.
func (c *ThesisContract) NotarizeThesis(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	hash string,
	signature string,
) error {
	thesisJSON, err := ctx.GetStub().GetState(thesisID)
	if err != nil {
		return fmt.Errorf("échec de lecture du ledger : %w", err)
	}
	if thesisJSON == nil {
		return fmt.Errorf("aucune thèse trouvée avec l'ID '%s'", thesisID)
	}

	var thesis ThesisPayload
	if err := json.Unmarshal(thesisJSON, &thesis); err != nil {
		return fmt.Errorf("échec de désérialisation de la thèse : %w", err)
	}

	thesis.HashDocument = hash
	thesis.SignatureDocument = signature

	updatedJSON, err := json.Marshal(thesis)
	if err != nil {
		return fmt.Errorf("échec de sérialisation de la thèse : %w", err)
	}

	return ctx.GetStub().PutState(thesisID, updatedJSON)
}

// CreateThesis insère une nouvelle thèse dans le ledger.
// Appelée par le superadmin : Student, Administrative et Metadata sont renseignés,
// seul le grade (ThesisGrade) reste vide jusqu'à la soutenance.
// initialDataJSON doit être un JSON représentant les champs Student, Administrative et Metadata.
func (c *ThesisContract) CreateThesis(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	studentID string,
	initialDataJSON string,
	createdBy string,
) error {
	exists, err := c.thesisExists(ctx, thesisID)
	if err != nil {
		return err
	}

	if exists {
		return fmt.Errorf("la thèse avec l'ID '%s' existe déjà", thesisID)
	}

	// Struct intermédiaire ne contenant que les champs fournis par le superadmin
	var initialData struct {
		Student        StudentInfo        `json:"student"`
		Administrative AdministrativeInfo `json:"administrative"`
		Metadata       ThesisMetadata     `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(initialDataJSON), &initialData); err != nil {
		return fmt.Errorf("échec de désérialisation des données initiales : %w", err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("échec de récupération du timestamp de transaction : %w", err)
	}
	createdAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	thesis := ThesisPayload{
		ThesisID:       thesisID,
		StudentID:      studentID,
		Student:        initialData.Student,
		Administrative: initialData.Administrative,
		Metadata:       initialData.Metadata,
		ThesisGrade:    "", // volontairement vide : seul champ non renseigné à la création
		Status:         StatusDraft,
		CreatedBy:      createdBy,
		CreatedAt:      createdAt,
	}

	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return fmt.Errorf("échec de sérialisation de la thèse : %w", err)
	}

	return ctx.GetStub().PutState(thesisID, thesisJSON)
}

// SubmitGrade renseigne la note d'une thèse après soutenance.
// C'est le seul champ censé être vide après création par le superadmin.
func (c *ThesisContract) SubmitGrade(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	grade string,
) error {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return err
	}

	thesis.ThesisGrade = grade
	thesis.Status = StatusDefended

	return c.putThesis(ctx, thesis)
}

// NotarizeDocument attache le hash et la signature HSM du document de thèse lui-même.
func (c *ThesisContract) NotarizeDocument(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	hashDocument string,
	signatureDocument string,
) error {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return err
	}

	thesis.HashDocument = hashDocument
	thesis.SignatureDocument = signatureDocument

	return c.putThesis(ctx, thesis)
}

// NotarizePv attache le hash et la signature HSM du procès-verbal (PV) de soutenance.
func (c *ThesisContract) NotarizePv(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	hashPv string,
	signaturePv string,
) error {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return err
	}

	thesis.HashPv = hashPv
	thesis.SignaturePv = signaturePv

	// Si le document ET le PV sont notariés, on peut considérer la thèse comme entièrement notariée
	if thesis.HashDocument != "" && thesis.SignatureDocument != "" {
		thesis.Status = StatusNotarized
	}

	return c.putThesis(ctx, thesis)
}

// ReadThesis retourne la thèse correspondant à thesisID.
// Échoue si la thèse n'existe pas.
func (c *ThesisContract) ReadThesis(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
) (*ThesisPayload, error) {
	return c.getThesis(ctx, thesisID)
}

// UpdateAdministrative permet au superadmin de corriger les données administratives
// ou l'identité de l'étudiant après création (ex: erreur de saisie), sans toucher au grade
// ni aux champs de notarisation.
func (c *ThesisContract) UpdateAdministrative(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	updatedDataJSON string,
) error {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return err
	}

	var updatedData struct {
		Student        StudentInfo        `json:"student"`
		Administrative AdministrativeInfo `json:"administrative"`
		Metadata       ThesisMetadata     `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(updatedDataJSON), &updatedData); err != nil {
		return fmt.Errorf("échec de désérialisation des données mises à jour : %w", err)
	}

	thesis.Student = updatedData.Student
	thesis.Administrative = updatedData.Administrative
	thesis.Metadata = updatedData.Metadata

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("échec de récupération du timestamp de transaction : %w", err)
	}
	thesis.UpdatedAt = time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	return c.putThesis(ctx, thesis)
}

// DeleteThesis supprime une thèse du ledger.
// Échoue si la thèse n'existe pas.
func (c *ThesisContract) DeleteThesis(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
) error {
	exists, err := c.thesisExists(ctx, thesisID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("aucune thèse trouvée avec l'ID '%s'", thesisID)
	}

	return ctx.GetStub().DelState(thesisID)
}

// GetAllTheses retourne toutes les thèses actuellement enregistrées dans le ledger.
func (c *ThesisContract) GetAllTheses(
	ctx contractapi.TransactionContextInterface,
) ([]*ThesisPayload, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("échec de parcours du ledger : %w", err)
	}
	defer resultsIterator.Close()

	var theses []*ThesisPayload
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("échec d'itération sur le ledger : %w", err)
		}

		var thesis ThesisPayload
		if err := json.Unmarshal(queryResponse.Value, &thesis); err != nil {
			return nil, fmt.Errorf("échec de désérialisation d'une thèse : %w", err)
		}
		theses = append(theses, &thesis)
	}

	return theses, nil
}

// --- Fonctions utilitaires internes ---

func (c *ThesisContract) thesisExists(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
) (bool, error) {
	thesisJSON, err := ctx.GetStub().GetState(thesisID)
	if err != nil {
		return false, fmt.Errorf("échec de lecture du ledger : %w", err)
	}
	return thesisJSON != nil, nil
}

// getThesis lit et désérialise une thèse ; centralise la gestion d'erreur
// pour toutes les fonctions de mutation.
func (c *ThesisContract) getThesis(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
) (*ThesisPayload, error) {
	thesisJSON, err := ctx.GetStub().GetState(thesisID)
	if err != nil {
		return nil, fmt.Errorf("échec de lecture du ledger : %w", err)
	}
	if thesisJSON == nil {
		return nil, fmt.Errorf("aucune thèse trouvée avec l'ID '%s'", thesisID)
	}

	var thesis ThesisPayload
	if err := json.Unmarshal(thesisJSON, &thesis); err != nil {
		return nil, fmt.Errorf("échec de désérialisation de la thèse : %w", err)
	}

	return &thesis, nil
}

// putThesis sérialise et écrit une thèse ; centralise la gestion d'erreur
// pour toutes les fonctions de mutation.
func (c *ThesisContract) putThesis(
	ctx contractapi.TransactionContextInterface,
	thesis *ThesisPayload,
) error {
	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return fmt.Errorf("échec de sérialisation de la thèse : %w", err)
	}
	return ctx.GetStub().PutState(thesis.ThesisID, thesisJSON)
}
