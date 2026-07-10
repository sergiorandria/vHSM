package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
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
//
// Grading and PV notarization are consensus processes, not single-actor
// writes: a thesis has Administrative.JuryMembers assigned to it, and the
// ledger will not consider the defense "DEFENDED" until every one of them
// has submitted a grade via SubmitJuryGrade, nor "NOTARIZED" until every
// one of them has signed the PV via SignPv (see tryFinalizeNotarization).
// This is intentional: no single jury member — or the API server acting
// on behalf of one — can unilaterally commit a grade or a seal to the
// ledger on the group's behalf.
//
// NOTE: every field that can legitimately be empty at some point in the
// lifecycle carries `metadata:",optional"`. This is required by
// fabric-contract-api-go's schema generator/validator — it does NOT read
// `omitempty` from the json tag (that only affects encoding/json
// marshaling). Without the metadata tag, endorsement-side response
// validation rejects any record with an empty field, e.g. drafts that
// haven't been defended/notarized yet.
type ThesisPayload struct {
	// omitempty should be removed in production environment
	// ThesisID is intentionally NOT marked optional: it's the ledger key and
	// is always populated. At least one field per struct must remain
	// required, or the generated JSON schema's "required" array ends up
	// empty, which the metadata validator rejects outright.
	ThesisID  string `json:"thesisId,omitempty"`
	StudentID string `json:"studentId,omitempty" metadata:",optional"`

	// --- Identity & administrative data (filled by superadmin at creation) ---
	Student        *StudentInfo        `json:"student,omitempty" metadata:",optional"`
	Administrative *AdministrativeInfo `json:"administrative,omitempty" metadata:",optional"`

	// --- Academic performance (filled later, after defense) ---
	AcademicPerformance *AcademicPerformance `json:"academicPerformance,omitempty" metadata:",optional"`

	// --- Thesis metadata ---
	Metadata *ThesisMetadata `json:"metadata,omitempty" metadata:",optional"`

	// ThesisGrade is the FINAL grade, computed only once every assigned
	// jury member has submitted their own grade in JuryGrades. Never set
	// this directly — it's derived by SubmitJuryGrade. Kept as a plain
	// string (rather than removed) so existing readers of the ledger that
	// expect a top-level "grade" field keep working.
	ThesisGrade string `json:"grade,omitempty" metadata:",optional"`

	// JuryGrades holds one entry per jury member who has graded this
	// thesis so far. The thesis moves from DRAFT to DEFENDED, and
	// ThesisGrade gets computed, only once len(JuryGrades) ==
	// len(Administrative.JuryMembers).
	JuryGrades []JuryGrade `json:"juryGrades,omitempty" metadata:",optional"`

	// PvSignatures holds one entry per jury member who has signed the PV
	// so far, all over the same HashPv. NOTARIZED status is only reached
	// once every assigned jury member has signed AND the document itself
	// has been hashed/signed (see tryFinalizeNotarization).
	PvSignatures []PvSignature `json:"pvSignatures,omitempty" metadata:",optional"`

	// --- Lifecycle ---
	Status    ThesisStatus `json:"status,omitempty" metadata:",optional"`
	CreatedBy string       `json:"createdBy,omitempty" metadata:",optional"`
	CreatedAt time.Time    `json:"createdAt,omitempty" metadata:",optional"`
	UpdatedAt time.Time    `json:"updatedAt,omitempty" metadata:",optional"`

	// --- Integrity / HSM-signed proof, empty until notarization ---
	// HashDocument/SignatureDocument cover the thesis manuscript itself —
	// a single hash+signature pair, since the manuscript doesn't require
	// multi-party sign-off the way the PV does.
	HashDocument      string `json:"hashDocument,omitempty" metadata:",optional"`      // dev-only for now
	SignatureDocument string `json:"signatureDocument,omitempty" metadata:",optional"` // dev-only for now

	// HashPv is recorded once, the first time any assigned jury member
	// signs the PV (see SignPv) — every subsequent signature must be over
	// this same hash, or it's rejected. This is what makes "the PV is
	// available to all jury and signed there" meaningful: everyone is
	// provably signing the identical document, not a document that could
	// have been swapped between signatures.
	HashPv string `json:"hashPv,omitempty" metadata:",optional"`
}

// JuryGrade is one jury member's grade for a thesis. All jury members
// listed in Administrative.JuryMembers must submit one before the thesis
// can move past DRAFT.
type JuryGrade struct {
	JurorID     string    `json:"jurorId"`
	Grade       float64   `json:"grade"`
	Comment     string    `json:"comment,omitempty" metadata:",optional"`
	SubmittedAt time.Time `json:"submittedAt"`
}

// PvSignature is one jury member's signature over the shared PV hash
// (ThesisPayload.HashPv). All jury members listed in
// Administrative.JuryMembers must contribute one before the PV — and
// therefore the thesis — can be considered notarized.
type PvSignature struct {
	JurorID   string    `json:"jurorId"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signedAt"`
}

// StudentInfo holds identity data, set once at record creation
type StudentInfo struct {
	FullName       string `json:"fullName"`
	NationalID     string `json:"nationalId,omitempty" metadata:",optional"` // consider hashing/omitting on-chain for privacy
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
	SupervisorID     string    `json:"supervisorId,omitempty" metadata:",optional"`
	JuryMembers      []string  `json:"juryMembers,omitempty" metadata:",optional"`
	DefenseDate      time.Time `json:"defenseDate" metadata:",optional"` // empty until scheduled
	RegistrationDate time.Time `json:"registrationDate"`
}

// AcademicPerformance holds the parts filled in only after defense.
// The struct itself is only reachable via the optional *AcademicPerformance
// pointer in ThesisPayload (nil until defense), so it's fine for Grade to
// stay required here: if this object exists at all, Grade is always set.
// See the note on ThesisID above for why at least one field per struct
// must remain required.
type AcademicPerformance struct {
	Grade        float64 `json:"grade,omitempty"`
	Mention      string  `json:"mention,omitempty" metadata:",optional"`
	JuryComments string  `json:"juryComments,omitempty" metadata:",optional"`
	Passed       bool    `json:"passed,omitempty" metadata:",optional"`
}

// ThesisMetadata describes the document itself
type ThesisMetadata struct {
	Title        string    `json:"title"`
	Abstract     string    `json:"abstract,omitempty" metadata:",optional"`
	Keywords     []string  `json:"keywords,omitempty" metadata:",optional"`
	Language     string    `json:"language"`
	PageCount    int       `json:"pageCount,omitempty" metadata:",optional"`
	FileRef      string    `json:"fileRef"`                                     // MinIO object reference, not the file itself
	FileChecksum string    `json:"fileChecksum,omitempty" metadata:",optional"` // sha256 of the raw file in MinIO
	SubmittedAt  time.Time `json:"submittedAt"`
}

// JuryStatus summarizes grading/signing progress for a thesis, returned
// by GetJuryStatus.
type JuryStatus struct {
	ThesisID       string       `json:"thesisId"`
	Status         ThesisStatus `json:"status"`
	Required       int          `json:"required"`
	GradesIn       int          `json:"gradesIn"`
	PvSignaturesIn int          `json:"pvSignaturesIn"`
	PendingGraders []string     `json:"pendingGraders,omitempty" metadata:",optional"`
	PendingSigners []string     `json:"pendingSigners,omitempty" metadata:",optional"`
}

// GetAllThesesRaw fetches all data without struct validation
// This should be removed in production environment
func (c *ThesisContract) GetAllThesesRaw(ctx contractapi.TransactionContextInterface) ([]string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var results []string
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		results = append(results, string(queryResponse.Value))
	}

	return results, nil
}

// NotarizeThesis attaches a document hash and HSM signature to an existing thesis record.
//
// NOTE: this duplicates NotarizeDocument's fields, but — unlike
// NotarizeDocument — it does NOT check that grading is complete first,
// and never touches Status. Kept as-is per prior request not to remove
// existing functions, but it should not be wired up by the API: calling
// it lets a caller record a document hash/signature before jury consensus
// on the grade exists, which the rest of this contract is now built to
// prevent. Route callers to NotarizeDocument instead.
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
		Student:        &initialData.Student,
		Administrative: &initialData.Administrative,
		Metadata:       &initialData.Metadata,
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

// SubmitGrade is DEPRECATED and disabled. It used to let a single caller
// overwrite the thesis grade and flip Status straight to DEFENDED,
// bypassing jury consensus entirely — exactly the direct-commit behavior
// that's no longer acceptable. Kept only so any existing caller gets a
// clear, explicit error instead of a missing-method failure at the API
// layer. Use SubmitJuryGrade instead: once per assigned jury member, with
// the thesis only reaching DEFENDED once all of them have submitted.
func (c *ThesisContract) SubmitGrade(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	grade string,
) error {
	return fmt.Errorf("SubmitGrade is disabled: grading now requires one submission per jury member via SubmitJuryGrade, not a single direct write")
}

// NotarizeDocument attache le hash et la signature HSM du document de thèse lui-même.
// This can only be done once every assigned jury member has graded the
// thesis (Status == DEFENDED) — it will not run ahead of jury consensus.
// Recording the hash here does not by itself seal the thesis: Status only
// moves to NOTARIZED once the PV is also fully signed (see
// tryFinalizeNotarization).
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

	if thesis.Status != StatusDefended {
		return fmt.Errorf(
			"impossible de notarier le document : la soutenance n'est pas encore actée par l'ensemble du jury (statut actuel : %s)",
			thesis.Status,
		)
	}

	thesis.HashDocument = hashDocument
	thesis.SignatureDocument = signatureDocument

	tryFinalizeNotarization(thesis)

	return c.putThesis(ctx, thesis)
}

// NotarizePv is DEPRECATED and disabled. It used to let a single caller
// commit one PV hash+signature pair directly — bypassing the requirement
// that every assigned jury member individually sign the same PV hash.
// Kept only so any existing caller gets a clear, explicit error instead
// of a missing-method failure at the API layer. Use SignPv instead: once
// per assigned jury member, all signing over the same recorded HashPv.
func (c *ThesisContract) NotarizePv(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	hashPv string,
	signaturePv string,
) error {
	return fmt.Errorf("NotarizePv is disabled: the PV now requires one signature per jury member via SignPv, not a single direct write")
}

// SubmitJuryGrade records one jury member's grade for a thesis. The
// thesis only moves from DRAFT to DEFENDED — and ThesisGrade only gets
// computed — once every jury member listed in Administrative.JuryMembers
// has submitted exactly one grade here. No single grade submission ever
// commits a final result on its own.
func (c *ThesisContract) SubmitJuryGrade(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	jurorID string,
	grade string,
	comment string,
) error {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return err
	}

	if thesis.Status != StatusDraft {
		return fmt.Errorf(
			"impossible de soumettre une note : la fenêtre de notation est fermée pour cette thèse (statut actuel : %s)",
			thesis.Status,
		)
	}

	if thesis.Administrative == nil || len(thesis.Administrative.JuryMembers) == 0 {
		return fmt.Errorf("aucun membre de jury n'est assigné à la thèse '%s'", thesisID)
	}
	members := thesis.Administrative.JuryMembers

	if !isJuryMember(jurorID, members) {
		return fmt.Errorf("'%s' n'est pas membre du jury assigné à la thèse '%s'", jurorID, thesisID)
	}

	for _, g := range thesis.JuryGrades {
		if g.JurorID == jurorID {
			return fmt.Errorf("le membre du jury '%s' a déjà soumis une note pour la thèse '%s'", jurorID, thesisID)
		}
	}

	gradeValue, err := strconv.ParseFloat(grade, 64)
	if err != nil {
		return fmt.Errorf("note invalide '%s' : %w", grade, err)
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("échec de récupération du timestamp de transaction : %w", err)
	}
	submittedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	thesis.JuryGrades = append(thesis.JuryGrades, JuryGrade{
		JurorID:     jurorID,
		Grade:       gradeValue,
		Comment:     comment,
		SubmittedAt: submittedAt,
	})

	// All jury members have now graded — compute the final grade and
	// unlock the notarization stage (SignPv / NotarizeDocument).
	if len(thesis.JuryGrades) == len(members) {
		var sum float64
		for _, g := range thesis.JuryGrades {
			sum += g.Grade
		}
		average := sum / float64(len(thesis.JuryGrades))
		thesis.ThesisGrade = strconv.FormatFloat(average, 'f', 2, 64)
		thesis.Status = StatusDefended
	}

	return c.putThesis(ctx, thesis)
}

// SignPv records one jury member's signature over the thesis's PV
// (procès-verbal). The PV's hash is recorded on the first call and is
// immutable from then on — every subsequent signer must be signing over
// that exact same hash, or the call is rejected, which is what makes the
// PV genuinely "available to all jury and signed there": everyone is
// provably reviewing and signing the identical document. Like grading,
// this can't be short-circuited by a single caller: it only unlocks once
// every jury member has signed, and only once the thesis has already
// reached DEFENDED (i.e. every jury member has graded it).
func (c *ThesisContract) SignPv(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	jurorID string,
	hashPv string,
	signature string,
) error {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return err
	}

	if thesis.Status != StatusDefended {
		return fmt.Errorf(
			"impossible de signer le PV : la soutenance n'est pas encore actée par l'ensemble du jury (statut actuel : %s)",
			thesis.Status,
		)
	}

	if thesis.Administrative == nil || len(thesis.Administrative.JuryMembers) == 0 {
		return fmt.Errorf("aucun membre de jury n'est assigné à la thèse '%s'", thesisID)
	}
	members := thesis.Administrative.JuryMembers

	if !isJuryMember(jurorID, members) {
		return fmt.Errorf("'%s' n'est pas membre du jury assigné à la thèse '%s'", jurorID, thesisID)
	}

	if thesis.HashPv == "" {
		thesis.HashPv = hashPv
	} else if thesis.HashPv != hashPv {
		return fmt.Errorf("le hash du PV fourni ne correspond pas au PV déjà enregistré pour la thèse '%s' — signature refusée", thesisID)
	}

	for _, s := range thesis.PvSignatures {
		if s.JurorID == jurorID {
			return fmt.Errorf("le membre du jury '%s' a déjà signé le PV de la thèse '%s'", jurorID, thesisID)
		}
	}

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("échec de récupération du timestamp de transaction : %w", err)
	}
	signedAt := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	thesis.PvSignatures = append(thesis.PvSignatures, PvSignature{
		JurorID:   jurorID,
		Signature: signature,
		SignedAt:  signedAt,
	})

	tryFinalizeNotarization(thesis)

	return c.putThesis(ctx, thesis)
}

// GetJuryStatus reports grading/signing progress for a thesis without
// requiring the caller to fetch and diff the full record themselves —
// handy for a "3 of 4 jury members have graded" progress display.
func (c *ThesisContract) GetJuryStatus(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
) (*JuryStatus, error) {
	thesis, err := c.getThesis(ctx, thesisID)
	if err != nil {
		return nil, err
	}

	var members []string
	if thesis.Administrative != nil {
		members = thesis.Administrative.JuryMembers
	}

	graded := make(map[string]bool, len(thesis.JuryGrades))
	for _, g := range thesis.JuryGrades {
		graded[g.JurorID] = true
	}
	signed := make(map[string]bool, len(thesis.PvSignatures))
	for _, s := range thesis.PvSignatures {
		signed[s.JurorID] = true
	}

	var pendingGraders, pendingSigners []string
	for _, m := range members {
		if !graded[m] {
			pendingGraders = append(pendingGraders, m)
		}
		if !signed[m] {
			pendingSigners = append(pendingSigners, m)
		}
	}

	return &JuryStatus{
		ThesisID:       thesis.ThesisID,
		Status:         thesis.Status,
		Required:       len(members),
		GradesIn:       len(thesis.JuryGrades),
		PvSignaturesIn: len(thesis.PvSignatures),
		PendingGraders: pendingGraders,
		PendingSigners: pendingSigners,
	}, nil
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

	thesis.Student = &updatedData.Student
	thesis.Administrative = &updatedData.Administrative
	thesis.Metadata = &updatedData.Metadata

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

// GetThesisIDs retourne uniquement les IDs (clés) de toutes les thèses présentes
// sur le ledger, sans tenter de désérialiser leur contenu. Utile pour retrouver
// l'ID d'un enregistrement incomplet/corrompu qui ferait échouer la validation
// de schéma sur GetAllTheses/ReadThesis.
func (c *ThesisContract) GetThesisIDs(
	ctx contractapi.TransactionContextInterface,
) ([]string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("échec de parcours du ledger : %w", err)
	}
	defer resultsIterator.Close()

	var ids []string
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("échec d'itération sur le ledger : %w", err)
		}
		ids = append(ids, queryResponse.Key)
	}

	return ids, nil
}

// --- Fonctions utilitaires internes ---

// isJuryMember reports whether jurorID is one of the jury members
// assigned to a thesis.
func isJuryMember(jurorID string, members []string) bool {
	return slices.Contains(members, jurorID)
}

// tryFinalizeNotarization flips a thesis to NOTARIZED if — and only if —
// every consensus condition is met: all jury members have graded
// (Status == DEFENDED), the document has been hashed/signed, and every
// jury member has signed the PV. It's a pure in-memory check with no
// ledger I/O of its own; callers (SignPv, NotarizeDocument) are
// responsible for persisting the result via putThesis. Safe to call
// speculatively after any partial update — it simply does nothing if the
// conditions aren't all satisfied yet.
func tryFinalizeNotarization(thesis *ThesisPayload) {
	if thesis.Status != StatusDefended {
		return
	}
	if thesis.Administrative == nil {
		return
	}
	juryCount := len(thesis.Administrative.JuryMembers)
	if juryCount == 0 {
		return
	}
	if thesis.HashDocument == "" || thesis.SignatureDocument == "" {
		return
	}
	if len(thesis.PvSignatures) != juryCount {
		return
	}
	thesis.Status = StatusNotarized
}

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
