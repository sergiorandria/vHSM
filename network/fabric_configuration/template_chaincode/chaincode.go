package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ThesisMetadata contient les informations descriptives d'une thèse.
type ThesisMetadata struct {
	ThesisTitle string `json:"thesisTitle"`
	DefenseDate string `json:"DefenseDate"`
}

// ThesisContract regroupe les fonctions du smart contract (CRUD basique).
type ThesisContract struct {
	contractapi.Contract
}

type ThesisPayload struct {
	ThesisID  string         `json:"thesisId"`
	Grade     float64        `json:"grade"`
	Metadata  ThesisMetadata `json:"metadata"`
	Hash      string         `json:"hash"`      // Should be omitempty, just for development
	Signature string         `json:"signature"` // Should be omitempty, just for development
}

// generateShortID derive un identifiant court et deterministe a partir du TxID.
// Deterministe = meme resultat sur tous les peers endosseurs (contrairement a un UUID v4 aleatoire).
func generateShortID(txID string) string {
	hash := sha256.Sum256([]byte(txID))
	return hex.EncodeToString(hash[:6]) // 12 caracteres hex
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

	thesis.Hash = hash
	thesis.Signature = signature

	updatedJSON, err := json.Marshal(thesis)
	if err != nil {
		return fmt.Errorf("échec de sérialisation de la thèse : %w", err)
	}

	return ctx.GetStub().PutState(thesisID, updatedJSON)
}

// CreateThesis insère une nouvelle thèse dans le ledger.
// L'ID de la thèse est désormais généré automatiquement (déterministe, dérivé du TxID)
// et retourné à l'appelant — il n'est plus fourni en paramètre.
func (c *ThesisContract) CreateThesis(
	ctx contractapi.TransactionContextInterface,
	grade float64,
	thesisTitle string,
	defenseDate string,
) (string, error) {
	txID := ctx.GetStub().GetTxID()
	thesisID := generateShortID(txID)

	exists, err := c.thesisExists(ctx, thesisID)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("la thèse avec l'ID '%s' existe déjà", thesisID)
	}

	thesis := ThesisPayload{
		ThesisID: thesisID,
		Grade:    grade,
		Metadata: ThesisMetadata{
			ThesisTitle: thesisTitle,
			DefenseDate: defenseDate,
		},
	}

	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return "", fmt.Errorf("échec de sérialisation de la thèse : %w", err)
	}

	if err := ctx.GetStub().PutState(thesisID, thesisJSON); err != nil {
		return "", fmt.Errorf("échec d'écriture dans le ledger : %w", err)
	}

	return thesisID, nil
}

// ReadThesis retourne la thèse correspondant à thesisID.
// Échoue si la thèse n'existe pas.
func (c *ThesisContract) ReadThesis(
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

// UpdateThesis met à jour une thèse existante (écrase entièrement ses champs).
// Échoue si la thèse n'existe pas.
func (c *ThesisContract) UpdateThesis(
	ctx contractapi.TransactionContextInterface,
	thesisID string,
	grade float64,
	thesisTitle string,
	defenseDate string,
) error {
	exists, err := c.thesisExists(ctx, thesisID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("aucune thèse trouvée avec l'ID '%s'", thesisID)
	}

	thesis := ThesisPayload{
		ThesisID: thesisID,
		Grade:    grade,
		Metadata: ThesisMetadata{
			ThesisTitle: thesisTitle,
			DefenseDate: defenseDate,
		},
	}

	thesisJSON, err := json.Marshal(thesis)
	if err != nil {
		return fmt.Errorf("échec de sérialisation de la thèse : %w", err)
	}

	return ctx.GetStub().PutState(thesisID, thesisJSON)
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
	// Une plage de clés vide ("", "") parcourt l'intégralité du ledger pour ce chaincode.
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

// thesisExists est une fonction utilitaire interne vérifiant l'existence d'une clé.
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
