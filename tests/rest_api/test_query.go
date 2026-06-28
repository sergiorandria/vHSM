package main

import (
	"encoding/json"
	"fmt"

	"github.com/sergiorandria/go-rest-api/gateway_sdk"
	"github.com/sergiorandria/go-rest-api/utils" // Tes utilitaires de connexion locaux
)

// ==================== Those type should be implemented globaly ======================

// ThesisMetadata correspond exactement à la structure de ton nouveau Smart Contract
type ThesisMetadata struct {
	ThesisTitle string `json:"thesisTitle"`
	DefenseDate string `json:"DefenseDate"`
}

// ThesisPayload correspond au modèle de données de thèses stocké dans la blockchain
type ThesisPayload struct {
	ThesisID string         `json:"thesisId"`
	Grade    float64        `json:"grade"`
	Metadata ThesisMetadata `json:"metadata"`
}

// =========================================================================================

func main() {
	fmt.Println("===  Démarrage du Test de Requête (Soutenances / Theses) ===")

	// 1. Initialisation des connexions gRPC et de la sécurité via tes utilitaires utils
	clientConn, err := utils.NewGrpcConnection()
	if err != nil {
		fmt.Printf("Erreur connexion gRPC: %s\n", err)
		return
	}
	defer clientConn.Close()

	id, err := utils.NewIdentity()
	if err != nil {
		fmt.Printf("Erreur Identité: %s\n", err)
		return
	}

	sign, err := utils.NewSign()
	if err != nil {
		fmt.Printf("Erreur Signature: %s\n", err)
		return
	}

	// 2. Création de l'instance GatewayClient
	gatewayClient, err := gateway_sdk.NewGatewayClient(clientConn, utils.ChannelName, utils.ChaincodeName, id, sign)
	if err != nil {
		fmt.Printf("Erreur initialisation gateway: %s\n", err)
		return
	}
	defer gatewayClient.Close()

	// =======================================================================
	// PRÉ-REQUIS OPTIONNEL : Remplir le registre si ce n'est pas déjà fait
	// =======================================================================
	fmt.Println("\n[Étape Préparatoire] Initialisation du registre avec InitLedger...")
	_, _ = gatewayClient.GetContract().SubmitTransaction("InitLedger")
	// On ignore volontairement l'erreur ici car si les données existent déjà, Fabric renverra une erreur.

	// =======================================================================
	// TEST DE QUERY 1 : Lire une seule thèse spécifique via 'ReadThesis'
	// =======================================================================
	targetID := "T125"
	fmt.Printf("\n[Query 1] Lecture de la thèse unique : %s...\n", targetID)

	// Accès au contrat Fabric sous-jacent via le Getter pour faire une évaluation (Query)
	readResult, err := gatewayClient.GetContract().EvaluateTransaction("ReadThesis", targetID)
	if err != nil {
		fmt.Printf(" Impossible de lire la thèse %s (As-tu bien déployé le chaincode ?): %s\n", targetID, err)
	} else {
		var thesis ThesisPayload
		err = json.Unmarshal(readResult, &thesis)
		if err != nil {
			fmt.Printf(" Erreur de décodage JSON pour ReadThesis: %s\n", err)
		} else {
			fmt.Println(" Thèse récupérée avec succès :")
			fmt.Printf("   • ID        : %s\n", thesis.ThesisID)
			fmt.Printf("   • Titre     : %s\n", thesis.Metadata.ThesisTitle)
			fmt.Printf("   • Note      : %.2f\n", thesis.Grade)
			fmt.Printf("   • Soutenue le: %s\n", thesis.Metadata.DefenseDate)
		}
	}

	// =======================================================================
	// TEST DE QUERY 2 : Récupérer toutes les thèses via 'GetAllTheses'
	// =======================================================================
	fmt.Println("\n[Query 2] Récupération globale de toutes les thèses enregistrées...")

	allResults, err := gatewayClient.GetContract().EvaluateTransaction("GetAllTheses")
	if err != nil {
		fmt.Printf(" Erreur lors de l'exécution de GetAllTheses: %s\n", err)
		return
	}

	// Décodage du tableau d'objets JSON reçu
	var thesesList []ThesisPayload
	err = json.Unmarshal(allResults, &thesesList)
	if err != nil {
		fmt.Printf(" Erreur de décodage JSON pour la liste globale: %s\n", err)
		return
	}

	// Affichage des résultats de la boucle globale
	fmt.Printf(" Requête globale réussie ! %d thèses trouvées dans le World State :\n", len(thesesList))
	for _, t := range thesesList {
		fmt.Printf("  • [ID: %s] Note: %.2f | Date: %s | Titre: %s\n",
			t.ThesisID, t.Grade, t.Metadata.DefenseDate, t.Metadata.ThesisTitle)
	}

	fmt.Println("\n=== Fin du Test de Lecture des Thèses ===")
}
