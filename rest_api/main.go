// package main

// import (
// 	"bytes"
// 	"crypto"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"
// 	"time"

// 	"github.com/HOKK-FINANCE-FZCO/crypto11"
// 	"github.com/sergiorandria/go-rest-api/canon"
// )

// // SubmissionRequest is the expected shape of the incoming payload. Grade is
// // decoded as json.Number (not float64) so malformed/out-of-range values can
// // be rejected explicitly in ValidateSubmission rather than silently coerced.
// type SubmissionRequest struct {
// 	ThesisID string                 `json:"thesisId"`
// 	Grade    json.Number            `json:"grade"`
// 	Metadata map[string]interface{} `json:"metadata"`
// }

// type SubmissionResponse struct {
// 	ThesisID      string `json:"thesisId"`
// 	DocHash       string `json:"docHash"`
// 	Signature     string `json:"signature"`
// 	CanonicalJSON string `json:"canonicalJson"`
// 	ReceivedAt    string `json:"receivedAt"`
// }

// // hsmCtx is opened once at startup and reused across requests, rather than
// // opening a new PKCS#11 session per submission.
// var hsmCtx *crypto11.Context

// func initHSM() error {
// 	pin := os.Getenv("HSM_PIN")
// 	if pin == "" {
// 		return fmt.Errorf("HSM_PIN environment variable not set")
// 	}

// 	config := &crypto11.Config{
// 		Path:       "/usr/lib/softhsm/libsofthsm2.so",
// 		TokenLabel: "MonTokenSecurise",
// 		Pin:        pin,
// 	}

// 	ctx, err := crypto11.Configure(config)
// 	if err != nil {
// 		return fmt.Errorf("failed to configure HSM: %w", err)
// 	}
// 	hsmCtx = ctx
// 	return nil
// }

// // signHash signs an already-computed SHA256 digest (given as hex) using the
// // long-lived HSM session. The caller is responsible for ensuring hashHex is
// // the exact hash that should be reported alongside the signature, so the
// // signed value and the displayed hash are provably the same bytes.
// func signHash(hashHex string) (string, error) {
// 	hashed, err := hex.DecodeString(hashHex)
// 	if err != nil {
// 		return "", fmt.Errorf("invalid hash hex: %w", err)
// 	}

// 	signer, err := hsmCtx.FindKeyPair(nil, []byte("MyKey"))
// 	if err != nil {
// 		return "", fmt.Errorf("failed to find key pair: %w", err)
// 	}

// 	signature, err := signer.Sign(nil, hashed, crypto.SHA256)
// 	if err != nil {
// 		return "", fmt.Errorf("signing failed: %w", err)
// 	}

// 	return hex.EncodeToString(signature), nil
// }

// // Adding CORS middleware
// func cors(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

// 		w.Header().Set(
// 			"Access-Control-Allow-Origin",
// 			"http://localhost:5173",
// 		)

// 		w.Header().Set(
// 			"Access-Control-Allow-Methods",
// 			"POST, OPTIONS",
// 		)

// 		w.Header().Set(
// 			"Access-Control-Allow-Headers",
// 			"Content-Type",
// 		)

// 		if r.Method == http.MethodOptions {
// 			w.WriteHeader(http.StatusOK)
// 			return
// 		}

// 		next.ServeHTTP(w, r)
// 	})
// }

// func handleSubmission(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

// 	raw, err := io.ReadAll(r.Body)
// 	if err != nil {
// 		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
// 		return
// 	}
// 	defer r.Body.Close()

// 	if len(raw) == 0 {
// 		http.Error(w, "empty request body", http.StatusBadRequest)
// 		return
// 	}

// 	// Decode using json.Number for Grade so numeric validation is explicit
// 	// (see ValidateSubmission) rather than relying on lossy/implicit
// 	// float64 coercion.
// 	var req SubmissionRequest
// 	dec := json.NewDecoder(bytes.NewReader(raw))
// 	dec.UseNumber()
// 	if err := dec.Decode(&req); err != nil {
// 		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	if err := ValidateSubmission(req); err != nil {
// 		http.Error(w, "validation failed: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	// Hashing operates on the raw bytes (canonicalized), not the decoded
// 	// struct, so the hash reflects exactly what was received before any
// 	// reserialization could subtly change it.
// 	hashHex, canonicalBytes, err := canon.HashJSON(raw)
// 	if err != nil {
// 		http.Error(w, "failed to hash payload: "+err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	signature, err := signHash(hashHex)
// 	if err != nil {
// 		http.Error(w, "failed to sign payload: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	resp := SubmissionResponse{
// 		ThesisID:      req.ThesisID,
// 		DocHash:       hashHex,
// 		Signature:     signature,
// 		CanonicalJSON: string(canonicalBytes),
// 		ReceivedAt:    time.Now().UTC().Format(time.RFC3339),
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	if err := json.NewEncoder(w).Encode(resp); err != nil {
// 		log.Printf("failed to write response: %v", err)
// 	}
// }

// func main() {
// 	if err := initHSM(); err != nil {
// 		log.Fatalf("HSM initialization failed: %v", err)
// 	}
// 	defer hsmCtx.Close()

// 	mux := http.NewServeMux()
// 	mux.HandleFunc("/api/v1/submissions", handleSubmission)

// 	addr := ":8080"
// 	log.Printf("jury-backend listening on %s", addr)
// 	if err := http.ListenAndServe(addr, cors(mux)); err != nil {
// 		log.Fatalf("server failed: %v", err)
// 	}
// }

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
	"github.com/sergiorandria/go-rest-api/gateway_sdk"
	"github.com/sergiorandria/go-rest-api/utils" // Vos utilitaires de connexion validés
)

// --- CONFIGURATION ---
// const maxBodyBytes = 1024 * 1024

// --- STRUCTURES ISSUES DU FORMULAIRE WEB (.ts) ---
type SubmissionRequest struct {
	ThesisID string                 `json:"thesisId"`
	Grade    json.Number            `json:"grade"` // Évite les pertes de précision lors du transfert HTTP
	Metadata map[string]interface{} `json:"metadata"`
}

type SubmissionResponse struct {
	ThesisID      string `json:"thesisId"`
	DocHash       string `json:"docHash"`
	Signature     string `json:"signature"`
	CanonicalJSON string `json:"canonicalJson"`
	ReceivedAt    string `json:"receivedAt"`
}

// --- GLOBALES REUTILISABLES ---
var (
	hsmCtx       *crypto11.Context
	fabricClient *gateway_sdk.GatewayClient
)

// --- INITIALISATION DU CONFIGURATEUR SOFTHSMV2 ---
func initHSM() error {
	pin := os.Getenv("HSM_PIN")
	if pin == "" {
		return fmt.Errorf("HSM_PIN environment variable not set")
	}

	slotID := int(1059061449) // Votre Slot ID SoftHSM fonctionnel

	config := &crypto11.Config{
		Path:       "/usr/local/lib/softhsm/libsofthsm2.so",
		SlotNumber: &slotID, // Sélection stricte par numéro de Slot unique
		Pin:        pin,
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return fmt.Errorf("failed to configure HSM: %w", err)
	}
	hsmCtx = ctx
	return nil
}

// --- SIGNATURE LOCAL VIA SOFTHSMV2 ---
func signHash(hashHex string) (string, error) {
	hashed, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("invalid hash hex: %w", err)
	}

	signer, err := hsmCtx.FindKeyPair(nil, []byte("MyKey"))
	if err != nil || signer == nil {
		return "", fmt.Errorf("private key 'MyKey' not found in HSM token")
	}

	signature, err := signer.Sign(nil, hashed, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	return hex.EncodeToString(signature), nil
}

// --- CORRECTION ET CONFIGURATION DU MIDDLEWARE CORS ---
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accepte toutes les requêtes locales de développement pour éliminer les NetworkError
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

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
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req SubmissionRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validation métier (via votre fichier validation.go)
	if err := ValidateSubmission(req); err != nil {
		http.Error(w, "validation failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// ─── LIGNE CORRIGÉE ───
	// Assurez-vous d'utiliser 'canon.' ici pour lier l'import !
	hashHex, canonicalBytes, err := canon.HashJSON(raw)
	if err != nil {
		http.Error(w, "hashing failed", http.StatusBadRequest)
		return
	}

	// Signature locale via votre clé matérielle sécurisée vHSM
	signature, err := signHash(hashHex)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}

	// Extraction et adaptation des paramètres pour le Smart Contract
	var thesisTitle, defenseDate string
	if title, ok := req.Metadata["thesisTitle"].(string); ok {
		thesisTitle = title
	}
	if date, ok := req.Metadata["defenseDate"].(string); ok {
		defenseDate = date
	}

	gradeFloat, err := req.Grade.Float64()
	if err != nil {
		http.Error(w, "invalid grade numeric format", http.StatusBadRequest)
		return
	}
	gradeStr := fmt.Sprintf("%.1f", gradeFloat)

	// Enregistrement immuable dans le réseau réel Hyperledger Fabric
	err = fabricClient.ExecuteTransaction("CreateThesis", req.ThesisID, gradeStr, thesisTitle, defenseDate)
	if err != nil {
		log.Printf("[FABRIC TRANSACT ERROR]: %v", err)
		http.Error(w, "failed to persist transaction on fabric ledger: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Réponse structurée destinée au framework client TypeScript (.ts)
	resp := SubmissionResponse{
		ThesisID:      req.ThesisID,
		DocHash:       hashHex,
		Signature:     signature,
		CanonicalJSON: string(canonicalBytes),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// --- POINT D'ENTREE DU DEMARRAGE BACKEND ---
func main() {
	log.Println("Initializing Security Modules and Network Infrastructure...")

	// 1. Initialisation de l'accès au conteneur SoftHSMv2
	if err := initHSM(); err != nil {
		log.Fatalf("HSM initialization failed: %v", err)
	}
	defer hsmCtx.Close()

	// 2. Établissement de la véritable connectivité gRPC réseau
	clientConn, err := utils.NewGrpcConnection()
	if err != nil {
		log.Fatalf("failed to create real gRPC connection: %v", err)
	}
	defer clientConn.Close()

	// 3. Extraction des identités X.509 de l'organisation locale de test
	id, err := utils.NewIdentity()
	if err != nil {
		log.Fatalf("failed to create fabric organization identity: %v", err)
	}

	// 4. Chargement de la fonction d'authentification des signatures du consortium
	sign, err := utils.NewSign()
	if err != nil {
		log.Fatalf("failed to create fabric organization signing function: %v", err)
	}

	// 5. Initialisation définitive de l'enveloppe globale du GatewayClient
	client, err := gateway_sdk.NewGatewayClient(clientConn, utils.ChannelName, utils.ChaincodeName, id, sign)
	if err != nil {
		log.Fatalf("failed to build gateway infrastructure: %v", err)
	}
	fabricClient = client
	defer fabricClient.Close()

	// 6. Lancement du serveur d'écoute HTTP API destiné à recevoir le fetch
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/submissions", handleSubmission)

	addr := ":8080"
	log.Printf("Jury API microservice successfully deployed on port %s", addr)
	if err := http.ListenAndServe(addr, cors(mux)); err != nil {
		log.Fatalf("server crash: %v", err)
	}
}
