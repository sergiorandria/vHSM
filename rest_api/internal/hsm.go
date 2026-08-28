package internal

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

const (
	gcmIVSize    = 12       // recommended IV size for AES-GCM (96 bits)
	gcmTagBits   = 128      // authentication tag size for GCM
	maxBodyBytes = 50 << 20 // 50 MiB, adjust according to your needs
)

// sha256DigestInfoPrefix is the DER-encoded AlgorithmIdentifier for SHA-256
// (used to build the PKCS#1 v1.5 block for RSA signatures over a pre-computed
// digest). It is the ASN.1 SEQUENCE { OID sha-256, NULL } followed by the
// OCTET STRING tag/length for the 32-byte digest.
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

type HSMService struct {
	ctx       *pkcs11.Ctx
	slot      uint
	pin       string
	mu        sync.Mutex
	label     string
	signLabel string
}

// NewHSMService initializes the PKCS#11 module and locates the slot that
// contains the token with the requested token label. This initialization
// should be performed only once during the process lifetime.
func NewHSMService(modulePath, tokenLabel, pin, keyLabel string, signKeyLabel string) (*HSMService, error) {
	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %s", modulePath)
	}
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("PKCS#11 initialization failed: %w", err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		p.Finalize()
		return nil, fmt.Errorf("GetSlotList failed: %w", err)
	}

	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if strings.TrimSpace(tokenInfo.Label) == tokenLabel {
			return &HSMService{
				ctx:       p,
				slot:      slot,
				pin:       pin,
				label:     keyLabel,
				signLabel: signKeyLabel,
			}, nil
		}
	}

	p.Finalize()
	return nil, fmt.Errorf("no slot found with token %q", tokenLabel)
}

// Close finalizes the PKCS#11 module. Call once during application shutdown.
func (h *HSMService) Close() {
	if h.ctx != nil {
		h.ctx.Finalize()
	}
}

// Encrypt performs AES-GCM encryption inside the HSM and returns the IV and
// the ciphertext (which includes the authentication tag as produced by the
// PKCS#11 API). The IV is randomly generated per call; it is not secret and
// must be stored/transmitted with the ciphertext for later decryption.
func (h *HSMService) Encrypt(plaintext []byte) (iv []byte, ciphertext []byte, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	session, err := h.ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, nil, fmt.Errorf("session open failed: %w", err)
	}
	defer h.ctx.CloseSession(session)

	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		return nil, nil, fmt.Errorf("login failed: %w", err)
	}
	defer h.ctx.Logout(session)

	// Explicitly filter for objects of class CKO_SECRET_KEY to avoid
	// accidentally matching other object types (certificates, public
	// keys, etc.) that may have the same label.
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.label),
	}
	if err := h.ctx.FindObjectsInit(session, template); err != nil {
		return nil, nil, fmt.Errorf("FindObjectsInit failed: %w", err)
	}
	objs, _, err := h.ctx.FindObjects(session, 1)
	if ferr := h.ctx.FindObjectsFinal(session); ferr != nil {
		log.Printf("FindObjectsFinal: %v", ferr)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("FindObjects failed: %w", err)
	}
	if len(objs) == 0 {
		return nil, nil, fmt.Errorf("secret key with label %q not found", h.label)
	}

	// Generate a fresh, unique IV for this operation. NEVER reuse an IV
	// with the same key.
	iv = make([]byte, gcmIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("IV generation failed: %w", err)
	}

	gcmParams := pkcs11.NewGCMParams(iv, nil, gcmTagBits)
	defer gcmParams.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)}
	if err := h.ctx.EncryptInit(session, mech, objs[0]); err != nil {
		return nil, nil, fmt.Errorf("EncryptInit failed: %w", err)
	}

	ciphertext, err = h.ctx.Encrypt(session, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("Encrypt failed: %w", err)
	}

	// Some HSMs ignore the provided IV and generate their own; read back the
	// actual IV used to ensure we store the correct value.
	if actualIV := gcmParams.IV(); len(actualIV) > 0 {
		iv = actualIV
	}

	return iv, ciphertext, nil
}

// Sign signs the provided data using the HSM private key identified by
// h.signLabel.  The signing mechanism is auto-detected: CKM_SHA256_RSA_PKCS
// for RSA keys, CKM_ECDSA_SHA256 for EC keys, determined by reading CKA_KEY_TYPE.
func (h *HSMService) Sign(data []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 1. Open a session
	session, err := h.ctx.OpenSession(h.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("session open failed: %w", err)
	}
	defer h.ctx.CloseSession(session)

	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}
	defer h.ctx.Logout(session)

	// 2. Find the private key by label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, h.signLabel),
	}
	if err := h.ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("FindObjectsInit failed: %w", err)
	}
	objs, moreExist, err := h.ctx.FindObjects(session, 1)
	if ferr := h.ctx.FindObjectsFinal(session); ferr != nil {
		return nil, fmt.Errorf("FindObjectsFinal failed: %w", ferr)
	}
	if err != nil {
		return nil, fmt.Errorf("FindObjects failed: %w", err)
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("private key with label %q not found", h.signLabel)
	}
	if moreExist {
		return nil, fmt.Errorf("multiple private keys match label %q; expected exactly one", h.signLabel)
	}

	// 3. Detect the key type to select the correct signing mechanism (RSA vs ECDSA)
	keyTypeAttrs, err := h.ctx.GetAttributeValue(session, objs[0],
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)})
	if err != nil {
		return nil, fmt.Errorf("GetAttributeValue (CKA_KEY_TYPE) failed: %w", err)
	}
	if len(keyTypeAttrs) == 0 || len(keyTypeAttrs[0].Value) == 0 {
		return nil, fmt.Errorf("CKA_KEY_TYPE attribute not returned for key %q", h.signLabel)
	}

	// CKA_KEY_TYPE is a CK_ULONG; decode using native byte order (little-endian
	// on x86_64 Linux, matching how the pkcs11 library encodes uintToBytes).
	val := keyTypeAttrs[0].Value
	var keyType uint
	switch len(val) {
	case 8:
		keyType = uint(binary.LittleEndian.Uint64(val))
	case 4:
		keyType = uint(binary.LittleEndian.Uint32(val))
	case 2:
		keyType = uint(binary.LittleEndian.Uint16(val))
	case 1:
		keyType = uint(val[0])
	default:
		return nil, fmt.Errorf("unexpected CKA_KEY_TYPE size: %d bytes", len(val))
	}

	// CKK_RSA = 0x00000000, CKK_EC = 0x00000003 (per PKCS#11, as defined in miekg/pkcs11)
	//
	// The caller passes a pre-computed SHA-256 digest (32 bytes). The HSM must
	// NOT hash again, otherwise signatures are over hash(hash(data)) and fail
	// verification. So we use the "raw" mechanisms:
	//   - EC: CKM_ECDSA signs the digest directly.
	//   - RSA: CKM_RSA_PKCS signs the PKCS#1 v1.5 block; we prepend the
	//     SHA-256 DigestInfo so the HSM signs exactly the digest.
	var mech *pkcs11.Mechanism
	switch keyType {
	case pkcs11.CKK_RSA:
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		data = append(sha256DigestInfoPrefix, data...)
	case pkcs11.CKK_EC:
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	default:
		return nil, fmt.Errorf("unsupported key type 0x%04X for key %q (expected RSA or EC)", keyType, h.signLabel)
	}

	// 4. Sign the data
	if err := h.ctx.SignInit(session, []*pkcs11.Mechanism{mech}, objs[0]); err != nil {
		return nil, fmt.Errorf("SignInit failed: %w", err)
	}
	sig, err := h.ctx.Sign(session, data)
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %w", err)
	}
	return sig, nil
}
