package encrypted

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
)

var c *Crypt

func init() {
	c = new(Crypt)
}

// Crypt contains the AES secret and config for crypto.
type Crypt struct {
	secret string
	key    []byte
}

func CryptInit(secret string) error {
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, err := hex.DecodeString(secret)
	if err != nil {
		log.Printf("ERROR: while hex decoding secret provided: %s", err.Error())
		return err
	}

	// Check key length
	if len(key) != 32 {
		err = errors.New("ERROR: 'ENCRYPTED_MYSQL_SECRET' needs to be 32 bytes long")
		log.Printf(err.Error())
		return err
	}

	c = &Crypt{
		key:    key,
		secret: secret,
	}

	return nil
}

func getCipherBlock() cipher.Block {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		log.Printf("ERROR: while running NewCipher on key provided: %s", err.Error())
	}

	return block
}

// Encrypt aes encrypts string
func Encrypt(unsafe string) string {
	plaintext := []byte(unsafe)

	if c.secret == "" {
		log.Printf("ERROR: 'ENCRYPTED_MYSQL_SECRET' is required")
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Printf("ERROR: while rand.Reader %s", err.Error())
		return ""
	}

	stream := cipher.NewCFBEncrypter(getCipherBlock(), iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return fmt.Sprintf("%x", ciphertext)
}

// Decrypt decrypts aes encrypted string
func Decrypt(safe string) string {
	ciphertext, err := hex.DecodeString(safe)
	if err != nil {
		log.Printf("ERROR: while hex decoding encoded string: %s", err.Error())
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		log.Printf("ERROR: ciphertext too short")
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(getCipherBlock(), iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}
