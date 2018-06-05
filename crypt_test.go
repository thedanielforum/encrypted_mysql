package encrypted

import (
	"testing"
)

const testSecret = "6368616e676520746869732070617373776f726420746f206120736563726574"
const testEncrypted = "99024ec70a6bf2804675e7311bfaad221f8b9576"

func TestCryptInit(t *testing.T) {
	// Should fail
	err := CryptInit("")
	if err == nil {
		t.Errorf("CryptInit was incorrect, got: %t, want: %t.", err, nil)
	}

	// Should fail
	err = CryptInit("testtest")
	if err == nil {
		t.Errorf("CryptInit was incorrect, got: %t, want: %t.", err, nil)
	}

	// Should succeed
	err = CryptInit(testSecret)
	if err != nil {
		t.Errorf("CryptInit was incorrect, got: %s, want: %s", err.Error(), "")
	}
}

func TestGetCipherBlock(t *testing.T) {
	err := CryptInit(testSecret)
	if err != nil {
		t.Errorf("CryptInit was incorrect, got: %s, want: %s", err.Error(), "")
	}

	// Check that we get a configured chiper.Block
	c := getCipherBlock()
	if c.BlockSize() != 16 {
		t.Errorf("getCipherBlock was incorrect, got: %d, want: %d", c.BlockSize(), 16)
	}
}

func TestEncrypt(t *testing.T) {
	err := CryptInit(testSecret)
	if err != nil {
		t.Errorf("CryptInit was incorrect, got: %s, want: %s", err.Error(), "")
	}

	enc := Encrypt("test")
	if len(enc) != 40 {
		t.Errorf("Encrypt was incorrect, got: %d, want: %d", len(enc), 40)
	}
}

func TestDecrypt(t *testing.T) {
	err := CryptInit(testSecret)
	if err != nil {
		t.Errorf("CryptInit was incorrect, got: %s, want: %s", err.Error(), "")
	}

	dec := Decrypt(testEncrypted)
	if dec != "test" {
		t.Errorf("Decrypt was incorrect, got: %s, want: %s", dec, "test")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	err := CryptInit(testSecret)
	if err != nil {
		t.Errorf("CryptInit was incorrect, got: %s, want: %s", err.Error(), "")
	}

	const text = "test this is a longer text than last time"

	enc := Encrypt(text)
	dec := Decrypt(enc)
	if dec != text {
		t.Errorf("Decrypt was incorrect, got: %s, want: %s", dec, text)
	}
}
