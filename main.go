package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 1<<15, 8, 1, 32) // 32 bytes = 256-bit key
}

func encrypt(plainText, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nil, nonce, []byte(plainText), nil)

	// Combine salt + nonce + ciphertext
	result := append(salt, nonce...)
	result = append(result, cipherText...)

	return base64.StdEncoding.EncodeToString(result), nil
}

func decrypt(encodedCipherText, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encodedCipherText)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce := data[16 : 16+nonceSize]
	cipherText := data[16+nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func main() {
	// password := "doublepassword"
	// message := "key words"

	// encrypted, err := encrypt(message, password)
	// if err != nil {
	// 	panic(err)
	// }

	password := "double password"
	encrypted := "encrypted key"
	decrypted, err := decrypt(encrypted, password)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", decrypted)
}
