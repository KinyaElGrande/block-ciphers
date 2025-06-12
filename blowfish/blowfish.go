package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/blowfish"
)

// pad implements PKCS7(standardized method for padding) padding for block alignment
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// Remove PKCS7 padding after decryption
func unpad(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}

	// reads the last byte to determine padding size
	unpadding := int(data[length-1])
	if unpadding > length {
		return data
	}
	return data[:(length - unpadding)]
}

func encryptBlowfish(plaintext, key []byte) ([]byte, error) {
	// Create Blowfish cipher
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedPlaintext := pad(plaintext, blowfish.BlockSize)

	// generate random initialization vector (IV) ensuring security on the encryption
	iv := make([]byte, blowfish.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Create CBC encrypter which is more secure than ECB
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the data
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Prepend IV to ciphertext so that it can be used for decryption
	result := append(iv, ciphertext...)
	return result, nil
}

// decryptBlowfish decrypts blowfish CBC mode
func decryptBlowfish(ciphertext, key []byte) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract IV from the beginning
	if len(ciphertext) < blowfish.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// extract the 1st 8 bytes as IV
	iv := ciphertext[:blowfish.BlockSize]
	ciphertext = ciphertext[blowfish.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	result := unpad(plaintext)
	return result, nil
}

// encryptBlowfishECB encrypts each 8byte block independently
func encryptBlowfishECB(plaintext, key []byte) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedPlaintext := pad(plaintext, blowfish.BlockSize)

	ciphertext := make([]byte, len(paddedPlaintext))

	// Encrypt each block separately (ECB mode)
	for i := 0; i < len(paddedPlaintext); i += blowfish.BlockSize {
		block.Encrypt(ciphertext[i:i+blowfish.BlockSize], paddedPlaintext[i:i+blowfish.BlockSize])
	}

	return ciphertext, nil
}

func decryptBlowfishECB(ciphertext, key []byte) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	// decrypt each block separately (ECB mode)
	for i := 0; i < len(ciphertext); i += blowfish.BlockSize {
		block.Decrypt(plaintext[i:i+blowfish.BlockSize], ciphertext[i:i+blowfish.BlockSize])
	}

	result := unpad(plaintext)
	return result, nil
}

func main() {
	key := []byte("CryptoKey2025")
	plaintext := []byte(`
FROM off a hill whose concave womb reworded
A plaintful story from a sistering vale`)

	fmt.Println("=== Blowfish Encryption Demo ===")
	fmt.Printf("Original text: %s\n", string(plaintext))
	fmt.Printf("Key: %s\n", string(key))
	fmt.Printf("Block size: %d bytes\n\n", blowfish.BlockSize)

	fmt.Println("#--- CBC Mode  ---#")
	ciphertext, err := encryptBlowfish(plaintext, key)
	if err != nil {
		log.Fatal("Encryption error:", err)
	}

	fmt.Printf("Encrypted (hex): %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("Ciphertext length: %d bytes\n", len(ciphertext))

	decrypted, err := decryptBlowfish(ciphertext, key)
	if err != nil {
		log.Fatal("Decryption error:", err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))
	fmt.Printf("Success: %t\n\n", string(plaintext) == string(decrypted))

	// ECB Mode Encryption section
	fmt.Println("#--- ECB Mode ---#")
	ciphertextECB, err := encryptBlowfishECB(plaintext, key)
	if err != nil {
		log.Fatal("ECB Encryption error:", err)
	}

	fmt.Printf("ECB Encrypted (hex): %s\n", hex.EncodeToString(ciphertextECB))
	fmt.Printf("ECB Ciphertext length: %d bytes\n", len(ciphertextECB))

	decryptedECB, err := decryptBlowfishECB(ciphertextECB, key)
	if err != nil {
		log.Fatal("ECB Decryption error:", err)
	}

	fmt.Printf("ECB Decrypted: %s\n", string(decryptedECB))
	fmt.Printf("ECB Success: %t\n\n", string(plaintext) == string(decryptedECB))

	// Section 2:  Demonstrate block processing
	fmt.Println("--- Block Processing Details ---")
	fmt.Printf("Original length: %d bytes\n", len(plaintext))
	paddedData := pad(plaintext, blowfish.BlockSize)
	fmt.Printf("Padded length: %d bytes\n", len(paddedData))
	fmt.Printf("Number of blocks: %d\n", len(paddedData)/blowfish.BlockSize)
	fmt.Printf("Padding bytes: %d\n", len(paddedData)-len(plaintext))

	fmt.Println("\nBlocks breakdown:")
	for i := 0; i < len(paddedData); i += blowfish.BlockSize {
		end := i + blowfish.BlockSize
		if end > len(paddedData) {
			end = len(paddedData)
		}
		block := paddedData[i:end]
		fmt.Printf("Block %d: %q (hex: %s)\n", i/blowfish.BlockSize+1, string(block), hex.EncodeToString(block))
	}
}
