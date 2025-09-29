package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"
)

type IdentityData struct {
	PersonalityType string
	NationalId      string
	RandomSalt      string
}

func decodeBase64(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(input))
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func aesEncrypt(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func buildPlainString(data IdentityData) string {
	return fmt.Sprintf("%s|%s|%s", data.PersonalityType, data.NationalId, data.RandomSalt)
}

func readInput(label string) (string, error) {
	fmt.Print(label)
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func main() {
	ivInput, err := readInput("Enter IV (Base64): ")
	if err != nil {
		fmt.Println(" خطا در خواندن IV:", err)
		return
	}

	keyInput, err := readInput("Enter Key (Base64): ")
	if err != nil {
		fmt.Println(" خطا در خواندن Key:", err)
		return
	}

	nationalId, err := readInput("Enter National ID: ")
	if err != nil {
		fmt.Println(" خطا در خواندن National ID:", err)
		return
	}

	iv, err := decodeBase64(ivInput)
	if err != nil || len(iv) != 16 {
		fmt.Println("خطا در IV:", err)
		return
	}

	key, err := decodeBase64(keyInput)
	if err != nil || len(key) != 16 {
		fmt.Println(" خطا در Key:", err)
		return
	}

	data := IdentityData{
		PersonalityType: "0",
		NationalId:      nationalId,
		RandomSalt:      "12456378",
	}

	plain := buildPlainString(data)
	fmt.Println(" رشته اولیه:", plain)

	ciphertext, err := aesEncrypt([]byte(plain), key, iv)
	if err != nil {
		fmt.Println(" خطا در رمزنگاری:", err)
		return
	}

	fmt.Println(" Encrypted (Base64):", base64.StdEncoding.EncodeToString(ciphertext))
}
