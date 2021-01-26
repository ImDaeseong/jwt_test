package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

func getSha256(json string) string {

	sha := sha256.New()
	sha.Write([]byte(json))
	hash256 := sha.Sum(nil)
	strHex := hex.EncodeToString(hash256)
	return strHex
}

func getHmac256(sData string, sPwd string) string {

	hmac := hmac.New(sha256.New, []byte(sPwd))
	hmac.Write([]byte(sData))
	hash256 := hmac.Sum(nil)
	strHex := hex.EncodeToString(hash256)
	base64 := EncodeBase64([]byte(strHex))
	return base64
}

func getHmacDatetime() string {

	now := time.Now()
	timeStamp := fmt.Sprintf("%s", now.Format(time.RFC3339))
	return timeStamp
}

func EncodeBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

func DecodeBase64(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}

func main() {

	json := "{\"iss\":\"daeseong.com\",\"exp\":1485270000000,\"https://daeseong.com/jwt\":true,\"userId\":\"userId1234567890\",\"username\":\"daeseong\"}"
	payloadEnc := getSha256(json)
	//fmt.Println("payloadEnc:" + payloadEnc)

	method := "POST"
	uri := "https://daeseong.com/jwt"
	hmacDatetime := getHmacDatetime()
	queryString := ""
	stringToSign := method + "\n" + uri + "\n" + hmacDatetime + "\n" + queryString + "\n" + payloadEnc
	//fmt.Println("stringToSign:" + stringToSign)

	sValue := getHmac256(stringToSign, "password1234567890")
	fmt.Println("sValue:" + sValue)
}
