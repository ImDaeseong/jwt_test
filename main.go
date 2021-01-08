// main
package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

type JwtData struct {
	iss      string
	exp      int64
	https    bool
	userId   string
	username string
}

func encodeHA256(key string, input JwtData) string {

	//데이터
	dataclaim := jwt.MapClaims{
		"iss": input.iss,
		"exp": input.exp,
		"https://daeseong.com/jwt": input.https,
		"userId":                   input.userId,
		"username":                 input.username,
	}

	Sign := jwt.NewWithClaims(jwt.SigningMethodHS256, dataclaim)

	token, err := Sign.SignedString([]byte(key))
	if err != nil {
		print(err)
	}
	return token
}

func decodeHA256(key []byte, tokenString string) bool {

	_, err := jwt.Parse(tokenString, func(*jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		return false
	}
	return true
}

func checkHA256(key []byte, tokenString string) {

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	//데이터 확인
	/*
		iss := fmt.Sprintf("%v", claims["iss"])
		exp := fmt.Sprintf("%v", claims["exp"])
		https := fmt.Sprintf("%v", claims["https://daeseong.com/jwt"])
		userId := fmt.Sprintf("%v", claims["userId"])
		username := fmt.Sprintf("%v", claims["username"])
		fmt.Println(iss)
		fmt.Println(exp)
		fmt.Println(https)
		fmt.Println(userId)
		fmt.Println(username)
	*/
	fmt.Println("데이터 확인:" + fmt.Sprintf("%v", claims))

	if err != nil {
		fmt.Println(err)
	}
}

func openPrivatekey(filePath string) *rsa.PrivateKey {

	keyData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		fmt.Println(err)
	}

	return key
}

func openPublickey(filePath string) *rsa.PublicKey {

	keyData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		fmt.Println(err)
	}

	return key
}

func signRSA(signKey *rsa.PrivateKey, input JwtData) string {

	//데이터
	dataclaim := jwt.MapClaims{
		"iss": input.iss,
		"exp": input.exp,
		"https://daeseong.com/jwt": input.https,
		"userId":                   input.userId,
		"username":                 input.username,
	}

	Sign := jwt.NewWithClaims(jwt.SigningMethodRS256, dataclaim)

	token, err := Sign.SignedString(signKey)
	if err != nil {
		print(err)
	}
	return token
}

func verifyRSA(verifyKey *rsa.PublicKey, tokenString string) bool {

	_, err := jwt.Parse(tokenString, func(*jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err != nil {
		return false
	}
	return true
}

func checkRSA(verifyKey *rsa.PublicKey, tokenString string) {

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	//데이터 확인
	/*
		iss := fmt.Sprintf("%v", claims["iss"])
		exp := fmt.Sprintf("%v", claims["exp"])
		https := fmt.Sprintf("%v", claims["https://daeseong.com/jwt"])
		userId := fmt.Sprintf("%v", claims["userId"])
		username := fmt.Sprintf("%v", claims["username"])
		fmt.Println(iss)
		fmt.Println(exp)
		fmt.Println(https)
		fmt.Println(userId)
		fmt.Println(username)
	*/
	fmt.Println("데이터 확인:" + fmt.Sprintf("%v", claims))

	if err != nil {
		fmt.Println(err)
	}
}

func HS256_test() {

	secretKey := "password1234567890"

	dataclaim := JwtData{
		"daeseong.com",
		1485270000000,
		true,
		"userId1234567890",
		"daeseong",
	}

	Token := encodeHA256(secretKey, dataclaim)
	fmt.Println("토큰값:" + Token)

	decoded := decodeHA256([]byte(secretKey), Token)
	if decoded {
		checkHA256([]byte(secretKey), Token)
	}
}

func RSA_test() {

	signKey := openPrivatekey("E:\\jwt_test\\private.key")
	//fmt.Println(signKey)

	verifyKey := openPublickey("E:\\jwt_test\\public.key")
	//fmt.Println(verifyKey)

	dataclaim := JwtData{
		"daeseong.com",
		1485270000000,
		true,
		"userId1234567890",
		"daeseong",
	}

	Token := signRSA(signKey, dataclaim)
	fmt.Println("토큰값:" + Token)

	decoded := verifyRSA(verifyKey, Token)
	if decoded {
		checkRSA(verifyKey, Token)
	}
}

func main() {

	HS256_test()
	RSA_test()
}
