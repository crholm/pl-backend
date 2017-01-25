package crypto

import (
	"github.com/crholm/pl-backend/config"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"encoding/base64"
	"strings"
	"time"
	"strconv"
	"golang.org/x/crypto/scrypt"
	"log"
)




type PowToken struct{

	Key       string `json:"key"`;
	Salt      string `json:"salt"`;

	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
	Length    int `json:"length"`;
	Zeros     int `json:"zeros"`;

	Timestamp int64 `json:"timestamp"`;
	Nonce     string `json:"nonce"`;

	Mac       string `json:"mac"`
}



func (token PowToken) macText() string{
	s := strings.Join([]string{
		token.Key,
		strconv.Itoa(token.N),
		strconv.Itoa(token.R),
		strconv.Itoa(token.P),
		strconv.Itoa(token.Length),
		strconv.Itoa(token.Zeros),
		strconv.FormatInt(token.Timestamp, 10),
		token.Nonce,
	}, "|");

	fmt.Println(s);

	return strings.Join([]string{
		token.Key,
		strconv.Itoa(token.N),
		strconv.Itoa(token.R),
		strconv.Itoa(token.P),
		strconv.Itoa(token.Length),
		strconv.Itoa(token.Zeros),
		strconv.FormatInt(token.Timestamp, 10),
		token.Nonce,
	}, "|");
}

func startingZeros(b byte) int{
	if(b >= 128){
		return 0;
	}else if(b >= 64){
		return 1;
	}else if(b >= 32){
		return 2;
	}else if(b >= 16){
		return 3;
	}else if(b >= 8){
		return 4;
	}else if(b >= 4){
		return 5;
	}else if(b >= 2){
		return 6;
	}else if(b >= 1){
		return 7;
	}else {
		return 8;
	}
}


func CreatePowToken() PowToken{
	token := new(PowToken)

	token.Salt = ""
	token.Key = RandomBase64(32)
	token.N = 2048
	token.R = 8
	token.P = 1
	token.Length = config.Get().Pow.Length
	token.Zeros = config.Get().Pow.Zeros

	token.Timestamp = time.Now().UnixNano() / 1000000
	token.Nonce = RandomBase64(16)

	fmt.Println(config.Get().ServerKey);

	key, _ := base64.StdEncoding.DecodeString(config.Get().ServerKey)

	mac := hmac.New(sha256.New, key)

	mac.Write([]byte(token.macText()))
	byteMac := mac.Sum(nil)

	token.Mac = base64.StdEncoding.EncodeToString(byteMac);

	return *token;
}



func (token PowToken) VerifyPowToken() bool{

	serverKey, _ := base64.StdEncoding.DecodeString(config.Get().ServerKey)

	mac := hmac.New(sha256.New, serverKey)

	mac.Write([]byte(token.macText()))
	byteMac := mac.Sum(nil)

	providedMac, _ := base64.StdEncoding.DecodeString(token.Mac)

	if(!hmac.Equal(byteMac, providedMac)){
		fmt.Println("Hmac does not match proof original")
		return false
	}

	key, _ := base64.StdEncoding.DecodeString(token.Key);
	salt, _ := base64.StdEncoding.DecodeString(token.Salt);

	start := time.Now()
	smac , _ := scrypt.Key(
		key,
		salt,
		token.N,
		token.R,
		token.R,
		token.Length,
	)
	elapsed := time.Since(start)
	log.Printf("SCRYOT took %s", elapsed)

	if(startingZeros(smac[0]) != token.Zeros){
		fmt.Println("scrypt does not extended key does not match given parameters")
		return false;
	}


	return true;
}




