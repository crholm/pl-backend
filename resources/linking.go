package resources

import (
	"github.com/labstack/echo"
	"net/http"
	"github.com/crholm/pl-backend/config"
	"crypto/sha256"
	"encoding/base64"
	"crypto/hmac"
	"strconv"
	"time"
	"github.com/crholm/pl-backend/common/crypto"
	"strings"
	"fmt"
	"os"
)

type Vault struct {
	VaultName string `json:"vaultName"`
}

type OTP struct{
	Email string `json:"email"`
	//Password string `json:"password"`
	Timestamp int64 `json:"timestamp"`
	Nonce string `json:"nonce"`
	Mac string `json:"mac"`
	OTP string `json:"otp"`
}

func (otp OTP) macText() string{
	s := strings.Join([]string{
		otp.Email,
		//otp.Password,
		strconv.FormatInt(otp.Timestamp, 10),
		otp.Nonce,
	}, "|");
	return s
}

func (otp OTP) toMac() string{
	serverKey, _:= base64.StdEncoding.DecodeString(config.Get().ServerKey);

	mac := hmac.New(sha256.New, serverKey)
	mac.Write([]byte(otp.macText()))
	macBytes := mac.Sum(nil);
	return base64.StdEncoding.EncodeToString(macBytes)
}

func (otp OTP) toOTP() string{
	serverKey, _:= base64.StdEncoding.DecodeString(config.Get().ServerKey);
	mac := hmac.New(sha256.New, serverKey)
	mac.Write([]byte(otp.Mac))
	macBytes := mac.Sum(nil);
	return base64.StdEncoding.EncodeToString(macBytes)[:4]
}

func (otp OTP) validMac() bool{
	mac1, _ := base64.StdEncoding.DecodeString(otp.toMac())
	mac2, _ := base64.StdEncoding.DecodeString(otp.Mac)
	return hmac.Equal(mac1, mac2)
}



func InitClientLinking(c echo.Context) error {

	email := c.Param("email")
	//password := c.QueryParam("password")

	var otp = new(OTP)
	otp.Email = email
	//otp.Password = password
	otp.Timestamp = time.Now().UnixNano() / 1000000
	otp.Nonce = crypto.RandomBase64(16)

	otp.Mac = otp.toMac()
	expectedOTP := otp.toOTP()

	// TODO smtp send email with OTP
	fmt.Println("Email OTP: " + expectedOTP)

	return c.JSON(http.StatusOK, otp)
}

func FinishClientLinking(c echo.Context) error{

	otp := new(OTP)
	if err := c.Bind(otp); err != nil {
		fmt.Println(err)
		return c.String(http.StatusBadRequest, "bad json")
	}

	if( (time.Now().UnixNano()/ 1000000) - otp.Timestamp > 1000*60*5){
		return c.String(http.StatusBadRequest, "OTP has timedout")
	}

	if(!otp.validMac()){
		return c.String(http.StatusBadRequest, "Basic data has been changed")
	}

	if(otp.OTP != otp.toOTP()){
		return c.String(http.StatusBadRequest, "OTP does not match")
	}


	storageKey, _:= base64.StdEncoding.DecodeString(config.Get().Storage.StorageKey);
	mac := hmac.New(sha256.New, storageKey)
	mac.Write([]byte(otp.Email));
	macBytes := mac.Sum(nil);
	vaultName := base64.StdEncoding.EncodeToString(macBytes);

	dir := config.Get().Storage.BaseDir + "/" + vaultName[:2] + "/" + vaultName;

	os.MkdirAll(dir, 0777);

	v := Vault{VaultName:vaultName}

	return c.JSON(http.StatusOK, v)
}
