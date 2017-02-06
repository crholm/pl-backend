package resources

import (
	"github.com/labstack/echo"
	"net/http"
	"github.com/crholm/pl-backend/config"
	"os"
	"bufio"
	"encoding/json"
	"io/ioutil"
)


type VaultFile struct {
	Vault string `json:"vault"`
	Salt string `json:"salt"`
	KDF Scrypt `json:"kdf"`
}

type Scrypt struct {
	N int `json:"N"`
	R int `json:"r"`
	P int `json:"p"`
}






func GetVault(c echo.Context) error {
	vaultName := c.Param("token");

	// Todo check that vault name is SHA256 length in base64
	// TODO check that vault name is valid base64

	file := config.Get().Storage.BaseDir + "/" + vaultName[:2] + "/" + vaultName + "/current" ;


	_, err := os.Stat(file)
	if err != nil {
		return c.String(http.StatusBadRequest, "File error 1")
	}
	if os.IsNotExist(err) {
		return c.String(http.StatusBadRequest, "File error 2")
	}
	f, err := os.Open(file);

	return c.Stream(http.StatusOK, "application/json", bufio.NewReader(f))
}


func SaveVault(c echo.Context) error {
	vaultName := c.Param("token");


	dir := config.Get().Storage.BaseDir + "/" + vaultName[:2] + "/" + vaultName  ;
	file := config.Get().Storage.BaseDir + "/" + vaultName[:2] + "/" + vaultName + "/current" ;


	_, err := os.Stat(dir)
	if err != nil {
		return c.String(http.StatusBadRequest, "Dir error 1")
	}
	if os.IsNotExist(err) {
		return c.String(http.StatusBadRequest, "Dir error 2")
	}

	vault := new(VaultFile)
	c.Bind(vault);

	jsonVault, err := json.Marshal(vault)
	if err != nil {
		panic(err)
	}

	//Writing to file
	err1 := ioutil.WriteFile(file, []byte(jsonVault), 0644)
	if err1 != nil {
		return c.String(http.StatusBadRequest, "File error 1")
	}

	return c.NoContent(http.StatusOK)
}