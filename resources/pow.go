package resources

import (
	"github.com/labstack/echo"
	"net/http"
	"github.com/crholm/pl-backend/common/crypto"
	"fmt"
	"strconv"
)




func Noop(c echo.Context) error {
	return c.String(http.StatusOK, "Noop")
}

func GetPow(c echo.Context) error {
	pow := crypto.CreatePowToken();
	return c.JSON(http.StatusOK, pow)
}

func ExchangePow(c echo.Context) error {
	token := new(crypto.PowToken)
	if err := c.Bind(token); err != nil {
		fmt.Println(err)
		return c.String(http.StatusBadRequest, "bad json")
	}

	fmt.Println(token)

	valid := token.VerifyPowToken()

	return c.String(http.StatusOK, "Valid " + strconv.FormatBool(valid) );

}


