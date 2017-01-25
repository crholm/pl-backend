package crypto

import (
	"encoding/binary"
	"crypto/rand"
	"encoding/base64"
)

func RandomString(pwdLen int) string {

	a := "0123456789"
	a += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	a += "abcdefghijklmnopqrstuvwxyz"

	aLen := uint64(len(a))

	buf := ""
	for i := 0; i < pwdLen; i++ {
		b := make([]byte, 8)
		rand.Read(b)
		c := binary.BigEndian.Uint64(b)
		buf += string(a[c % aLen])
	}

	return buf
}


func RandomBase64(numOfBytes int) string {
	b := make([]byte, numOfBytes)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}