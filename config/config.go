package config

import (
	"os"
	"io"
	"github.com/BurntSushi/toml"
	"bytes"
)

var (
	config Conf
)



type Conf struct {
	Name string
	ServerKey string
	Server Server
	Storage Storage
	Pow Pow
}

type Server struct {
	Interface string;
	Port int;
}

type Storage struct {
	BaseDir string `toml:"base_dir"`;
	StorageKey string `toml:"storage_key"`;
}

type Pow struct {
	Ttw int
	Kdf string;
	Length int
	Zeros int;
}


func LoadConfig(filename string){

	buf := bytes.NewBuffer(nil)

	f, _ := os.Open(filename) // Error handling elided for brevity.
	io.Copy(buf, f)           // Error handling elided for brevity.
	f.Close()

	s := string(buf.Bytes())



	if _, err := toml.Decode(s, &config); err != nil {
		// handle error
	}
}

func Get() Conf{
	return config
}