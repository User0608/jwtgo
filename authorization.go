package jwtgo

import (
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/dgrijalva/jwt-go"
)

const (
	ErrorOpeningFile = "No se pudo abrir el archivo %s\n"
	ErrorReadingFile = "No se pudo leer el archivo %s\n"
	ErrorParsingKeys = "No se pudo parsear la llave %s\n"
)

// JwtGo , estructura la cual contendra las claves, tanto privada com publica, y realizara
// las operasions, para JWT
type JwtGo struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	once       sync.Once
}

func New() *JwtGo {
	return &JwtGo{}
}
func Fatal(err error) {
	if err != nil {
		log.Fatalln("Error:", err.Error())
	}
}

// LoadRSAKeys recibe como parametros, los paths de la clave privada y la
// clave public generda con openssl. También ver LoadRSAKeysWithFiles
func (j *JwtGo) LoadRSAKeys(privatePath, publicPath string) (err error) {
	err = nil
	j.once.Do(func() {
		var privateFile, publicFile *os.File
		privateFile, err = os.OpenFile(privatePath, os.O_RDONLY, 0666)
		if err != nil {
			err = fmt.Errorf(ErrorOpeningFile, privatePath)
			return
		}
		publicFile, err = os.OpenFile(publicPath, os.O_RDONLY, 0666)
		if err != nil {
			err = fmt.Errorf(ErrorOpeningFile, publicPath)
			return
		}
		err = j.loadRSAKeys(privateFile, publicFile)
	})
	return
}

// LoadRSAKeysWithFiles recibe los archivos en los cuales se encuentra las claves,
// tanto privada como publica.
func (j *JwtGo) LoadRSAKeysWithFiles(privateFile, publicFile *os.File) (err error) {
	err = nil
	j.once.Do(func() {
		err = j.loadRSAKeys(privateFile, publicFile)
	})
	return
}
func (j *JwtGo) loadRSAKeys(privateFile, publicFile *os.File) error {
	var privateBytesKey []byte
	var publicBytesKey []byte
	var err error

	if privateBytesKey, err = io.ReadAll(privateFile); err != nil {
		return fmt.Errorf(ErrorReadingFile, privateFile.Name())
	}
	if publicBytesKey, err = io.ReadAll(publicFile); err != nil {
		return fmt.Errorf(ErrorReadingFile, publicFile.Name())
	}
	if j.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateBytesKey); err != nil {
		return fmt.Errorf(ErrorParsingKeys, privateFile.Name())
	}
	if j.publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicBytesKey); err != nil {
		return fmt.Errorf(ErrorParsingKeys, publicFile.Name())
	}
	return nil
}
