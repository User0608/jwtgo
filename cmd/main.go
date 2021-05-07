package main

import (
	"fmt"
	"log"

	"github.com/user0608/jwtgo"
)

func main() {
	jw := jwtgo.New()
	if err := jw.LoadRSAKeys("rsa/app.rsa", "rsa/app.rsa.pub"); err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("Cargo con éxito!")
}
