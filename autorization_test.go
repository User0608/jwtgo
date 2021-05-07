package jwtgo_test

import (
	"fmt"
	"testing"

	"github.com/user0608/jwtgo"
)

func TestLoadRSAFile(t *testing.T) {
	datos := []struct {
		Name        string
		JWT         *jwtgo.JwtGo
		PrivatePath string
		Publicpath  string
		Want        error
	}{
		{"WithRightParams", jwtgo.New(), "cmd/rsa/app.rsa", "cmd/rsa/app.rsa.pub", nil},
		{"PublicBadPath", jwtgo.New(), "cmd/rsa/app.rsa", "nnn", fmt.Errorf(jwtgo.ErrorOpeningFile, "nnn")},
		{"PrivateBadPath", jwtgo.New(), "nn", "cmd/rsa/app.rsa.pub", fmt.Errorf(jwtgo.ErrorOpeningFile, "nn")},
		{"WithoutParams", jwtgo.New(), "", "", fmt.Errorf(jwtgo.ErrorOpeningFile, "")},
	}
	for _, d := range datos {
		t.Run(d.Name, func(t *testing.T) {
			err := d.JWT.LoadRSAKeys(d.PrivatePath, d.Publicpath)
			if err != nil {
				if err.Error() != d.Want.Error() {
					t.Error(err)
				}
			} else {
				if err != d.Want {
					t.Error(err)
				}
			}
		})
	}
}
