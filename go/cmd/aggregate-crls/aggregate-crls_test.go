package main

import (
	"net/url"
	"testing"
)

func Test_makeFilenameFromUrl(t *testing.T) {
	names := make(map[string]bool)

	checkCollision := func(t *testing.T, list []string, db map[string]bool) {
		for _, crl := range list {
			url, _ := url.Parse(crl)

			filename := makeFilenameFromUrl(*url)
			if db[filename] {
				t.Errorf("Name collision: %s in %v", filename, db)
			}

			db[filename] = true
		}
	}

	crls := []string{"http://repository.net/crl/1000-1/complete.crl",
		"http://repository.net/crl/100-1/complete.crl",
		"http://repository.net/crl/10-1/complete.crl",
		"http://repository.net/crl/complete.crl"}
	checkCollision(t, crls, names)

	crls2 := []string{"http://repository.com/crl",
		"http://repository.com/crl.crl",
		"http://crl.repository.com/",
		"http://crl.repository.com/crl"}
	checkCollision(t, crls2, names)

}
