package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

func Example_csr() {

	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Some Org Pte Ltd"},
		},
		PublicKey: &privKey.PublicKey,
	}

	signedCSR, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		fmt.Println(err)
	}

	sCSR, err := x509.ParseCertificateRequest(signedCSR)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(sCSR.Subject.Organization)

	// Output:
	// [Some Org Pte Ltd]
}
