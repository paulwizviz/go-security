package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"reflect"
)

func Example_signCACert() {

	// Creating RSA private key
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024) // Private key for the CA

	signedCert, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	signedCert, err = x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// Determine if cert contains the public key
	cert, _ := x509.ParseCertificate(signedCert)
	if reflect.DeepEqual(cert.PublicKey, &caPrivKey.PublicKey) {
		fmt.Println("abc")
	}

	// Output:
	// x509: unsupported public key type: rsa.PublicKey
	// abc

}

func Example_signCert() {

	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	signedWithCACert, err := x509.CreateCertificate(rand.Reader, certTemplate, caCertTemplate, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	caC, err := x509.ParseCertificate(signedWithCACert)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(caC.Issuer.Organization)

	signedWithCert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	c, err := x509.ParseCertificate(signedWithCert)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(c.Issuer.Organization)

	// Output:
	// [ORGANIZATION_NAME]
	// [Acme Pte Ltd]

}
