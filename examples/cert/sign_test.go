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
	rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024) // Private key for the CA

	// Self signing the root certificate, passing public key by value
	// This will produce error
	signedCert, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, rootPrivKey.PublicKey, rootPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// Self signing the root certificate with pointer to public key
	signedCert, err = x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &rootPrivKey.PublicKey, rootPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// Determine if cert contains the public key
	cert, _ := x509.ParseCertificate(signedCert)
	if reflect.DeepEqual(cert.PublicKey, &rootPrivKey.PublicKey) {
		fmt.Println("Public key found in signed certificate")
	}

	// Output:
	// x509: unsupported public key type: rsa.PublicKey
	// Public key found in signed certificate

}

// This example create an intermediate cert from root cert
func Example_signICert() {

	rootPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024) // Root private key
	iPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)    // Intermediate private key

	selfSignedRootCert, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &rootPrivKey.PublicKey, rootPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	signedRootCert, err := x509.ParseCertificate(selfSignedRootCert)
	if err != nil {
		fmt.Println(err)
	}

	signeICert, err := x509.CreateCertificate(rand.Reader, iCertTemplate, signedRootCert, &iPrivKey.PublicKey, rootPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// Unmarshal intermediate cert in bytes
	iCert, err := x509.ParseCertificate(signeICert)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(iCert.Issuer)
	fmt.Println(iCert.Subject)

	if reflect.DeepEqual(iCert.PublicKey, &iPrivKey.PublicKey) {
		fmt.Println("Same certificate public key")
	}

	// Output:
	// O=ACME Root Inc,POSTALCODE=ZIP 123456,STREET=Some Street,L=Some City,ST=Some State,C=US
	// O=ACME Intermediate AS,POSTALCODE=123456 EU,STREET=Some Street,L=Some City,ST=Some State,C=EU
	// Same certificate public key

}
