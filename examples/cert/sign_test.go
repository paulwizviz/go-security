package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"time"
)

// CA's Certificate specification
var caCert *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(256),
	Subject: pkix.Name{
		Organization:  []string{"ORGANIZATION_NAME"},
		Country:       []string{"COUNTRY_CODE"},
		Province:      []string{"PROVINCE"},
		Locality:      []string{"CITY"},
		StreetAddress: []string{"ADDRESS"},
		PostalCode:    []string{"POSTAL_CODE"},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	BasicConstraintsValid: true,
}

// Certification to be signed by the certificate authority
var cert *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(2019),
	Subject: pkix.Name{
		Organization:  []string{"Acme Pte Ltd"},
		Country:       []string{"UK"},
		Province:      []string{""},
		Locality:      []string{"London"},
		StreetAddress: []string{"Somewhere in london"},
		PostalCode:    []string{"LH00LH"},
	},
	IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	NotBefore:    time.Now(),
	NotAfter:     time.Now().AddDate(10, 0, 0),
	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,
}

func Example_signCACert() {

	// Creating RSA private key
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024) // Private key for the CA

	signedCert, err := x509.CreateCertificate(rand.Reader, caCert, caCert, caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	signedCert, err = x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivKey.PublicKey, caPrivKey)
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

	signedWithCACert, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	caC, err := x509.ParseCertificate(signedWithCACert)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(caC.Issuer.Organization)

	signedWithCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, caPrivKey)
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
