package pemenc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"reflect"
	"time"
)

func Example_key() {

	privKey, err := rsa.GenerateKey(rand.Reader, 1025)
	if err != nil {
		log.Fatal(err)
	}

	keyPEM := new(bytes.Buffer)
	pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	content := []byte(fmt.Sprintf("%v", keyPEM))

	block, _ := pem.Decode(content)
	keyFromBlock, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if reflect.DeepEqual(keyFromBlock, privKey) {
		fmt.Println("--Same key---")
	}

	// Output:
	// --Same key---

}

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

func Example_cert() {
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	signedWithCACert, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedWithCACert,
	})

	content := []byte(fmt.Sprintf("%v", certPEM))

	block, _ := pem.Decode(content)
	if reflect.DeepEqual(signedWithCACert, block.Bytes) {
		fmt.Println("--Same Cert--")
	}

	// Output:
	// --Same Cert--
}
