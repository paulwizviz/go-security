package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/paulwizviz/learn-security/internal/certmodel"
)

func genPrivateKeyPEM(key any) *bytes.Buffer {

	pemBuffer := new(bytes.Buffer)
	switch v := key.(type) {
	case *rsa.PrivateKey:
		pem.Encode(pemBuffer, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(v),
		})
		return pemBuffer
	default:
		return nil
	}
}

func genICertPEM[T *rsa.PublicKey | *ecdsa.PublicKey, U *rsa.PrivateKey | *ecdsa.PrivateKey](pubKey T, privKey U) *bytes.Buffer {
	cert, _ := x509.CreateCertificate(rand.Reader, certmodel.CACertTemplate, certmodel.CertTemplate, pubKey, privKey)
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return certPEM
}

func main() {

	walletDirPtr := flag.String("directory", "", "Location of wallet")
	flag.Parse()

	if *walletDirPtr == "" {
		log.Fatal(fmt.Errorf("location of wallet not specified"))
	}

	if _, err := os.Stat(*walletDirPtr); os.IsNotExist(err) {
		os.Mkdir(*walletDirPtr, 0775)
	}

	rsaCAPK, _ := rsa.GenerateKey(rand.Reader, 1024)

	keyPEM := genPrivateKeyPEM(rsaCAPK)
	if err := ioutil.WriteFile(path.Join(*walletDirPtr, "pk.pem"), keyPEM.Bytes(), 0755); err != nil {
		log.Fatal(err)
	}

	icertPEM := genICertPEM(&rsaCAPK.PublicKey, rsaCAPK)
	if err := ioutil.WriteFile(path.Join(*walletDirPtr, "ca.cer"), icertPEM.Bytes(), 0755); err != nil {
		log.Fatal(err)
	}
}
