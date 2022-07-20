package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func genCertPEM1() ([]byte, error) {

	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	cert, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CA CERTIFICATE",
		Bytes: cert,
	})

	return certPEM.Bytes(), nil
}

func genCertPEM2() ([]byte, error) {

	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	cert, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	return certPEM.Bytes(), nil
}

func Example_certPool() {

	pem1, _ := genCertPEM1()
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(pem1)
	fmt.Println(ok)

	pem2, _ := genCertPEM2()
	ok = pool.AppendCertsFromPEM(pem2)
	fmt.Println(ok)

	// Output:
	// false
	// true

}
