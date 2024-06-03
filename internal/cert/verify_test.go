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
	cert, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &privKey.PublicKey, privKey)
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
	cert, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &privKey.PublicKey, privKey)
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

func Example_verifyCertificate() {

	// The following steps would have been to serialize cert to PEM and cert deserialize from PEM file
	rPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	signRCert, _ := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &rPrivKey.PublicKey, rPrivKey)
	rPEM := new(bytes.Buffer)
	pem.Encode(rPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signRCert,
	})
	sRCert, _ := x509.ParseCertificate(signRCert)

	// Intermediate certificate
	iPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	signedICert, err := x509.CreateCertificate(rand.Reader, iCertTemplate, sRCert, &iPrivKey.PublicKey, rPrivKey)
	iPEM := new(bytes.Buffer)
	pem.Encode(iPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signedICert,
	})
	sICert, err := x509.ParseCertificate(signedICert)

	// Leaf certificate
	lPrivKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	signedLCert, _ := x509.CreateCertificate(rand.Reader, leafCertTemplate, sICert, &lPrivKey.PublicKey, iPrivKey)
	sLCert, _ := x509.ParseCertificate(signedLCert)

	// Create pools
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rPEM.Bytes())

	imtermediates := x509.NewCertPool()
	imtermediates.AppendCertsFromPEM(iPEM.Bytes())

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: imtermediates,
	}

	chains, err := sLCert.Verify(opts)
	fmt.Println(chains[0][0].Subject, err)
	fmt.Println(chains[0][1].Subject, err)
	fmt.Println(chains[0][2].Subject, err)

	// Output:
	// O=ACME Pte Ltd,POSTALCODE=LH00LH,STREET=Somewhere in london,L=London,ST=South East,C=UK <nil>
	// O=ACME Intermediate AS,POSTALCODE=123456 EU,STREET=Some Street,L=Some City,ST=Some State,C=EU <nil>
	// O=ACME Root Inc,POSTALCODE=ZIP 123456,STREET=Some Street,L=Some City,ST=Some State,C=US <nil>
}
