package certmodel

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// CA's Certificate specification
var CACertTemplate *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(256),
	Subject: pkix.Name{
		Organization:  []string{"Acme Root CA Inc"},
		Country:       []string{"US"},
		Province:      []string{"Oregon"},
		Locality:      []string{"Springfield"},
		StreetAddress: []string{"Somewhere in Springfield"},
		PostalCode:    []string{"1234567"},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	BasicConstraintsValid: true,
}

// Certification to be signed by the certificate authority
var CertTemplate *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(2019),
	Subject: pkix.Name{
		Organization:  []string{"Acme Pte Ltd"},
		Country:       []string{"UK"},
		Province:      []string{"Westminister"},
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
