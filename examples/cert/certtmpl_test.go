package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

var rootCertTemplate *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(256),
	Subject: pkix.Name{
		Organization:  []string{"ACME Root Inc"},
		Country:       []string{"US"},
		Province:      []string{"Some State"},
		Locality:      []string{"Some City"},
		StreetAddress: []string{"Some Street"},
		PostalCode:    []string{"ZIP 123456"},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	BasicConstraintsValid: true,
}

var iCertTemplate *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(256),
	Subject: pkix.Name{
		Organization:  []string{"ACME Intermediate AS"},
		Country:       []string{"EU"},
		Province:      []string{"Some State"},
		Locality:      []string{"Some City"},
		StreetAddress: []string{"Some Street"},
		PostalCode:    []string{"123456 EU"},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	BasicConstraintsValid: true,
}

var leafCertTemplate *x509.Certificate = &x509.Certificate{
	SerialNumber: big.NewInt(2019),
	Subject: pkix.Name{
		Organization:  []string{"ACME Pte Ltd"},
		Country:       []string{"UK"},
		Province:      []string{"South East"},
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
