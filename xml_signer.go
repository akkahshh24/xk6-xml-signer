package xmlsigner

import (
	"crypto"
	"crypto/rsa"
	"encoding/pem"
	"log"
	"os"

	"go.k6.io/k6/js/modules"
	"golang.org/x/crypto/pkcs12"
)

func init() {
	modules.Register("k6/x/xmlsigner", new(XmlSigner))
}

type XmlSigner struct {
	// PrivateKey crypto.Signer
	// CertBytes  []byte
	// SignedXml  string
	// TxnId      string
}

func GetPrivateKeyAndCert(p12FilePath, password string) (crypto.Signer, []byte) {
	p12Bytes, err := os.ReadFile(p12FilePath)
	if err != nil {
		log.Fatalf("failed to read .p12 file: %v", err)
	}

	privateKey, cert, err := pkcs12.Decode(p12Bytes, password)
	if err != nil {
		log.Fatalf("failed to decode .p12 file: %v", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("private key is not of type *rsa.PrivateKey")
	}

	signer := crypto.Signer(rsaPrivateKey)

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	certPEMBytes := pem.EncodeToMemory(certPEM)

	return signer, certPEMBytes
}

// func (x *XmlSigner) GetSignedXmlAndTxnId(signer crypto.Signer, cert []byte, payloadStr string) (string, string, error) {

// }
