package xmlsigner

import (
	"crypto"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/pkcs12"
)

type XmlSigner struct {
	// SignedXml string
	// TxnId     string
}

func GetPrivateKeyAndCert(p12FilePath, password string) (crypto.Signer, []byte, error) {
	p12Bytes, err := os.ReadFile(p12FilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read .p12 file: %v", err)
	}

	privateKey, cert, err := pkcs12.Decode(p12Bytes, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode .p12 file: %v", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not of type *rsa.PrivateKey")
	}

	signer := crypto.Signer(rsaPrivateKey)

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	certPEMBytes := pem.EncodeToMemory(certPEM)

	return signer, certPEMBytes, nil
}

// func (x *XmlSigner) GetSignedXmlAndTxnId(signer crypto.Signer, cert []byte, payloadStr string) (string, string, error) {

// }
