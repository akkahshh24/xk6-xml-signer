// xk6 build latest --with github.com/akkahshh24/xk6-xml-signer@v0.0.1

package xmlsigner

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	dsig "github.com/akkahshh24/go-xml-signer"
	"github.com/beevik/etree"
	"github.com/brianvoe/gofakeit/v6"
	"go.k6.io/k6/js/modules"
	"golang.org/x/crypto/pkcs12"
)

func init() {
	modules.Register("k6/x/xmlsigner", new(XmlSigner))
}

type XmlSigner struct {
	PrivateKey      crypto.Signer
	CertBytes       []byte
	PayloadDocument *etree.Document
	SignedXml       string
	TxnId           string
	Modulus         string
	Exponent        string
}

func (x *XmlSigner) GetPrivateKeyAndCert(p12FilePath, password string) {
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

	x.PrivateKey = signer
	x.CertBytes = certPEMBytes

	// Decode the PEM data
	block, _ := pem.Decode(certPEMBytes)
	if block == nil {
		log.Fatalf("failed to decode PEM block")
	}

	// Parse the certificate
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v", err)
	}

	// Check if the certificate contains an RSA public key
	rsaPublicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("certificate does not contain an RSA public key")
	}

	modulusValue := new(big.Int).SetBytes(rsaPublicKey.N.Bytes())
	exponentValue := big.NewInt(int64(rsaPublicKey.E))

	x.Modulus = base64.StdEncoding.EncodeToString(modulusValue.Bytes())
	x.Exponent = base64.StdEncoding.EncodeToString(exponentValue.Bytes())
}

func (x *XmlSigner) GetPayloadDocument(payload string) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(payload); err != nil {
		log.Fatalf("failed to create doc from string: %v", err)
	}
	x.PayloadDocument = doc
}

func (x *XmlSigner) GetSignedXml() {

	x.PayloadDocument.Root().SelectElement("Head").SelectAttr("msgId").Value = gofakeit.Regex(`^[a-zA-Z0-9]{35}$`)
	x.PayloadDocument.Root().SelectElement("Head").SelectAttr("ts").Value = time.Now().Format("2006-01-02T15:04:05.000-07:00")
	x.PayloadDocument.Root().SelectElement("Txn").SelectAttr("custRef").Value = gofakeit.Regex(`^[0-9]{12}$`)
	x.TxnId = gofakeit.Regex(`^[a-zA-Z0-9]{35}$`)
	x.PayloadDocument.Root().SelectElement("Txn").SelectAttr("id").Value = x.TxnId
	x.PayloadDocument.Root().SelectElement("Txn").SelectAttr("refId").Value = gofakeit.Regex(`^[0-9]{6}$`)
	x.PayloadDocument.Root().SelectElement("Txn").SelectAttr("ts").Value = time.Now().Format("2006-01-02T15:04:05.000-07:00")

	ctx, _ := dsig.NewSigningContext(x.PrivateKey, [][]byte{x.CertBytes})
	signedElement, err := ctx.SignEnveloped(x.PayloadDocument.Root())
	if err != nil {
		log.Fatalf("failed to sign payload: %v", err)
	}

	signedElement.SelectElement("Modulus").SetText(x.Modulus)
	signedElement.SelectElement("Exponent").SetText(x.Exponent)
	x.PayloadDocument.SetRoot(signedElement)

	str, err := x.PayloadDocument.WriteToString()
	if err != nil {
		log.Fatalf("failed to write payload to string: %v", err)
	}

	x.SignedXml = str
}
