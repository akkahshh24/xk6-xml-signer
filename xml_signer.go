package xmlsigner

import (
	"crypto"
	"crypto/rsa"
	"log"
	"os"
	"time"

	"github.com/beevik/etree"
	"github.com/brianvoe/gofakeit/v6"
	dsig "github.com/russellhaering/goxmldsig"
	"go.k6.io/k6/js/modules"
	"golang.org/x/crypto/pkcs12"
)

func init() {
	modules.Register("k6/x/xmlsigner", new(XmlSigner))
}

type XmlSigner struct {
	PrivateKey crypto.Signer
	CertBytes  []byte
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

	x.PrivateKey = signer
	x.CertBytes = cert.Raw
}

func (x *XmlSigner) GetSignedXml(payload string) (string, string) {

	doc := etree.NewDocument()
	if err := doc.ReadFromString(payload); err != nil {
		panic(err)
	}

	doc.Root().SelectElement("Head").SelectAttr("msgId").Value = gofakeit.Regex(`^[a-zA-Z0-9]{35}$`)
	doc.Root().SelectElement("Head").SelectAttr("ts").Value = time.Now().Format("2006-01-02T15:04:05.000-07:00")
	doc.Root().SelectElement("Txn").SelectAttr("custRef").Value = gofakeit.Regex(`^[0-9]{12}$`)
	txnId := gofakeit.Regex(`^[a-zA-Z0-9]{35}$`)
	doc.Root().SelectElement("Txn").SelectAttr("id").Value = txnId
	doc.Root().SelectElement("Txn").SelectAttr("refId").Value = gofakeit.Regex(`^[0-9]{6}$`)
	doc.Root().SelectElement("Txn").SelectAttr("ts").Value = time.Now().Format("2006-01-02T15:04:05.000-07:00")

	ctx, _ := dsig.NewSigningContext(x.PrivateKey, [][]byte{x.CertBytes})
	signedElement, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		log.Fatalf("failed to sign payload: %v", err)
	}

	doc.SetRoot(signedElement)

	str, err := doc.WriteToString()
	if err != nil {
		log.Fatalf("failed to write payload to string: %v", err)
	}

	return str, txnId
}
