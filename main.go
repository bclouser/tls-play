package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
)

func CertificateToPem(cert *x509.Certificate) []byte {
	// format as x509 and dump as pem block into buf
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(certBlock)
}

func CertificateBytesToPem(certBytes []byte) []byte {
	// format as x509 and dump as pem block into buf
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	return pem.EncodeToMemory(certBlock)
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

func marshalAsn1ExtensionValue(ku x509.KeyUsage) ([]byte, error) {

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	return asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
}

func main() {

	// create device rsa key pair
	// deviceRsaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	// if err != nil {
	// 	fmt.Println("Failed to generate rsa key pair: " + err.Error())
	// }
	// deviceRsaPubKey := deviceRsaPrivKey.PublicKey

	// create device ecdsa key pair
	fmt.Println("Generating key pair...")
	deviceEcdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Failed to generate rsa key pair: " + err.Error())
	}
	deviceEcdsaPubKey := deviceEcdsaPrivKey.PublicKey

	// format as x509 and dump key to file
	privKeyX509Bytes, err := x509.MarshalPKCS8PrivateKey(deviceEcdsaPrivKey)
	if err != nil {
		fmt.Println("Failed to format rsa private key as x509. Error: " + err.Error())
	}
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyX509Bytes,
	}
	devicePrivateKeyPem := pem.EncodeToMemory(privateKeyBlock)

	// format as x509 and dump key to file
	pubKeyX509Bytes, err := x509.MarshalPKIXPublicKey(&deviceEcdsaPubKey)
	if err != nil {
		fmt.Println("Failed to marshal ecdsa public key into x509 bytes. Error: " + err.Error())
		os.Exit(1)
	}
	pubKeyBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubKeyX509Bytes,
	}
	devicePublicKeyPem := pem.EncodeToMemory(pubKeyBlock)

	fmt.Println(string(devicePublicKeyPem[:]))
	fmt.Println(string(devicePrivateKeyPem[:]))

	deviceUuid := uuid.NewV4()
	fmt.Println("Generating csr for device with uuid: " + deviceUuid.String())

	subject := pkix.Name{
		CommonName: deviceUuid.String(),
	}

	// this actually worked...
	// idkDigitalSignature, err := marshalAsn1ExtensionValue(x509.KeyUsageDigitalSignature)
	// if err != nil {
	// 	fmt.Println("Failed to marshal digitalSignature as ASN1")
	// }

	// This objectIdentifier came from the x509 package for client auth
	// https://github.com/golang/go/blob/73667209c1c83bd48fe7338c3b4caaa05c073202/src/crypto/x509/x509.go#L644C3-L644C24
	idkClientAuth, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}})
	if err != nil {
		fmt.Println("Failed to marshal clientAuth as ASN1")
	}
	csrExtensions := []pkix.Extension{
		// pkix.Extension{
		// 	// keyUsage
		// 	Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		// 	Critical: true,
		// 	Value:    idkDigitalSignature,
		// },
		pkix.Extension{
			// extKeyUsage
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
			Critical: true,
			Value:    idkClientAuth,
		},
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		// Extensions contains all requested extensions, in raw form. When parsing
		// CSRs, this can be used to extract extensions that are not parsed by this
		// package.
		Extensions: csrExtensions,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, deviceEcdsaPrivKey)

	if err != nil {
		fmt.Println("Failed to create csr. Err: " + err.Error())
		os.Exit(1)
	}

	deviceCsrDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	fmt.Println("CSR: ")
	fmt.Println(string(deviceCsrDER[:]))

	// openssl x509 -req -days 36135 -extfile "${CERTS_DIR}/client.ext" -in "${device_dir}/${device_id}.csr" -CAkey "${DEVICES_DIR}/ca.key" -CA "${DEVICES_DIR}/ca.crt" -CAcreateserial -out "${device_dir}/client.pem"

	// parse as certificate
	// get the public key
	// read in the private key

	// read and parse device root ca
	// TODO: We need to get these from the server
	fmt.Println("Reading and parsing device root cert")
	deviceRootCaFile, err := os.ReadFile("deviceRootCa.crt")
	if err != nil {
		fmt.Println("Failed to read in device root ca. Error: " + err.Error())
		os.Exit(1)
	}
	certBlock, _ := pem.Decode(deviceRootCaFile)

	deviceRootCa, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("Failed to parse device root certificate from file. Error: " + err.Error())
		os.Exit(1)
	}

	deviceRootCaBytes := CertificateToPem(deviceRootCa)
	fmt.Println("Device Root Ca Cert as PEM block")
	fmt.Println(string(deviceRootCaBytes[:]))

	fmt.Println("Getting device root ca public key from the certificate")
	// get public key from the certificate
	rootCaPublicKey := deviceRootCa.PublicKey.(*ecdsa.PublicKey)
	fmt.Println(rootCaPublicKey.X)
	fmt.Println("")

	fmt.Println("Reading and parsing device root ca private key")
	// read and parse private key
	rootCaPrivKeyFile, err := os.ReadFile("deviceRootCaPrivate.key")
	if err != nil {
		fmt.Println("Failed to read in root ca private key. Error: " + err.Error())
		os.Exit(1)
	}

	privBlock, _ := pem.Decode(rootCaPrivKeyFile)
	rootCaPrivateKey, _ := x509.ParseECPrivateKey(privBlock.Bytes)
	fmt.Println(rootCaPrivateKey.X)
	fmt.Println("")

	// Create the cert we want to sign
	deviceCert := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(uuid.NewV4().Bytes()),
		Subject: pkix.Name{
			CommonName:    deviceUuid.String(),
			Organization:  []string{"Toradex, INC."},
			Country:       []string{"CH"},
			Province:      []string{""},
			Locality:      []string{"Horw"},
			StreetAddress: []string{"Ebenaustrasse 10"},
			PostalCode:    []string{"6048"},
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().AddDate(100, 0, 0),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: csrExtensions,
	}

	if err != nil {
		fmt.Println("Failed to parse certificate from CSR. Error: " + err.Error())
		os.Exit(1)
	}

	fmt.Println("Creating device certificate...")
	caBytes, err := x509.CreateCertificate(rand.Reader, deviceCert, deviceRootCa, &deviceEcdsaPubKey, rootCaPrivateKey)
	if err != nil {
		fmt.Println("Failed to create device certificate. Error: " + err.Error())
		os.Exit(1)
	}

	newDeviceCertPemBlock := CertificateBytesToPem(caBytes)
	fmt.Println("Created and signed device cert that looks like:")
	fmt.Println(string(newDeviceCertPemBlock[:]))
	fmt.Println("Saving it to file: deviceCertUnverified.crt")
	os.WriteFile("deviceCertUnverified.crt", newDeviceCertPemBlock, 0666)

	newDeviceCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		fmt.Println("Failed to parse new device ertificate from cert bytes. Error: " + err.Error())
		os.Exit(1)
	}

	fmt.Println("Successfully created device cert:")
	caPemBlockBytes := CertificateToPem(newDeviceCert)
	fmt.Println(string(caPemBlockBytes[:]))
	os.WriteFile("newDevice.crt", caPemBlockBytes, 0666)
}

// save this for tests
/*
pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
	case *dsa.PublicKey:
		fmt.Println("pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub)
	case ed25519.PublicKey:
		fmt.Println("pub is of type Ed25519:", pub)
	default:
		panic("unknown type of public key")
	}
*/
