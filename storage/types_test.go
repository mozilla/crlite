package storage

import (
	"encoding/json"
	"encoding/pem"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

// issuer:ca
// subject: leadingZeros
// serialNumber: 0x00AA
//
// ... requires hacking pycert.py

const (
	kLeadingZeroes = `-----BEGIN CERTIFICATE-----
MIICozCCAYugAwIBAgICAKowDQYJKoZIhvcNAQELBQAwDTELMAkGA1UEAwwCY2Ew
IhgPMjAxNzExMjcwMDAwMDBaGA8yMDIwMDIwNTAwMDAwMFowGDEWMBQGA1UEAwwN
IGxlYWRpbmdaZXJvczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALqI
UahEjhbWQf1utogGNhA9PBPZ6uQ1SrTs9WhXbCR7wcclqODYH72xnAabbhqG8mvi
r1p1a2pkcQh6pVqnRYf3HNUknAJ+zUP8HmnQOCApk6sgw0nk27lMwmtsDu0Vgg/x
fq1pGrHTAjqLKkHup3DgDw2N/WYLK7AkkqR9uYhheZCxV5A90jvF4LhIH6g304hD
7ycW2FW3ZlqqfgKQLzp7EIAGJMwcbJetlmFbt+KWEsB1MaMMkd20yvf8rR0l0wnv
uRcOp2jhs3svIm9p47SKlWEd7ibWJZ2rkQhONsscJAQsvxaLL+Xxj5kXMbiz/kkj
+nJRxDHVA6zaGAo17Y0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGGxF47xA91w0
JvJ9kMGyiTqwtU7RaCXW+euVrFq8fFqE6+Gy+EnAQkNvzAjgHBoboodsost7xwuq
JG/LoF6qUsztYVpGHtpElghTv6XXhMCh0zaoM0PrE5oXYY75di+ltEH1DJVf0xj0
30AK23vyZ+UsNwISUyzECxA10RUSAD697vFIqW9RrJG1fM6f3l/VRBLINqOafrNB
z6brFHZzowdAKMBkog7ZQyiHEi1BqV8Vd8SKng2lQNw67RFgfB2Ltgbew2SiZMor
ylxqvBshawlL7jExLaSnMgE0RvcvSjpDguO7QO84CtH2LDGYjBABfy9ShGWTsKHi
Tqhe91GhlQ==
-----END CERTIFICATE-----`
)

func TestIssuerLazyInit(t *testing.T) {
	i := Issuer{
		id:   nil,
		spki: SPKI{[]byte{0xFF}},
	}
	if i.id != nil {
		t.Fatal("Should start with a nil id")
	}

	if i.ID() != "qBAK5qoZQNC2Y7sxzUZhQuu9vVGHExuS2TgYmHgy64k=" {
		t.Errorf("Unexpected encoding: %s", i.ID())
	}

	if i.id == nil {
		t.Error("ID should no longer be nil")
	}
}

func TestSerial(t *testing.T) {
	x := NewSerialFromHex("DEADBEEF")
	y := Serial{
		serial: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	if !reflect.DeepEqual(x, y) {
		t.Errorf("Serials should match")
	}

	if x.Cmp(y) != 0 {
		t.Errorf("Should compare the same")
	}

	if y.String() != "deadbeef" {
		t.Errorf("Wrong encoding, got: %s but expected deadbeef", y.String())
	}

	if x.String() != "deadbeef" {
		t.Errorf("Wrong encoding, got: %s but expected deadbeef", y.String())
	}
}

func TestSerialFromCertWithLeadingZeroes(t *testing.T) {
	b, _ := pem.Decode([]byte(kLeadingZeroes))

	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Error(err)
	}

	x := NewSerial(cert)
	// The Serial should be only the Value of the serialNumber field, so in this
	// case [00, AA].
	// The Stringification is the hexification, lowercase
	if x.String() != "00aa" {
		t.Errorf("Lost leading zeroes: %s != 00aa", x.String())
	}

	// The internal ID repr is base64
	if x.ID() != "AKo=" {
		t.Errorf("ID was %s but should be AKo=", x.ID())
	}
}

func TestSerialJson(t *testing.T) {
	serials := []Serial{NewSerialFromHex("ABCDEF"), NewSerialFromHex("001100")}
	data, err := json.Marshal(serials)
	if err != nil {
		t.Error(err)
	}

	var decoded []Serial
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Errorf("Decoding %s got error %v", string(data), err)
	}

	if !reflect.DeepEqual(serials, decoded) {
		t.Errorf("Should match %+v %+v", serials, decoded)
	}
}

func TestSerialBigInt(t *testing.T) {
	bint := big.NewInt(0xCAFEDEAD)
	serial := NewSerialFromBytes(bint.Bytes())
	reflex := serial.AsBigInt()
	if reflex.Cmp(bint) != 0 {
		t.Errorf("Expected %v but got %v", bint, reflex)
	}
}

func TestSerialBinaryStrings(t *testing.T) {
	serials := []Serial{
		NewSerialFromHex("ABCDEF"),
		NewSerialFromHex("001100"),
		NewSerialFromHex("ABCDEF0100101010010101010100101010"),
		NewSerialFromHex("00ABCDEF01001010101010101010010101"),
		NewSerialFromHex("FFFFFFFFFFFFFF00F00FFFFFFFFFFFFFFF"),
	}

	for _, s := range serials {
		astr := s.BinaryString()

		decoded, err := NewSerialFromBinaryString(astr)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(s, decoded) {
			t.Errorf("Expected to match %v != %v", s, decoded)
		}
	}
}

func TestSerialID(t *testing.T) {
	x := NewSerialFromHex("DEADBEEF")
	idStr := x.ID()
	decoded, err := NewSerialFromIDString(idStr)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(x, decoded) {
		t.Errorf("Should match %+v & %+v", x, decoded)
	}

	if _, err := NewSerialFromIDString("not base64"); err == nil {
		t.Error("Expected an error decoding an invalid ID string")
	}

	if x.HexString() != "deadbeef" {
		t.Errorf("Expected HexString to match %s", x.HexString())
	}
}

func TestLog(t *testing.T) {
	log := CertificateLog{
		ShortURL:       "log.example.com/2525",
		MaxEntry:       math.MaxInt64,
		LastEntryTime:  time.Date(2525, time.May, 20, 19, 21, 54, 39, time.UTC),
		LastUpdateTime: time.Date(3000, time.December, 31, 23, 55, 59, 0, time.UTC),
	}

	expectedString := "[log.example.com/2525] MaxEntry=9223372036854775807, LastEntryTime=2525-05-20 19:21:54.000000039 +0000 UTC LastUpdateTime=3000-12-31 23:55:59 +0000 UTC"
	if log.String() != expectedString {
		t.Errorf("Expecting %s but got %s", expectedString, log.String())
	}

	expectedID := "bG9nLmV4YW1wbGUuY29tLzI1MjU="
	if log.ID() != expectedID {
		t.Errorf("Expecting ID of %s but got %s", expectedID, log.ID())
	}

	// From previous version
	log = CertificateLog{
		ShortURL:      "yeti2021.ct.digicert.com/log/",
		MaxEntry:      1517184,
		LastEntryTime: time.Date(2019, time.August, 30, 05, 30, 16, 82, time.UTC),
	}

	expectedID = "eWV0aTIwMjEuY3QuZGlnaWNlcnQuY29tL2xvZy8="
	if log.ID() != expectedID {
		t.Errorf("Expecting ID of %s but got %s", expectedID, log.ID())
	}
}

func TestExpDate(t *testing.T) {
	testParsing := func(d string) ExpDate {
		expDate, err := NewExpDate(d)
		if err != nil {
			t.Error(err)
		}
		if expDate.ID() != d {
			t.Errorf("Expected ID of %s but got %s", d, expDate.ID())
		}
		return expDate
	}

	hourless := testParsing("2004-01-19")
	if !hourless.IsExpiredAt(time.Date(2004, 01, 20, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Should have been expired: %s", hourless)
	}
	if hourless.IsExpiredAt(time.Date(2004, 01, 19, 23, 59, 59, 59, time.UTC)) {
		t.Errorf("Should have been valid: %s", hourless)
	}

	fourOclock := testParsing("2004-01-19-04")
	if !fourOclock.IsExpiredAt(time.Date(2004, 01, 19, 05, 0, 0, 0, time.UTC)) {
		t.Errorf("Should have been expired: %s", fourOclock)
	}
	if fourOclock.IsExpiredAt(time.Date(2004, 01, 19, 04, 59, 59, 0, time.UTC)) {
		t.Errorf("Should have been valid: %s", fourOclock)
	}

	elevenOclock := testParsing("2004-01-19-23")
	if !elevenOclock.IsExpiredAt(time.Date(2004, 01, 19, 24, 0, 0, 0, time.UTC)) {
		t.Errorf("Should have been expired: %s", elevenOclock)
	}
	if elevenOclock.IsExpiredAt(time.Date(2004, 01, 19, 23, 59, 59, 59, time.UTC)) {
		t.Errorf("Should have been valid: %s", elevenOclock)
	}
}

func TestExpDateFromTime(t *testing.T) {
	date := time.Date(2004, 01, 20, 4, 22, 19, 44, time.UTC)
	truncDate := time.Date(2004, 01, 20, 0, 0, 0, 0, time.UTC)

	expDate := NewExpDateFromTime(date)
	if !expDate.IsExpiredAt(date) {
		t.Errorf("Should have expired at its own time")
	}

	if expDate.IsExpiredAt(truncDate.Add(-1 * time.Millisecond)) {
		t.Errorf("Should not be expired a moment earlier")
	}
}

func TestParseUniqueCertIdentifier(t *testing.T) {
	_, err := ParseUniqueCertIdentifier("a::b")
	if err == nil {
		t.Error("Should have been an error")
	}

	expected := "2019-04-28-22::an issuer::AESq_w=="
	n, err := ParseUniqueCertIdentifier(expected)
	if err != nil {
		t.Error(err)
	}

	if n.String() != expected {
		t.Errorf("Expected %s got %s", expected, n.String())
	}
}
