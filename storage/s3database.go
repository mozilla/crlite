package storage

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/certificate-transparency/go/x509"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3Database struct {
	service *s3.S3
	bucket  string
}

func NewS3Database(aPath string) (*S3Database, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Use the credentials from ~/.aws/
	svc := s3.New(sess)

	result, err := svc.ListBuckets(nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to list buckets, %v", err)
	}

	found := false
	for _, b := range result.Buckets {
		if aws.StringValue(b.Name) == aPath {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("Could not find Bucket %s", aPath)
	}

	db := &S3Database{
		service: svc,
		bucket:  aPath,
	}

	return db, nil
}

func (db *S3Database) SaveLogState(aLogObj *CertificateLog) error {
	logObjBytes, err := json.Marshal(aLogObj)
	if err != nil {
		return err
	}

	log.Printf("Saving %s", logObjBytes)

	key := fmt.Sprintf("state/%s", aLogObj.URL)

	params := &s3.PutObjectInput{
		Bucket:  aws.String(db.bucket),
		Key:     aws.String(key),
		Body: 	 bytes.NewReader(logObjBytes),
	}

	_, err = db.service.PutObject(params)
	if err != nil {
	    return err
	}

	return nil
}

func (db *S3Database) GetLogState(aUrl string) (*CertificateLog, error) {
	var certLogObj CertificateLog

	key := fmt.Sprintf("state/%s", aUrl)

	// Load an object with the key aUrl
	r, err := db.service.GetObject(&s3.GetObjectInput{
			Bucket: aws.String(db.bucket),
			Key:    aws.String(key),
	})
	if err != nil {
		// Only error here is does-not-exist, so let's pass along a fresh obj
		return &CertificateLog{ URL: aUrl }, nil
	}

	decoder := json.NewDecoder(r.Body)

	err = decoder.Decode(&certLogObj)
	if err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("More than one object to decode? There can be only one.")
	}

	return &certLogObj, nil
}

func (db *S3Database) Store(aCert *x509.Certificate) error {
	akiString := base64.URLEncoding.EncodeToString(aCert.AuthorityKeyId)
	skiString := base64.URLEncoding.EncodeToString(aCert.SubjectKeyId)

	key := fmt.Sprintf("cert/%04d/%03d/%s/%s", aCert.NotAfter.Year(), aCert.NotAfter.YearDay(), akiString, skiString)

	params := &s3.PutObjectInput{
		Bucket:  aws.String(db.bucket), // Required
		Key:     aws.String(key), // Required
		Body:    bytes.NewReader(aCert.Raw),
		Expires: &aCert.NotAfter,
		Metadata: map[string]*string{
			"AKI": aws.String(akiString),
		},
	}

	resp, err := db.service.PutObject(params)
	if err != nil {
	    // Print the error, cast err to awserr.Error to get the Code and
	    // Message from an error.
	    fmt.Println(err.Error())
	    return err
	}

	// Pretty-print the response data.
	log.Printf("Saved ski %s, got %s", skiString, resp)
	return nil
}
