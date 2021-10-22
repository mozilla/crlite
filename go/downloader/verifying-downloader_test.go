package downloader

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/vbauerster/mpb/v5"
)

type testIdentifier struct{}

func (ti testIdentifier) ID() string {
	return "test identifier"
}

type testVerifier struct{}

func (tv *testVerifier) IsValid(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("Empty file")
	}
	return nil
}

type testAuditor struct{}

func (ta *testAuditor) FailedDownload(issuer DownloadIdentifier, crlUrl *url.URL, dlTracer *DownloadTracer, err error) {
}
func (ta *testAuditor) FailedVerifyUrl(issuer DownloadIdentifier, crlUrl *url.URL, dlTracer *DownloadTracer, err error) {
}
func (ta *testAuditor) FailedVerifyPath(issuer DownloadIdentifier, crlUrl *url.URL, crlPath string, err error) {
}

func Test_NotFoundNotLocal(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	tmpfile, err := ioutil.TempFile("", "Test_NotFoundNotLocal")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	testUrl, _ := url.Parse(ts.URL)

	ctx := context.TODO()

	dataAtPathIsValid, err := DownloadAndVerifyFileSync(ctx, &testVerifier{}, &testAuditor{},
		&testIdentifier{}, display, *testUrl,
		tmpfile.Name(), 1, 0)

	if err == nil {
		t.Error("Expected error")
	}
	if dataAtPathIsValid {
		t.Error("Expected not dataAtPathIsValid")
	}
	if !strings.Contains(err.Error(), "Local error=Empty file, Caused by=Non-OK status: 404 Not Found") {
		t.Error(err)
	}

	_, statErr := os.Stat(fmt.Sprintf("%s.tmp", tmpfile.Name()))
	if statErr == nil {
		t.Error("tmpfile not cleaned up")
	}
}

func Test_NotFoundButIsLocal(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	tmpfile, err := ioutil.TempFile("", "Test_NotFoundButIsLocal")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())
	ioutil.WriteFile(tmpfile.Name(), []byte("Local File"), 0644)

	testUrl, _ := url.Parse(ts.URL)

	ctx := context.TODO()

	dataAtPathIsValid, err := DownloadAndVerifyFileSync(ctx, &testVerifier{}, &testAuditor{},
		&testIdentifier{}, display, *testUrl,
		tmpfile.Name(), 1, 0)

	if err == nil {
		t.Error("Expected error")
	}
	if !dataAtPathIsValid {
		t.Error("Expected dataAtPathIsValid!")
	}
	if err.Error() != "Non-OK status: 404 Not Found" {
		t.Error(err)
	}

	_, statErr := os.Stat(fmt.Sprintf("%s.tmp", tmpfile.Name()))
	if statErr == nil {
		t.Error("tmpfile not cleaned up")
	}
}

func Test_FoundRemoteButNotLocal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	tmpfile, err := ioutil.TempFile("", "Test_FoundRemoteButNotLocal")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	testUrl, _ := url.Parse(ts.URL)

	ctx := context.TODO()

	dataAtPathIsValid, err := DownloadAndVerifyFileSync(ctx, &testVerifier{}, &testAuditor{},
		&testIdentifier{}, display, *testUrl,
		tmpfile.Name(), 1, 0)

	if err != nil {
		t.Errorf("Expected no error but got %s", err)
	}
	if !dataAtPathIsValid {
		t.Error("Expected dataAtPathIsValid")
	}
	_, statErr := os.Stat(fmt.Sprintf("%s.tmp", tmpfile.Name()))
	if statErr == nil {
		t.Error("tmpfile not cleaned up")
	}
}

func Test_FoundRemoteAndAlsoLocal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	tmpfile, err := ioutil.TempFile("", "Test_FoundRemoteAndAlsoLocal")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())
	ioutil.WriteFile(tmpfile.Name(), []byte("Local File"), 0644)

	testUrl, _ := url.Parse(ts.URL)

	ctx := context.TODO()

	dataAtPathIsValid, err := DownloadAndVerifyFileSync(ctx, &testVerifier{}, &testAuditor{},
		&testIdentifier{}, display, *testUrl,
		tmpfile.Name(), 1, 0)

	if err != nil {
		t.Errorf("Expected no error but got %s", err)
	}
	if !dataAtPathIsValid {
		t.Error("Expected dataAtPathIsValid")
	}
	_, statErr := os.Stat(fmt.Sprintf("%s.tmp", tmpfile.Name()))
	if statErr == nil {
		t.Error("tmpfile not cleaned up")
	}
}
