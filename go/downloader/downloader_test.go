package downloader

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vbauerster/mpb/v4"
)

func Test_DownloadNotFound(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	tmpfile, err := ioutil.TempFile("", "Test_DownloadNotFound")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(display, *url, tmpfile.Name())
	if err.Error() != "Non-OK status: 404 Not Found" {
		t.Error(err)
	}
}

func Test_DownloadOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	tmpfile, err := ioutil.TempFile("", "Test_DownloadNotFound")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(display, *url, tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	content, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if string(content) != "Hello, client\n" {
		t.Logf("File contents: %s", content)
		t.Error("File contents not correct")
	}
}

func Test_DownloadResumeNotSupported(t *testing.T) {
	testcontent := []byte("download resume not supported test file's content\n")

	// Prepare a partially-downloaded file
	alreadydownloaded := testcontent[:4]
	downloadedfile, err := ioutil.TempFile("", "Test_DownloadResumeNotSupported.down")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(downloadedfile.Name())

	if _, err := downloadedfile.Write(alreadydownloaded); err != nil {
		t.Fatal(err)
	}
	if err := downloadedfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Server always returns the whole file
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(testcontent)
	}))
	defer ts.Close()

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(display, *url, downloadedfile.Name())
	if err != nil {
		t.Error(err)
	}

	// Check results
	content, err := ioutil.ReadFile(downloadedfile.Name())
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(content, testcontent) == false {
		t.Logf("File contents: %s", string(content))
		t.Error("File contents not appended")
	}
}

func Test_DownloadResume(t *testing.T) {
	testcontent := []byte("download resume test file's content\n")

	dir, err := ioutil.TempDir("", "Test_DownloadResume")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Dir: %s", dir)
	defer os.RemoveAll(dir)

	err = ioutil.WriteFile(filepath.Join(dir, "Test_DownloadNotFound.file"), testcontent, 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Start the server
	ts := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer ts.Close()

	// Prepare a partially-downloaded file
	alreadydownloaded := testcontent[:4]
	downloadedfile, err := ioutil.TempFile("", "Test_DownloadNotFound.down")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(downloadedfile.Name())

	if _, err := downloadedfile.Write(alreadydownloaded); err != nil {
		t.Fatal(err)
	}
	if err := downloadedfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Download
	url, _ := url.Parse(ts.URL)
	url.Path = "Test_DownloadNotFound.file"

	display := mpb.New(
		mpb.WithOutput(ioutil.Discard),
	)

	err = DownloadFileSync(display, *url, downloadedfile.Name())
	if err != nil {
		t.Error(err)
	}

	// Check result
	content, err := ioutil.ReadFile(downloadedfile.Name())
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(content, testcontent) == false {
		t.Logf("File contents: %s", string(content))
		t.Error("File contents not appended")
	}
}

func Test_GetSizeAndDateOfFile(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "Test_GetSizeAndDateOfFile")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	size, date, err := GetSizeAndDateOfFile(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if size != 0 {
		t.Error("Size should be 0")
	}

	if time.Since(date) > time.Second {
		t.Error("Timestamp more than a second ago")
	}

	// Check that dates shift
	earlyDate := time.Now().AddDate(-1, 0, 0)
	_ = os.Chtimes(tmpfile.Name(), earlyDate, earlyDate)

	size, date, err = GetSizeAndDateOfFile(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if size != 0 {
		t.Error("Size should still be 0")
	}

	if earlyDate.Sub(date) > time.Second {
		t.Error("Timestamp more than a second off")
	}

	// Make it non-zero bytes, resetting the date
	err = ioutil.WriteFile(tmpfile.Name(), []byte("ten bytes\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	size, date, err = GetSizeAndDateOfFile(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if size != 10 {
		t.Errorf("Size should be 10: %d", size)
	}

	if time.Since(date) > time.Second {
		t.Error("Timestamp more than a second ago")
	}
}
