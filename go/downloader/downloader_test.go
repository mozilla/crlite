package downloader

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func Test_DownloadNotFound(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", "Test_DownloadNotFound")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(context.TODO(), *url, tmpfile.Name(), 3, 0)
	if err.Error() != "Non-OK status: 404 Not Found" {
		t.Error(err)
	}
}

func Test_DownloadOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", "Test_DownloadNotFound")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(context.TODO(), *url, tmpfile.Name(), 1, 0)
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

type SingleFailureHandler struct {
	mu         sync.Mutex // guards failedOnce
	failedOnce bool
	t          *testing.T
}

func (h *SingleFailureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failedOnce {
		h.failedOnce = true
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "failure")
		return
	}
	fmt.Fprintln(w, "Hello, client")
}

func Test_DownloadFailureWithoutRetry(t *testing.T) {
	ts := httptest.NewServer(http.Handler(&SingleFailureHandler{t: t}))
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", "Test_DownloadFailureWithoutRetry")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(context.TODO(), *url, tmpfile.Name(), 0, 0)
	if err == nil {
		t.Error("Should have failed")
	}
}

func Test_DownloadFailureWithRetry(t *testing.T) {
	ts := httptest.NewServer(http.Handler(&SingleFailureHandler{t: t}))
	defer ts.Close()

	tmpfile, err := ioutil.TempFile("", "Test_DownloadFailureWithRetry")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(context.TODO(), *url, tmpfile.Name(), 1, 0)
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

	url, _ := url.Parse(ts.URL)

	err = DownloadFileSync(context.TODO(), *url, downloadedfile.Name(), 1, 0)
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

	err = DownloadFileSync(context.TODO(), *url, downloadedfile.Name(), 1, 0)
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

// rangeServingHandler serves a fixed body, honoring a "Range: bytes=N-" request
// with a 206 response. It records the Range header it saw and how many body
// bytes it sent, so a test can tell a real resume from a full re-download.
func rangeServingHandler(body []byte, sent *int, sawRange *string) http.Handler {
	lastModified := time.Unix(1_000_000, 0).UTC().Format(http.TimeFormat)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Last-Modified", lastModified)

		start := 0
		if r.Method == http.MethodGet {
			*sawRange = r.Header.Get("Range")
			if n, ok := strings.CutPrefix(*sawRange, "bytes="); ok {
				first, _, _ := strings.Cut(n, "-")
				parsed, err := strconv.Atoi(first)
				if err != nil {
					http.Error(w, "bad Range", http.StatusBadRequest)
					return
				}
				start = parsed
			}
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(body)-start))
		if r.Method != http.MethodGet {
			// A HEAD response carries the headers only.
			return
		}
		if start > 0 {
			w.Header().Set("Content-Range",
				fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
			w.WriteHeader(http.StatusPartialContent)
		}
		n, err := w.Write(body[start:])
		if err != nil {
			return
		}
		*sent += n
	})
}

// A resume has to be a real range request: the server must be asked for the
// bytes after the local copy, and only those bytes may be transferred.
func Test_DownloadResumeHonorsRange(t *testing.T) {
	testcontent := []byte("download resume test file's content\n")

	dir, err := ioutil.TempDir("", "Test_DownloadResumeHonorsRange")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	alreadyDownloaded := testcontent[:4]

	var bytesSent int
	var sawRange string
	ts := httptest.NewServer(rangeServingHandler(testcontent, &bytesSent, &sawRange))
	defer ts.Close()

	downloadedFile := filepath.Join(dir, "partial.crl")
	if err := ioutil.WriteFile(downloadedFile, alreadyDownloaded, 0o644); err != nil {
		t.Fatal(err)
	}

	crlURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if err := DownloadFileSync(context.TODO(), *crlURL, downloadedFile, 1, 0); err != nil {
		t.Fatal(err)
	}

	if want := fmt.Sprintf("bytes=%d-", len(alreadyDownloaded)); sawRange != want {
		t.Errorf("Range header: got %q, want %q", sawRange, want)
	}

	if want := len(testcontent) - len(alreadyDownloaded); bytesSent != want {
		t.Errorf("transferred %d body bytes, want %d (a full re-download moves %d)",
			bytesSent, want, len(testcontent))
	}

	content, err := ioutil.ReadFile(downloadedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, testcontent) {
		t.Errorf("file content: got %q, want %q", content, testcontent)
	}
}

// Partial content that does not start where the local copy ends cannot be
// appended: doing so would corrupt the file.
func Test_DownloadResumeRejectsMisalignedPartialContent(t *testing.T) {
	testcontent := []byte("download resume test file's content\n")

	dir, err := ioutil.TempDir("", "Test_DownloadResumeRejectsMisaligned")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	lastModified := time.Unix(1_000_000, 0).UTC().Format(http.TimeFormat)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Last-Modified", lastModified)
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(testcontent)))
			return
		}
		// Claim to resume from the start of the file, not from the local copy's end.
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(testcontent)-1, len(testcontent)))
		w.WriteHeader(http.StatusPartialContent)
		if _, err := w.Write(testcontent); err != nil {
			return
		}
	}))
	defer ts.Close()

	downloadedFile := filepath.Join(dir, "partial.crl")
	if err := ioutil.WriteFile(downloadedFile, testcontent[:4], 0o644); err != nil {
		t.Fatal(err)
	}

	crlURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if err := DownloadFileSync(context.TODO(), *crlURL, downloadedFile, 0, 0); err == nil {
		t.Fatal("expected an error for misaligned partial content")
	}
}

func Test_ContentRangeStart(t *testing.T) {
	for _, tc := range []struct {
		header  string
		want    int64
		wantErr bool
	}{
		{"bytes 0-99/100", 0, false},
		{"bytes 4-99/100", 4, false},
		{"bytes 4-4/*", 4, false},
		{"", 0, true},
		{"items 0-99/100", 0, true},
		{"bytes 4/100", 0, true},
		{"bytes four-99/100", 0, true},
	} {
		got, err := contentRangeStart(tc.header)
		if tc.wantErr {
			if err == nil {
				t.Errorf("contentRangeStart(%q) = %d, want an error", tc.header, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("contentRangeStart(%q): %v", tc.header, err)
		} else if got != tc.want {
			t.Errorf("contentRangeStart(%q) = %d, want %d", tc.header, got, tc.want)
		}
	}
}
