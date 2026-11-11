package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

type DownloadAction int

const (
	Create   DownloadAction = 0
	Resume   DownloadAction = 1
	UpToDate DownloadAction = 2
)

func GetSizeAndDateOfFile(path string) (int64, time.Time, error) {
	curFile, err := os.Open(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	stat, err := curFile.Stat()
	if err != nil {
		return 0, time.Time{}, err
	}
	curFile.Close()

	return stat.Size(), stat.ModTime(), nil
}

func determineAction(client *http.Client, crlUrl url.URL, path string) (DownloadAction, int64, int64) {
	szOnDisk, localDate, err := GetSizeAndDateOfFile(path)
	if err != nil {
		glog.V(1).Infof("[%s] CREATE: File not on disk: %s ", crlUrl.String(), err)
		return Create, 0, 0
	}
	req, err := http.NewRequest("HEAD", crlUrl.String(), nil)
	if err != nil {
		return Create, szOnDisk, 0
	}
	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/crlite")

	resp, err := client.Do(req)
	if err != nil {
		return Create, szOnDisk, 0
	}

	eTag := resp.Header.Get("Etag")
	lastMod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		glog.V(1).Infof("[%s] CREATE: Invalid last-modified: %s [%s]", crlUrl.String(), err, resp.Header.Get("Last-Modified"))
		return Create, szOnDisk, 0
	}
	szOnServer, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		glog.V(1).Infof("[%s] CREATE: No content length: %s [%s]", crlUrl.String(), err, resp.Header.Get("Content-Length"))
		return Create, szOnDisk, 0
	}

	if localDate.Before(lastMod) {
		glog.V(1).Infof("[%s] CREATE: Local Date is before last modified header date, assuming out-of-date", crlUrl.String())
		return Create, szOnDisk, szOnServer
	}

	if szOnServer == szOnDisk {
		glog.V(1).Infof("[%s] UP TO DATE", crlUrl.String())
		return UpToDate, szOnDisk, szOnServer
	}

	if szOnServer > szOnDisk {
		if resp.Header.Get("Accept-Ranges") == "bytes" {
			glog.V(1).Infof("[%s] RESUME: { Already on disk: %d %s, Last-Modified: %s, Etag: %s, Length: %d }", crlUrl.String(), szOnDisk, localDate.String(), lastMod.String(), eTag, szOnServer)
			return Resume, szOnDisk, szOnServer
		}

		glog.V(1).Infof("[%s] Accept-Ranges not supported, unable to resume", crlUrl.String())
	}

	glog.V(1).Infof("[%s] CREATE: Fallthrough", crlUrl.String())
	return Create, szOnDisk, szOnServer
}

// contentRangeStart returns the first byte position of a 206 response's
// Content-Range header, for example 4 for "bytes 4-99/100".
func contentRangeStart(header string) (int64, error) {
	malformed := fmt.Errorf("malformed Content-Range header %q", header)
	rest, ok := strings.CutPrefix(header, "bytes ")
	if !ok {
		return 0, malformed
	}
	first, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, malformed
	}
	start, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	if err != nil {
		return 0, malformed
	}
	return start, nil
}

func download(ctx context.Context, crlUrl url.URL, path string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}

	action, offset, size := determineAction(client, crlUrl, path)

	if action == UpToDate {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", crlUrl.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-Automated-Tool", "https://github.com/mozilla/crlite")
	if action == Resume {
		// Ask for the bytes that are not on disk yet. `Content-Range` is a
		// response header; a range request is a `Range` header.
		req.Header.Add("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var outFileParams int
	switch resp.StatusCode {
	case http.StatusPartialContent:
		// The bytes are appended to what is already on disk, so the server has
		// to start exactly where the local copy ends. A server that starts
		// anywhere else, or that omits `Content-Range`, would silently corrupt
		// the file; fail instead.
		start, err := contentRangeStart(resp.Header.Get("Content-Range"))
		if err != nil {
			return err
		}
		if start != offset {
			return fmt.Errorf("Partial content starts at byte %d, expected %d", start, offset)
		}
		outFileParams = os.O_APPEND | os.O_WRONLY
		action = Resume
		glog.V(1).Infof("[%s] Successfully resumed download at offset %d", crlUrl.String(), offset)
	case http.StatusOK:
		outFileParams = os.O_TRUNC | os.O_CREATE | os.O_WRONLY
		action = Create
	default:
		return fmt.Errorf("Non-OK status: %s", resp.Status)
	}

	outFile, err := os.OpenFile(path, outFileParams, 0644)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// and copy from reader, propagating errors
	totalBytes, err := io.Copy(outFile, resp.Body)
	if err != nil {
		return err
	}

	if action == Create && size != 0 && totalBytes != size {
		glog.Warningf("[%s] Didn't seem to download the right number of bytes, expected=%d got %d",
			crlUrl.String(), size, totalBytes)
	}

	if action == Resume && size != 0 && totalBytes+offset != size {
		glog.Warningf("[%s] Didn't seem to download the right number of bytes, expected=%d got %d with %d already local",
			crlUrl.String(), size, totalBytes, offset)
	}

	lastModStr := resp.Header.Get("Last-Modified")
	// http.TimeFormat is 29 characters
	if len(lastModStr) < 16 {
		glog.Infof("[%s] No compliant reported last-modified time, file may expire early: [%s]", crlUrl.String(), lastModStr)
		return nil
	}

	lastMod, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil {
		glog.Warningf("[%s] Couldn't parse modified time: %s [%s]", crlUrl.String(), err, lastModStr)
		return nil
	}

	if err := os.Chtimes(path, lastMod, lastMod); err != nil {
		glog.Warningf("Couldn't set modified time: %s", err)
	}
	return nil
}

func DownloadFileSync(ctx context.Context, crlUrl url.URL,
	path string, maxRetries uint, timeout time.Duration) error {
	glog.V(1).Infof("Downloading %s from %s", path, crlUrl.String())

	var err error
	var i uint

	for ; i <= maxRetries; i++ {
		select {
		case <-ctx.Done():
			glog.Infof("Signal caught, stopping threads at next opportunity.")
			return nil
		default:
			err = download(ctx, crlUrl, path, timeout)
			if err == nil {
				return nil
			}
		}
		glog.Infof("Failed to download %s (%d/%d): %s", path, i, maxRetries, err)
	}
	return err
}
