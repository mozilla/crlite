package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
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

func download(ctx context.Context, display *mpb.Progress, crlUrl url.URL, path string, timeout time.Duration) error {
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
		req.Header.Add("Content-Range", fmt.Sprintf("bytes: %d-%d/%d", offset, size, offset-size))
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var outFileParams int
	switch resp.StatusCode {
	case http.StatusPartialContent:
		// Depending on what the server responds with, we may have to go back to Create
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

	// Fpr partial content, resp.ContentLength will
	// be the partial length.
	progBar := display.AddBar(resp.ContentLength,
		mpb.PrependDecorators(
			decor.Name(crlUrl.String()),
		),
		mpb.AppendDecorators(
			decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 14}),
			decor.CountersKibiByte(" %6.1f / %6.1f"),
		),
		mpb.BarRemoveOnComplete(),
	)

	defer progBar.Abort(true)

	defer resp.Body.Close()
	reader := progBar.ProxyReader(resp.Body)

	// and copy from reader, propagating errors
	totalBytes, err := io.Copy(outFile, reader)
	if err != nil {
		return err
	}

	// Sometimes ContentLength is crazy far off.
	progBar.SetTotal(totalBytes, true)

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

func DownloadFileSync(ctx context.Context, display *mpb.Progress, crlUrl url.URL,
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
			err = download(ctx, display, crlUrl, path, timeout)
			if err == nil {
				return nil
			}
		}
		glog.Infof("Failed to download %s (%d/%d): %s", path, i, maxRetries, err)
	}
	return err
}
