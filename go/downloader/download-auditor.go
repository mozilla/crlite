package downloader

import (
	"net/url"

	"github.com/jcjones/ct-mapreduce/storage"
)

type DownloadAuditor interface {
	FailedDownload(issuer storage.Issuer, crlUrl *url.URL, dlTracer *DownloadTracer, err error)
	FailedVerifyUrl(issuer storage.Issuer, crlUrl *url.URL, dlTracer *DownloadTracer, err error)
	FailedVerifyPath(issuer storage.Issuer, crlPath string, err error)
}
