package downloader

import (
	"context"
	"net/http/httptrace"

	"github.com/golang/glog"
)

type DownloadTracer struct {
	DNSDone []httptrace.DNSDoneInfo
}

func NewDownloadTracer() *DownloadTracer {
	return &DownloadTracer{
		DNSDone: []httptrace.DNSDoneInfo{},
	}
}

func (da *DownloadTracer) dnsDone(ddi httptrace.DNSDoneInfo) {
	glog.V(1).Infof("DNS result: %+v", ddi)
	da.DNSDone = append(da.DNSDone, ddi)
}

func (da *DownloadTracer) Configure(ctx context.Context) context.Context {
	traceObj := &httptrace.ClientTrace{
		DNSDone: da.dnsDone,
	}

	return httptrace.WithClientTrace(ctx, traceObj)
}

func (da *DownloadTracer) DNSResults() []string {
	results := []string{}
	for _, ddi := range da.DNSDone {
		for _, addr := range ddi.Addrs {
			results = append(results, addr.String())
		}
	}
	return results
}

func (da *DownloadTracer) Errors() []string {
	results := []string{}
	for _, ddi := range da.DNSDone {
		if ddi.Err != nil {
			results = append(results, ddi.Err.Error())
		}
	}
	return results
}
