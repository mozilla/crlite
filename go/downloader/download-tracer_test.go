package downloader

import (
	"context"
	"net/http"
	"testing"
)

func Test_DownloadTracerBlank(t *testing.T) {
	dla := NewDownloadTracer()
	if len(dla.DNSResults()) != 0 {
		t.Error("Should have no DNS results")
	}
	if len(dla.Errors()) != 0 {
		t.Error("Should have no errors")
	}
}

func Test_SingleLookup(t *testing.T) {
	dla := NewDownloadTracer()

	ctx := dla.Configure(context.Background())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if len(dla.DNSResults()) == 0 {
		t.Error("Should have DNS results!")
	}
	if len(dla.Errors()) != 0 {
		t.Error("Should have no DNS errors!")
	}
}

func Test_SingleLookupError(t *testing.T) {
	dla := NewDownloadTracer()

	ctx := dla.Configure(context.Background())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.testing/", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err == nil || resp != nil {
		t.Fatal("Expected an error")
	}

	if len(dla.Errors()) == 0 {
		t.Error("Should have DNS errors!")
	}
	if len(dla.DNSResults()) != 0 {
		t.Error("Should have no DNS results!")
	}
}
