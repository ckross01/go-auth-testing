package api

import (
	"../auth"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const (
	empty  string = ""
	zero   int    = 0
)

var (
	accessKey string = os.Getenv("HD_ACCESS_KEY")
	secretKey string = os.Getenv("HD_SECRET_KEY")
)

type request struct {
	method  string
	url     string
	headers map[string]string
	body    string
	req     *http.Request
}

func init() {
	if accessKey == "" && secretKey == "" {
		panic("The access key or secret key is not set in the environment.")
	}
}

func GetHmac(url string) (int, string) {
	headers := make(map[string]string)
	r := newRequest("GET", url, headers, "")
	return r.makeHmacRequest()
}

func PostHmac(url string, body string) (int, string) {
	headers := make(map[string]string)
	r := newRequest("POST", url, headers, body)
	return r.makeHmacRequest()
}

func Get(url string) (int, string) {
	headers := make(map[string]string)
	r := newRequest("GET", url, headers, "")
	return r.makeRequest()
}

func Post(url string, body string) (int, string) {
	headers := make(map[string]string)
	r := newRequest("POST", url, headers, body)
	return r.makeRequest()
}

//Methods

func newRequest(method string, url string, headers map[string]string, body string) *request {
	r := new(request)
	r.method = method
	r.url = url
	r.headers = headers
	r.body = body
	req, err := http.NewRequest(method, url, bytes.NewBufferString(body))
	if r.req = req; err != nil {
		log.Fatalf("http."+method+" for url "+url+" => %v", err.Error())
		return nil
	}
	return r
}

func (r *request) makeRequest() (int, string) {

	client := &http.Client{}

	if resp, err := client.Do(r.req); err != nil {
		log.Fatalf("http."+r.method+" => %v", err.Error())
		return zero, empty
	} else {
		defer resp.Body.Close()
		if json, err := ioutil.ReadAll(resp.Body); err != nil {
			log.Fatalf("Could not read body from response => %v", err.Error())
			return zero, empty
		} else {
			return resp.StatusCode, string(json)
		}
	}
}

func (r *request) makeHmacRequest() (int, string) {

	client := &http.Client{}
	r.addHmacHeaders()

	if resp, err := client.Do(r.req); err != nil {
		log.Fatalf("http."+r.method+" => %v", err.Error())
		return zero, empty
	} else {
		defer resp.Body.Close()
		if json, err := ioutil.ReadAll(resp.Body); err != nil {
			log.Fatalf("Could not read body from response => %v", err.Error())
			return zero, empty
		} else {
			return resp.StatusCode, string(json)
		}
	}
}

func (r request) addHmacHeaders() {
	amzDate, authorization := auth.GetAuthHeaders(r.method, r.url, r.headers, string(r.body), accessKey, secretKey)
	r.req.Header.Add("X-Amz-Date", amzDate)
	r.req.Header.Add("Authorization", authorization)
	r.req.Header.Add("Content-Type", "application/json")
}

func get(url string, path string) string {
	fmt.Println("Get call to " + url + path)
	if resp, err := http.Get(url + path); err != nil {
		log.Fatalf("http.Get => %v", err.Error())
		return empty
	} else {
		defer resp.Body.Close()
		if json, err := ioutil.ReadAll(resp.Body); err != nil {
			log.Fatalf("Could not read body from response => %v", err.Error())
			return empty
		} else {
			return string(json)
		}
	}
}
