
package auth

import (
  "fmt"
  "time"
  "strings"
  "errors"
)

const (
  awsVersion string = "AWS4"
  awsRequest string = "aws4_request"
  defaultRegion string = "us-east-1"
  defaultAlgorithm string = "AWS4-HMAC-SHA256"
)

type request struct {
  method string
  service string
  scheme string
  host string
  path string
  region string
  params string
  headers map[string]string
  body string
  requestTime time.Time
  accessKey string
  secretKey string
  url string
}

// used to validate a request. Builds ontop of a request struct type
type validation struct {
  request request
  client_signature string
  request_type string
  credential_string string
  signed_headers []string
}

type validation_return_struct struct {
  Server_genearted_canonical_request string
  Server_generated_signature string
  Server_generated_signature_key []byte
  Server_generated_string_to_sign string
  Server_expected_authorization_header string
  Server_received_body string
}

//Constructor

func newRequest(method string, url string, headers map[string]string, body string, accessKey string, secretKey string) *request {
  r := new(request)

  scheme, host, path, params := decomposeURL(url)

  r.url = url
  r.method = method
  r.service = getShortHostName(host)
  r.scheme = scheme
  r.host = host
  r.path = path
  r.region = defaultRegion
  r.params = params
  r.body = body
  r.requestTime = time.Now().UTC()
  r.headers = injectDefaultHeaders(headers, r.requestTime)
  r.accessKey = accessKey
  r.secretKey = secretKey

  return r
}

func NewValidation(method string, url string, headers map[string]string, body string) (error, *validation) {

  v := new(validation)

  // convert headers to lower case to prevent issues matching b/c of case
  lowercase_headers := make(map[string]string)
  for k,v := range headers {
    lowercase_headers[strings.ToLower(k)] = v
  }
  // if we didn't have an authorization header
  if _, ok := lowercase_headers["authorization"]; !ok {
      fmt.Println("You Must Provide an Authorization Header meetig the AWS4 specification")
      return errors.New("You Must Provide an Authorization Header meetig the AWS4 specification"), v
  }


  scheme, host, path, params := decomposeURL(url)
  v.request.method = method
  v.request.scheme = scheme
  v.request.host = host
  v.request.path = path
  v.request.params = params
  v.request.body = body
  v.request.headers = lowercase_headers
  v.request.requestTime,_ = time.Parse("20060102T150405Z", v.request.headers["x-amz-date"])
  return nil,v
}


func GetAuthHeaders(method string, url string, headers map[string]string, body string, accessKey string, secretKey string) (string, string) {
  r := newRequest(method, url, headers, body, accessKey, secretKey)
  return r.requestTime.Format("20060102T150405Z"), defaultAlgorithm + " " + "Credential=" + r.accessKey + "/" + r.getCredentialScope() + ", " + "SignedHeaders=" + r.getSignedHeaders() + ", " + "Signature=" + r.signMessage()
}

// method to construct what Authorization header should have been
func validateGetAuthHeader(v *validation) string {
  return defaultAlgorithm + " " + "Credential=" + v.request.accessKey + "/" + v.request.getCredentialScope() + ", " + "SignedHeaders=" + v.request.getSignedHeaders() + ", " + "Signature=" + v.request.signMessage()
}

func (r *request) signMessage() string {
  return getByteDigest(sign(r.getSignatureKey(), r.getStringToSign()))
}

func  (v *validation) matchSignatures(signature string) bool {
  // compare request signature to generated signature
  if signature != v.client_signature {
    return false
  }
  return true
}

func (r *request) getSignatureKey() []byte {
  signedDate := sign([]byte(awsVersion + r.secretKey), r.requestTime.Format("20060102"))
  signedRegion := sign(signedDate, r.region)
  signedService := sign(signedRegion, r.service)
  return sign(signedService, awsRequest)
}

func (r *request) getStringToSign() string {
  return defaultAlgorithm + "\n" + r.requestTime.Format("20060102T150405Z") + "\n" + r.getCredentialScope() + "\n" + sha(r.formatToCanonical())
}

func (r *request) formatToCanonical() string {
  headers := r.getHeaders()
  signedHeaders := r.getSignedHeaders()
  return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", r.method, r.path, r.params, headers, signedHeaders, sha(r.body))
}


func (r *request) getCredentialScope() string {
  return r.requestTime.Format("20060102") + "/" + defaultRegion + "/" + r.service + "/" + awsRequest
}

func (v *validation) expandCredentialString() (error) {
  split_credential_string := strings.Split(v.credential_string, "/")
  if len( split_credential_string) != 5 {
    fmt.Println("Credential String must contain the following: access_key/YYYYMMDD/region/service/aws4_request ie (Credential=asdfasdfasfasdh/20150521/us-east-1/aws4_request)")
    return errors.New("Credential String must contain the following: access_key/YYYYMMDD/region/service/aws4_request ie (Credential=asdfasdfasfasdh/20150521/us-east-1/aws4_request)")
  }
  v.request.accessKey = split_credential_string[0]
  v.request.region = split_credential_string[2]
  v.request.service = split_credential_string[3]
  v.request_type = split_credential_string[4]
  return nil
}

// populates request.headers based on signed headers
func (v *validation) populate_headers() error {

  temp_headers := make(map[string]string)
  for _, k := range v.signed_headers {
    // if header doesn't exist, throw error
    if _, ok := v.request.headers[k]; ok {
        temp_headers[k] = v.request.headers[k]
    }else{
      fmt.Println(fmt.Sprintf("Header %s was not included in request, but request says that header was signed",k))
      return errors.New(fmt.Sprintf("Header %s was not included in request, but request says that header was signed",k))
    }

  }
  v.request.headers = temp_headers

  return nil
}
