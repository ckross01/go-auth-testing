
package auth

import (
  "fmt"
  "sort"
  "time"
  "strings"
)

func (r *request) getHeaders() string {

  var sorted[]string
  for k := range r.headers {
    sorted = append(sorted, k)
  }

  sort.Strings(sorted)

  newHeaders := ""
  for _, v := range sorted {
    newHeaders += fmt.Sprintf("%s:%s\n", strings.TrimSpace(strings.ToLower(v)), strings.TrimSpace(r.headers[v]))
  }
  return newHeaders
}

func (r *request) getSignedHeaders() string {

  var sorted[]string
  for k := range r.headers {
    sorted = append(sorted, strings.ToLower(k))
  }

  sort.Strings(sorted)
  return strings.Join(sorted, ";")
}

func injectDefaultHeaders(headers map[string]string, now time.Time) map[string]string {
  headers["x-amz-date"] = now.Format("20060102T150405Z")
  headers["content-type"] = "application/json"
  return headers
}
