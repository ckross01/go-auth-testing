
package auth

import (
  "net/url"
  "strings"
)

func decomposeURL(requestUrl string) (string, string, string, string) {
  if urlInfo, err := url.Parse(requestUrl); err != nil {
    panic("Not able to parse url")
  } else {
    return urlInfo.Scheme, urlInfo.Host, urlInfo.Path, urlInfo.RawQuery
  }
}

func getShortHostName(host string) string {
  return strings.Split(host, ".")[0]
}
