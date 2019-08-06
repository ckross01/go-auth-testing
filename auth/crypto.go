
package auth

import (
  "crypto/sha256"
  "crypto/hmac"
  "encoding/hex"
)

func sign(key []byte, msg string) []byte {
  h := hmac.New(sha256.New, []byte(key))
  h.Write([]byte(msg))
  return h.Sum(nil)
}

func sha(data string) string {
  hash := sha256.New()
  hash.Write([]byte(data))
  md := hash.Sum(nil)
  return hex.EncodeToString(md)
}

func getByteDigest(data []byte) string {
  return hex.EncodeToString(data)
}
