package schema

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func bytesReader(b []byte) io.Reader    { return bytes.NewReader(b) }
func ptr[T any](v T) *T                 { return &v }
func fp64() string                      { return strings.Repeat("a", 64) }
