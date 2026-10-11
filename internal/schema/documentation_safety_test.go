package schema

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestOperationalRunbooksContainNoConcreteIdentityValues(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..")
	paths := []string{"docs/signing.md", "docs/appcontrol.md"}
	uuid := regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	email := regexp.MustCompile(`(?i)\b[[:alnum:]._%+-]+@[[:alnum:].-]+\.[a-z]{2,}\b`)
	endpointID := regexp.MustCompile(`(?i)\b(?:device|client|endpoint)\s+[0-9]+(?:[/,][0-9]+)*\b|\b(?:lt|pc|ws)[0-9]{3,}\b`)
	for _, relative := range paths {
		data, err := os.ReadFile(filepath.Join(repositoryRoot, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if uuid.MatchString(text) {
			t.Errorf("%s contains a concrete GUID", relative)
		}
		if email.MatchString(text) {
			t.Errorf("%s contains a concrete email identity", relative)
		}
		if endpointID.MatchString(text) {
			t.Errorf("%s contains a concrete endpoint identifier", relative)
		}
	}
}
