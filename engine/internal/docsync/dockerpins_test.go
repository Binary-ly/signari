package docsync

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pinnedImage is a reference that names its content: a tag may stand beside the
// digest to say what it is, and the digest is what is pulled.
var pinnedImage = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// Every image a tracked Dockerfile builds from is pinned by digest (3.29). A tag is
// whatever its registry says it is today, and can be pointed somewhere else after a
// release was checked; a build from it is then not the build that was checked. A
// stage of the same file and `scratch` name no registry and need no pin.
func TestEveryBaseImageIsPinnedByDigest(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	seen := 0
	for _, name := range bytes.Split(out, []byte{0}) {
		path := string(name)
		base := filepath.Base(path)
		if base != "Dockerfile" && !strings.HasPrefix(base, "Dockerfile.") && !strings.HasSuffix(base, ".Dockerfile") &&
			base != "Containerfile" {
			continue
		}
		seen++
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		// Stages named so far: a FROM can build on one of the stages above it.
		stages := map[string]bool{"scratch": true}
		lines := bufio.NewScanner(bytes.NewReader(raw))
		for n := 1; lines.Scan(); n++ {
			fields := strings.Fields(lines.Text())
			if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
				continue
			}
			args := fields[1:]
			for len(args) > 0 && strings.HasPrefix(args[0], "--") {
				args = args[1:]
			}
			if len(args) == 0 {
				t.Errorf("%s:%d: a FROM with no image", path, n)
				continue
			}
			image := args[0]
			switch {
			case stages[strings.ToLower(image)]:
			case strings.Contains(image, "$"):
				t.Errorf("%s:%d: %s is chosen when the image is built, so nothing here can pin it", path, n, image)
			case !pinnedImage.MatchString(image):
				t.Errorf("%s:%d: %s is not pinned by digest; add @sha256: of the index the tag names now "+
					"(docs/deployment-artefacts.md)", path, n, image)
			}
			if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
				stages[strings.ToLower(args[2])] = true
			}
		}
	}
	if seen == 0 {
		t.Fatal("no tracked Dockerfile was found, so nothing was checked")
	}
}
