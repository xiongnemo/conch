// Command gen records a kernel release's asset checksums in kernels.json,
// using the sha256 digests GitHub publishes for release assets.
//
//	go run ./internal/kernels/gen -kernel mihomo -repo MetaCubeX/mihomo -version v1.19.32 -file internal/kernels/kernels.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"nautilus/internal/kernels"
)

func main() {
	kernel := flag.String("kernel", "mihomo", "kernel name")
	repo := flag.String("repo", "MetaCubeX/mihomo", "GitHub owner/name")
	version := flag.String("version", "", "release tag")
	file := flag.String("file", "kernels.json", "manifest to update")
	flag.Parse()
	if *version == "" {
		log.Fatal("-version is required")
	}

	m := kernels.Manifest{}
	if data, err := os.ReadFile(*file); err == nil {
		if err := json.Unmarshal(data, &m); err != nil {
			log.Fatal(err)
		}
	}

	resp, err := http.Get(fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/%s", *repo, *version))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("GitHub: %s", resp.Status)
	}
	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		log.Fatal(err)
	}

	release := &kernels.Release{Version: *version, Assets: map[string]string{}}
	for _, a := range rel.Assets {
		sum, ok := strings.CutPrefix(a.Digest, "sha256:")
		if ok && (strings.HasSuffix(a.Name, ".gz") || strings.HasSuffix(a.Name, ".zip")) {
			release.Assets[a.Name] = sum
		}
	}
	if len(release.Assets) == 0 {
		log.Fatal("release has no .gz/.zip assets with digests")
	}

	k := m[*kernel]
	if k == nil {
		k = &kernels.Kernel{Repo: *repo}
		m[*kernel] = k
	}
	k.Releases = slices.DeleteFunc(k.Releases, func(r *kernels.Release) bool { return r.Version == *version })
	k.Releases = append([]*kernels.Release{release}, k.Releases...)

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*file, append(out, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("%s %s: %d assets", *kernel, *version, len(release.Assets))
}
