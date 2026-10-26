// Command gen-fixtures writes the synthetic fixture packs to testdata/.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ares-networks/ares-verify/internal/fixtures"
)

func main() {
	out := flag.String("out", "testdata", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, v := range fixtures.Variants {
		p, err := fixtures.BuildVariant(v)
		if err == nil {
			var z []byte
			if z, err = p.Zip(); err == nil {
				err = os.WriteFile(filepath.Join(*out, v+".zip"), z, 0o644)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", v, err)
			os.Exit(1)
		}
		fmt.Println(filepath.Join(*out, v+".zip"))
	}
}
