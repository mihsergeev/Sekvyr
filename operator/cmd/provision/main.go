// sekvyr-provision prepares reviewed offline files. It does not install, fetch,
// commit, discover trust or contact a cluster. Paths are never echoed on errors.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mihsergeev/Sekvyr/operator/internal/provision"
)

func run(args []string, stdout io.Writer) error {
	if len(args) == 1 && args[0] == "version" {
		_, err := fmt.Fprintln(stdout, provision.Version)
		return err
	}
	if len(args) < 1 {
		return provision.ErrInvalid
	}
	flags := flag.NewFlagSet("sekvyr-provision", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	work := flags.String("work-dir", "", "Existing private 0700 directory (Linux)")
	input := flags.String("input", "", "Relative secure reviewed JSON input")
	output := flags.String("output", "", "New relative exclusive output directory")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *work == "" || *input == "" || *output == "" {
		return provision.ErrInvalid
	}
	receipt, err := provision.Run(context.Background(), args[0], *work, *input, *output, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(receipt)
}
func main() {
	if run(os.Args[1:], os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "ProvisionFailed")
		os.Exit(1)
	}
}
