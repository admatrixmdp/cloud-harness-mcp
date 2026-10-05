// Command harness-worker is the in-executor JSON tool process
// (today worker/harness-worker.mjs).
package main

import (
	"fmt"
	"os"

	"github.com/bestagentkits/cloud-harness-mcp/internal/executor"
)

func main() {
	if err := executor.HandleStdin(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
