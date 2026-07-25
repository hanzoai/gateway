package cmd

import (
	"github.com/hanzoai/gateway/v2/internal/lura/core"
	"github.com/spf13/cobra"
)

func versionFunc(cmd *cobra.Command, _ []string) {
	cmd.Println("KrakenD Version:", core.KrakendVersion)
	cmd.Println("Go Version:", core.GoVersion)
	cmd.Println("Glibc Version:", core.GlibcVersion)
}
