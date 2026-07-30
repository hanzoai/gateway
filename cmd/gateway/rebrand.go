// cmd/gateway/rebrand.go rewrites every user-visible CLI string contributed by
// the upstream cobra helper (krakend-cobra) so the built binary presents as
// hanzoai/gateway. This is the CLI-layer counterpart of the HTTP-layer rebrand
// in /rebrand.go.
//
// Scope: root command name, short/long/example strings on every subcommand,
// the help-template banner, the `version` subcommand output, and the lint
// schema URL. The strings we override are package-level vars or mutable
// fields on cobra.Command — no fork of krakend-cobra is required.
//
// LEGACY: only compiled alongside the legacy KrakenD entrypoint
// (main_legacy.go). Removed when the legacy file is removed.

//go:build legacy
// +build legacy

package main

import (
	"fmt"
	"strings"

	"github.com/hanzoai/gateway/v2/internal/lura/core"
	cmd "github.com/hanzoai/gateway/v2/internal/plugin/cobra"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cliBrandName is the user-visible binary name used in CLI help text.
const cliBrandName = "gateway"

// cliBrandLong is the user-visible long brand emitted by `version` and help.
const cliBrandLong = "hanzoai/gateway"

// cliSchemaURL replaces the upstream krakend.io schema URL for `check --lint`.
// The path template %s is substituted with the minor version by the check cmd.
const cliSchemaURL = "https://gateway.hanzo.ai/schema/v%s/gateway.json"

// rebrandCLI mutates the krakend-cobra command tree in place to strip every
// user-visible kraken reference. Must run after cmd.DefaultRoot is built but
// before cmd.Execute is called. Idempotent.
func rebrandCLI() {
	// Replace the default lint schema URL so `gateway check -l` does not hit
	// krakend.io.
	cmd.SchemaURL = cliSchemaURL

	// Root: name, short, help template (strips the KrakenD ASCII logo).
	root := cmd.DefaultRoot.Cmd
	root.Use = cliBrandName
	root.Short = fmt.Sprintf(
		"%s is a Hanzo API gateway that helps you publish, secure, control, and monitor your services",
		cliBrandLong,
	)
	root.SetHelpTemplate(
		fmt.Sprintf("%s %s\n\n", cliBrandLong, core.KrakendVersion) + defaultHelpTemplate(),
	)

	// Rewrite every subcommand's help text.
	rewriteTree(root)
}

// defaultHelpTemplate returns cobra's stock help template. We inline it so the
// rebranded banner prepends cleanly without depending on an already-modified
// HelpTemplate() return value.
func defaultHelpTemplate() string {
	return `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`
}

// rewriteTree walks every node in the cobra command tree and rewrites any
// leftover kraken references in user-visible fields.
func rewriteTree(c *cobra.Command) {
	c.Short = rebrandString(c.Short)
	c.Long = rebrandString(c.Long)
	c.Example = rebrandString(c.Example)

	// Rewrite flag usage strings too; upstream embeds "KrakenD" in several.
	c.Flags().VisitAll(func(f *pflag.Flag) {
		f.Usage = rebrandString(f.Usage)
	})
	c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Usage = rebrandString(f.Usage)
	})

	// Replace the version subcommand's Run so `gateway version` prints the
	// Hanzo brand instead of "KrakenD Version:".
	if c.Use == "version" {
		c.Run = func(cc *cobra.Command, _ []string) {
			cc.Println(cliBrandLong+" Version:", core.KrakendVersion)
			cc.Println("Go Version:", core.GoVersion)
			cc.Println("Glibc Version:", core.GlibcVersion)
		}
	}

	for _, sub := range c.Commands() {
		rewriteTree(sub)
	}
}

// rebrandString rewrites any user-visible kraken reference in s to the Hanzo
// brand. Ordering matters — longer substrings first so we do not partial-match.
func rebrandString(s string) string {
	if s == "" {
		return s
	}
	replacements := [][2]string{
		{"KrakenD", "Gateway"},
		{"Krakend", "Gateway"},
		{"krakend", cliBrandName},
		{"KRAKEND", "GATEWAY"},
	}
	for _, r := range replacements {
		s = strings.ReplaceAll(s, r[0], r[1])
	}
	return s
}
