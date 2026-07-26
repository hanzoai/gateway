// Gateway sets up a complete Hanzo API Gateway ready to serve.
//
// LEGACY: superseded by HIP-0110. The canonical entrypoint is main.go
// (zip+ZAP edge process). This Lura-based path remains compilable
// under the `legacy` build tag for one release cycle so operators have
// a safety net during the Phase A → Phase C rollout. After the cloud
// binary's gateway.Mount registration is removed (Phase C), this file
// will be deleted.

//go:build legacy
// +build legacy

package main

import (
	"context"
	"embed"
	"log"
	"os"
	"os/signal"
	"syscall"

	gateway "github.com/hanzoai/gateway/v2"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	cmd "github.com/hanzoai/gateway/v2/internal/plugin/cobra"
	flexibleconfig "github.com/hanzoai/gateway/v2/internal/plugin/flexibleconfig"
	koanf "github.com/hanzoai/gateway/v2/internal/plugin/koanf"
)

const (
	fcPartials  = "FC_PARTIALS"
	fcTemplates = "FC_TEMPLATES"
	fcSettings  = "FC_SETTINGS"
	fcPath      = "FC_OUT"
	fcEnable    = "FC_ENABLE"
)

//go:embed schema
var embedSchema embed.FS

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case sig := <-sigs:
			log.Println("Signal intercepted:", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	gateway.RegisterEncoders()

	for key, alias := range aliases {
		config.ExtraConfigAlias[alias] = key
	}

	var cfg config.Parser
	cfg = koanf.New()
	if os.Getenv(fcEnable) != "" {
		cfg = flexibleconfig.NewTemplateParser(flexibleconfig.Config{
			Parser:    cfg,
			Partials:  os.Getenv(fcPartials),
			Settings:  os.Getenv(fcSettings),
			Path:      os.Getenv(fcPath),
			Templates: os.Getenv(fcTemplates),
		})
	}

	var rawSchema string
	schema, err := embedSchema.ReadFile("schema/schema.json")
	if err == nil {
		rawSchema = string(schema)
	}

	commandsToLoad := []cmd.Command{
		cmd.RunCommand,
		cmd.NewCheckCmd(rawSchema),
		cmd.PluginCommand,
		cmd.VersionCommand,
		cmd.AuditCommand,
		gateway.NewTestPluginCmd(),
	}

	cmd.DefaultRoot = cmd.NewRoot(cmd.RootCommand, commandsToLoad...)
	cmd.DefaultRoot.Cmd.CompletionOptions.DisableDefaultCmd = true

	// Build the command tree eagerly so subcommands exist when rebrandCLI
	// walks them. the cobra tree's Root.Build is sync.Once-guarded, so calling
	// it here and letting Execute call it again is a no-op on the second pass.
	cmd.DefaultRoot.Build()
	rebrandCLI()

	cmd.Execute(cfg, gateway.NewExecutor(ctx))
}

var aliases = map[string]string{
	"github_com/devopsfaith/krakend/transport/http/server/handler":  "plugin/http-server",
	"github.com/devopsfaith/krakend/transport/http/client/executor": "plugin/http-client",
	"github.com/devopsfaith/krakend/proxy/plugin":                   "plugin/req-resp-modifier",
	"github.com/devopsfaith/krakend/proxy":                          "proxy",
	"github_com/luraproject/lura/router/gin":                        "router",

	"github.com/devopsfaith/krakend-httpcache":                "qos/http-cache",
	"github.com/devopsfaith/krakend-circuitbreaker/gobreaker": "qos/circuit-breaker",

	"github.com/devopsfaith/krakend-oauth2-clientcredentials": "auth/client-credentials",
	"github.com/devopsfaith/krakend-jose/validator":           "auth/validator",
	"github.com/devopsfaith/krakend-jose/signer":              "auth/signer",
	"github_com/devopsfaith/bloomfilter":                      "auth/revoker",

	"github_com/devopsfaith/krakend-botdetector": "security/bot-detector",
	"github_com/devopsfaith/krakend-httpsecure":  "security/http",
	"github_com/devopsfaith/krakend-cors":        "security/cors",

	"github.com/devopsfaith/krakend-cel":        "validation/cel",
	"github.com/devopsfaith/krakend-jsonschema": "validation/json-schema",

	"github.com/devopsfaith/krakend-amqp/agent": "async/amqp",

	"github.com/devopsfaith/krakend-amqp/consume":                  "backend/amqp/consumer",
	"github.com/devopsfaith/krakend-amqp/produce":                  "backend/amqp/producer",
	"github.com/devopsfaith/krakend-lambda":                        "backend/lambda",
	"github.com/devopsfaith/krakend-pubsub/publisher":              "backend/pubsub/publisher",
	"github.com/devopsfaith/krakend-pubsub/subscriber":             "backend/pubsub/subscriber",
	"github.com/devopsfaith/krakend/transport/http/client/graphql": "backend/graphql",
	"github.com/devopsfaith/krakend/http":                          "backend/http",

	// telemetry/gelf and telemetry/logstash are deliberately absent: logging
	// goes through hanzoai/log (internal/hanzolog) and neither the Graylog
	// sink nor the logstash text pattern is built in any more. This table is
	// the list of extra_config namespaces the gateway actually honours, so a
	// key it cannot serve does not belong in it.
	"github_com/devopsfaith/krakend-gologging":  "telemetry/logging",
	"github_com/devopsfaith/krakend-metrics":    "telemetry/metrics",
	"github_com/letgoapp/krakend-influx":        "telemetry/influx",
	"github_com/devopsfaith/krakend-opencensus": "telemetry/opencensus",

	"github.com/devopsfaith/krakend-lua/router":        "modifier/lua-endpoint",
	"github.com/devopsfaith/krakend-lua/proxy":         "modifier/lua-proxy",
	"github.com/devopsfaith/krakend-lua/proxy/backend": "modifier/lua-backend",
	"github.com/devopsfaith/krakend-martian":           "modifier/martian",
}
