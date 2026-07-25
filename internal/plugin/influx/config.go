package influxdb

import (
	"errors"
	"time"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
)

type influxConfig struct {
	address    string
	username   string
	password   string
	ttl        time.Duration
	database   string
	bufferSize int
}

func configGetter(extraConfig config.ExtraConfig) (influxConfig, error) {
	cfg := influxConfig{
		ttl:      time.Minute,
		database: "krakend",
	}

	castedConfig, ok := extraConfig[Namespace].(map[string]interface{})
	if !ok {
		return cfg, ErrNoConfig
	}

	if value, ok := castedConfig["address"].(string); ok {
		cfg.address = value
	} else {
		return cfg, errNoAddress
	}

	if value, ok := castedConfig["username"].(string); ok {
		cfg.username = value
	}

	if value, ok := castedConfig["password"].(string); ok {
		cfg.password = value
	}

	if value, ok := castedConfig["buffer_size"].(int); ok {
		cfg.bufferSize = value
	}

	if value, ok := castedConfig["ttl"].(string); ok {
		ttl, err := time.ParseDuration(value)

		if err != nil {
			return cfg, err
		}

		cfg.ttl = ttl
	}

	if value, ok := castedConfig["db"].(string); ok {
		cfg.database = value
	}

	return cfg, nil
}

var ErrNoConfig = errors.New("unable to load custom config")
var errNoAddress = errors.New("address is required")
