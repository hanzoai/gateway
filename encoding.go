//go:build legacy
// +build legacy

package gateway

import (
	rss "github.com/hanzoai/gateway/v2/internal/plugin/rss"
	xml "github.com/hanzoai/gateway/v2/internal/plugin/xml"
	ginxml "github.com/hanzoai/gateway/v2/internal/plugin/xml/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/router/gin"
)

// RegisterEncoders registers all the available encoders
func RegisterEncoders() {
	xml.Register()
	rss.Register()

	gin.RegisterRender(xml.Name, ginxml.Render)
}
