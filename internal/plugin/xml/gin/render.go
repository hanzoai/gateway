package gin

import (
	"github.com/clbanning/mxj/v2"
	"github.com/gin-gonic/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
)

func init() {
	mxj.XMLEscapeChars(true)
}

// Render marshals the proxy response and passes the resulting xml to the response writer
func Render(c *gin.Context, response *proxy.Response) {
	status := c.Writer.Status()
	if response == nil {
		c.XML(status, nil)
		return
	}
	mv := mxj.Map(response.Data)
	c.Header("Content-Type", gin.MIMEXML)
	mv.XmlWriter(c.Writer)
}
