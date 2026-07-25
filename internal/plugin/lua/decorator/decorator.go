package decorator

import (
	"errors"

	"github.com/hanzoai/gateway/v2/internal/pkg/binder"
)

type Decorator func(*binder.Binder)

var (
	ErrNeedsArguments   = errors.New("need arguments")
	ErrResponseExpected = errors.New("response expected")
)
