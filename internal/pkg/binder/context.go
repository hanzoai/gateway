package binder

import "github.com/yuin/gopher-lua"

// Context function context
type Context struct {
	state  *lua.LState
	pushed int
}

// Top returns count of function arguments
func (c *Context) Top() int {
	return c.state.GetTop()
}

// Arg returns function argument by number
func (c *Context) Arg(num int) *Argument {
	return &Argument{
		state:  c.state,
		number: num,
	}
}

// Push pushes function result
func (c *Context) Push() *Push {
	return &Push{
		context: c,
	}
}

func (c *Context) increase() {
	c.pushed++
}

func (c *Context) error(e string) {
	// RaiseError is printf-style. `e` is a runtime string — it carries Lua
	// script and host error text — so passing it as the FORMAT lets any '%' in
	// a message be read as a verb, mangling the error and emitting
	// %!v(MISSING) noise from attacker-influenceable input. Pass it as an
	// argument instead. (go vet: non-constant format string.)
	c.state.RaiseError("%s", e)
}
