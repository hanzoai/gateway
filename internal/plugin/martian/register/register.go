package register

import "maps"

import "sync"

const (
	// ScopeRequest modifies an HTTP request.
	ScopeRequest Scope = "request"
	// ScopeResponse modifies an HTTP response.
	ScopeResponse Scope = "response"
)

// Register is the struct containing all the martian components
type Register map[string]Component

// Scope defines the scope of the component
type Scope string

// Component contains the scope and the module factory
type Component struct {
	Scope       []Scope
	NewFromJSON func(b []byte) (any, error)
}

var (
	register = Register{}
	mutex    = &sync.RWMutex{}
)

// Set adds the received data into the register
func Set(name string, scope []Scope, f func(b []byte) (any, error)) {
	mutex.Lock()
	register[name] = Component{
		Scope:       scope,
		NewFromJSON: f,
	}
	mutex.Unlock()
}

// Get retrieves a copy of the register
func Get() Register {
	mutex.RLock()
	r := make(Register, len(register))
	maps.Copy(r, register)
	mutex.RUnlock()
	return r
}
