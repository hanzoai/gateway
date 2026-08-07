package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
)

type InterpretableDefinition struct {
	CheckExpression string `json:"check_expr"`
	ModExpression   string `json:"mod_expr"`
}

func ConfigGetter(e config.ExtraConfig) ([]InterpretableDefinition, bool) {
	var def []InterpretableDefinition

	v, ok := e[Namespace]
	if !ok {
		return def, ok
	}
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(&v); err != nil {
		return def, false
	}

	if err := json.NewDecoder(buf).Decode(&def); err != nil {
		return def, false
	}
	return def, true
}

const Namespace = "github.com/devopsfaith/krakend-cel"

var (
	ErrParsing  = errors.New("cel: error parsing the expression")
	ErrChecking = errors.New("cel: error checking the expression and its param definition")
	ErrNoExpr   = errors.New("cel: no expression")
)

type ErrorChecking struct {
	details error
}

func (e ErrorChecking) Error() string {
	return fmt.Sprintf("error parsing the expression %s", e.details.Error())
}

func NewCheckExpressionParser(l logging.Logger) Parser {
	return Parser{
		extractor: extractCheckExpr,
		l:         l,
	}
}

func NewModExpressionParser(l logging.Logger) Parser {
	return Parser{
		extractor: extractModExpr,
		l:         l,
	}
}

type Parser struct {
	extractor func(InterpretableDefinition) string
	l         logging.Logger
}

func (p Parser) Parse(definition InterpretableDefinition) (cel.Program, error) {
	expr := p.extractor(definition)
	if expr == "" {
		return nil, ErrNoExpr
	}
	p.l.Debug("[CEL]", fmt.Sprintf("Parsing expression: %v", expr))
	env, err := cel.NewEnv(defaultDeclarations())
	if err != nil {
		return nil, err
	}

	ast, iss := env.Parse(p.extractor(definition))
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("error parsing the expression %s", iss.Err())
	}
	c, iss := env.Check(ast)
	if iss != nil && iss.Err() != nil {
		return nil, ErrorChecking{details: iss.Err()}
	}

	return env.Program(c)
}

func (p Parser) ParsePre(definitions []InterpretableDefinition) ([]cel.Program, error) {
	return p.parseByKey(definitions, PreKey)
}

func (p Parser) ParsePost(definitions []InterpretableDefinition) ([]cel.Program, error) {
	return p.parseByKey(definitions, PostKey)
}

func (p Parser) ParseJWT(definitions []InterpretableDefinition) ([]cel.Program, error) {
	return p.parseByKey(definitions, JwtKey)
}

func (p Parser) parseByKey(definitions []InterpretableDefinition, key string) ([]cel.Program, error) {
	var res []cel.Program

	for _, def := range definitions {
		if !strings.Contains(p.extractor(def), key) {
			continue
		}
		v, err := p.Parse(def)
		if err != nil {
			// Including ErrorChecking — an expression naming a variable this
			// environment does not declare.
			//
			// That case used to be logged at DEBUG and `continue`d, so
			// parseByKey returned (no programs, nil error) and the caller
			// built an endpoint with an empty evaluator list: a check that
			// existed in config, reported nothing above Debug, and allowed
			// every request. One mistyped variable name was the whole
			// distance between a policy and no policy.
			p.l.Error("[CEL]", "check cannot be compiled:", err.Error())
			return res, err
		}
		res = append(res, v)
	}
	return res, nil
}

func defaultDeclarations() cel.EnvOption {
	return cel.Declarations(
		decls.NewConst(NowKey, decls.String, nil),

		decls.NewConst(PreKey+"_method", decls.String, nil),
		decls.NewConst(PreKey+"_path", decls.String, nil),
		decls.NewConst(PreKey+"_params", decls.NewMapType(decls.String, decls.String), nil),
		decls.NewConst(PreKey+"_headers", decls.NewMapType(decls.String, decls.NewListType(decls.String)), nil),
		decls.NewConst(PreKey+"_querystring", decls.NewMapType(decls.String, decls.NewListType(decls.String)), nil),
		// req_body, as a string, so a rule can match on the request payload.
		//
		// Every JSON-RPC method the edge multiplexes over ONE path lives in
		// the body — `/v1/info` carries info.isBootstrapped and info.peers
		// alike — so without this a path-based gate cannot tell them apart and
		// no policy over methods is expressible at all. Both gateway configs
		// in the estate were written against `req_body` anyway; undeclared,
		// they failed env.Check(), and ProxyFactory answered that by handing
		// back the UNGUARDED proxy. api.lux.network, api.hanzo.network and
		// api.zoo.network served info.peers — full peer list, node IDs,
		// addresses, staking port, exact luxd version — behind a rule that
		// read as if it forbade exactly that.
		decls.NewConst(PreKey+"_body", decls.String, nil),

		decls.NewConst(PostKey+"_completed", decls.Bool, nil),
		decls.NewConst(PostKey+"_metadata_status", decls.Int, nil),
		decls.NewConst(PostKey+"_metadata_headers", decls.NewMapType(decls.String, decls.NewListType(decls.String)), nil),
		decls.NewConst(PostKey+"_data", decls.NewMapType(decls.String, decls.Dyn), nil),

		decls.NewConst(JwtKey, decls.NewMapType(decls.String, decls.Dyn), nil),
	)
}

func extractCheckExpr(i InterpretableDefinition) string { return i.CheckExpression }
func extractModExpr(i InterpretableDefinition) string   { return i.ModExpression }

const (
	PreKey  = "req"
	PostKey = "resp"
	JwtKey  = "JWT"
	NowKey  = "now"
)
