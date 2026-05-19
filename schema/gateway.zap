// gateway.zap — ZAP schema for the Gateway subsystem.
//
// HIP-0106 unified-binary contract. Gateway is the trust boundary in
// the unified cloud binary — it validates JWTs against the configured
// JWKS, strips client-supplied identity headers, and mints the
// gateway-authorized X-Org-Id / X-User-Id / X-Roles / X-User-Email /
// X-User-IsAdmin / X-Phone-Number / X-User-Permissions set per HIP-0026.

package gateway.v1;

service Health {
  // Check returns OK when the gateway middleware is wired and the
  // JWKS cache is reachable.
  Check(HealthRequest) -> HealthResponse;
}

message HealthRequest {}

message HealthResponse {
  string status = 1;       // "ok"
  bool auth_enabled = 2;   // true when AUTH_ENABLED=true
  string issuer = 3;       // JWT issuer (e.g. https://hanzo.id)
}
