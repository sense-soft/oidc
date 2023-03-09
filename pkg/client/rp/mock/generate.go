package mock

//go:generate mockgen -package mock -destination ./verifier.mock.go github.com/sense-soft/oidc/pkg/rp Verifier
