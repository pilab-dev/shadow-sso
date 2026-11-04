package geo

import "context"

// GeoInfo is coarse location data derived from an IP address.
type GeoInfo struct {
	Country string
	Region  string
	City    string
	ASN     string
}

// Resolver looks up coarse location for an IP address.
type Resolver interface {
	Lookup(ctx context.Context, ip string) (GeoInfo, error)
}

// NoopResolver returns empty location for every IP.
type NoopResolver struct{}

func (NoopResolver) Lookup(ctx context.Context, ip string) (GeoInfo, error) {
	return GeoInfo{}, nil
}

// StaticResolver is used in tests.
type StaticResolver struct {
	Info GeoInfo
	Err  error
}

func (s StaticResolver) Lookup(ctx context.Context, ip string) (GeoInfo, error) {
	if s.Err != nil {
		return GeoInfo{}, s.Err
	}
	return s.Info, nil
}
