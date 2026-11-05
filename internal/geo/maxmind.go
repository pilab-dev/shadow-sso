package geo

import (
	"context"
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// MaxMindResolver resolves coarse location from a MaxMind GeoIP2/GeoLite2
// city database (.mmdb) and, optionally, a separate ASN database.
type MaxMindResolver struct {
	db    *geoip2.Reader
	asnDB *geoip2.Reader
}

// NewMaxMindResolver opens a MaxMind city database at path.
func NewMaxMindResolver(path string) (*MaxMindResolver, error) {
	return NewMaxMindResolverWithASN(path, "")
}

// NewMaxMindResolverWithASN opens a city database and an optional ASN database.
func NewMaxMindResolverWithASN(cityPath, asnPath string) (*MaxMindResolver, error) {
	if cityPath == "" {
		return nil, fmt.Errorf("geoip database path is required")
	}
	db, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("open geoip database: %w", err)
	}
	r := &MaxMindResolver{db: db}
	if asnPath != "" {
		asn, err := geoip2.Open(asnPath)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("open geoip asn database: %w", err)
		}
		r.asnDB = asn
	}
	return r, nil
}

// Lookup resolves coarse location for ip.
func (r *MaxMindResolver) Lookup(ctx context.Context, ip string) (GeoInfo, error) {
	_ = ctx
	if r == nil || r.db == nil {
		return GeoInfo{}, fmt.Errorf("geoip database not open")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoInfo{}, fmt.Errorf("invalid ip")
	}
	record, err := r.db.City(parsed)
	if err != nil {
		return GeoInfo{}, err
	}
	info := GeoInfo{
		Country: record.Country.IsoCode,
		City:    record.City.Names["en"],
	}
	if len(record.Subdivisions) > 0 {
		info.Region = record.Subdivisions[0].IsoCode
		if info.Region == "" {
			info.Region = record.Subdivisions[0].Names["en"]
		}
	}
	if r.asnDB != nil {
		if asn, err := r.asnDB.ASN(parsed); err == nil && asn != nil {
			if asn.AutonomousSystemOrganization != "" {
				info.ASN = asn.AutonomousSystemOrganization
			} else if asn.AutonomousSystemNumber != 0 {
				info.ASN = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
			}
		}
	}
	return info, nil
}

// Close releases the databases.
func (r *MaxMindResolver) Close() error {
	if r == nil {
		return nil
	}
	var first error
	if r.db != nil {
		first = r.db.Close()
	}
	if r.asnDB != nil {
		if err := r.asnDB.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

var _ Resolver = (*MaxMindResolver)(nil)
