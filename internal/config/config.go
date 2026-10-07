// Package config загружает и проверяет конфигурацию ноды gomesh.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Rendex451/gomesh/internal/crypto"
)

// maxIfaceName — IFNAMSIZ (16) минус завершающий ноль.
const maxIfaceName = 15

// ErrInsecurePermissions означает, что файл с приватным ключом
// доступен группе или всем.
var ErrInsecurePermissions = errors.New("config file is accessible by group or others")

// Config — конфигурация одной ноды.
type Config struct {
	PrivateKey crypto.PrivateKey `toml:"private_key"`
	ListenPort uint16            `toml:"listen_port"`
	TunName    string            `toml:"tun_name"`
	// TunAddress — адрес ноды на TUN с маской ВСЕГО overlay (10.99.1.1/16):
	// ядро создаст маршрут на эту подсеть через TUN.
	TunAddress netip.Prefix `toml:"tun_address"`
	// Subnet — подсеть, которую нода анонсирует остальным (10.99.1.0/24).
	Subnet netip.Prefix     `toml:"subnet"`
	Seeds  []netip.AddrPort `toml:"seeds"`
	// Peers — статические пиры для этапа 1; на этапе 3 их заменит gossip.
	Peers []Peer `toml:"peers"`
}

// Peer — статически заданный пир.
type Peer struct {
	PublicKey crypto.PublicKey `toml:"public_key"`
	Endpoint  netip.AddrPort   `toml:"endpoint"`
	Subnets   []netip.Prefix   `toml:"subnets"`
}

// Load читает и проверяет конфиг из файла.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse разбирает и проверяет конфиг из строки. Отделён от Load,
// чтобы тесты не трогали файловую систему.
func Parse(data string) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	// Опечатка в имени ключа не должна молча превращаться в пустое значение.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config:\n%w", err)
	}
	return &cfg, nil
}

// CheckPermissions возвращает ErrInsecurePermissions, если файл
// читаем группой или всеми. Это предупреждение, а не отказ в запуске.
func CheckPermissions(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %#o, want 0600", ErrInsecurePermissions, path, uint32(perm))
	}
	return nil
}

// claim — подсеть и поле конфига, в котором она объявлена.
type claim struct {
	field  string
	prefix netip.Prefix
}

// Validate проверяет конфиг целиком и возвращает все найденные
// проблемы сразу, объединённые через errors.Join.
func (c *Config) Validate() error {
	var errs []error
	add := func(field, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
	}

	var ownPub crypto.PublicKey
	if c.PrivateKey.IsZero() {
		add("private_key", "is required")
	} else if pub, err := c.PrivateKey.PublicKey(); err != nil {
		add("private_key", "%v", err)
	} else {
		ownPub = pub
	}

	if c.ListenPort == 0 {
		add("listen_port", "is required")
	}

	switch {
	case c.TunName == "":
		add("tun_name", "is required")
	case len(c.TunName) > maxIfaceName:
		add("tun_name", "%q is longer than %d bytes", c.TunName, maxIfaceName)
	}

	// Собственные адреса. overlay известен, только если tun_address корректен.
	var overlay netip.Prefix
	var claims []claim
	if !c.TunAddress.IsValid() {
		add("tun_address", "is required")
	}
	if !c.Subnet.IsValid() {
		add("subnet", "is required")
	}
	if c.TunAddress.IsValid() && c.Subnet.IsValid() {
		switch {
		case c.Subnet != c.Subnet.Masked():
			add("subnet", "%s has host bits set, did you mean %s?", c.Subnet, c.Subnet.Masked())
		case !c.Subnet.Contains(c.TunAddress.Addr()):
			add("tun_address", "%s is outside own subnet %s", c.TunAddress.Addr(), c.Subnet)
		case c.TunAddress.Bits() >= c.Subnet.Bits():
			add("tun_address", "mask /%d must be shorter than subnet /%d so that the route covers the whole overlay (e.g. %s/16)",
				c.TunAddress.Bits(), c.Subnet.Bits(), c.TunAddress.Addr())
		case c.TunAddress.Addr() == c.Subnet.Addr():
			add("tun_address", "%s is the network address of subnet %s, use a host address such as %s",
				c.TunAddress.Addr(), c.Subnet, c.Subnet.Addr().Next())
		default:
			overlay = c.TunAddress.Masked()
			claims = append(claims, claim{"subnet", c.Subnet})
		}
	}

	for i, s := range c.Seeds {
		if !s.IsValid() || s.Port() == 0 {
			add(fmt.Sprintf("seeds[%d]", i), "want ip:port with a non-zero port, got %s", s)
		}
	}

	seen := make(map[crypto.PublicKey]int, len(c.Peers))
	for i, p := range c.Peers {
		f := fmt.Sprintf("peers[%d]", i)

		switch {
		case p.PublicKey.IsZero():
			add(f+".public_key", "is required")
		case !ownPub.IsZero() && p.PublicKey == ownPub:
			add(f+".public_key", "is our own public key")
		default:
			if j, dup := seen[p.PublicKey]; dup {
				add(f+".public_key", "duplicates peers[%d]", j)
			} else {
				seen[p.PublicKey] = i
			}
		}

		if !p.Endpoint.IsValid() || p.Endpoint.Port() == 0 {
			add(f+".endpoint", "want ip:port with a non-zero port, got %s", p.Endpoint)
		}

		if len(p.Subnets) == 0 {
			add(f+".subnets", "at least one subnet is required")
		}
		for j, s := range p.Subnets {
			sf := fmt.Sprintf("%s.subnets[%d]", f, j)
			switch {
			case !s.IsValid():
				add(sf, "invalid prefix")
			case s != s.Masked():
				add(sf, "%s has host bits set, did you mean %s?", s, s.Masked())
			case overlay.IsValid() && !containsPrefix(overlay, s):
				add(sf, "%s is outside overlay %s", s, overlay)
			default:
				claims = append(claims, claim{sf, s})
			}
		}
	}

	// Подсети не должны пересекаться: иначе маршрут неоднозначен.
	for i := range claims {
		for j := i + 1; j < len(claims); j++ {
			if claims[i].prefix.Overlaps(claims[j].prefix) {
				add(claims[j].field, "%s overlaps %s (%s)",
					claims[j].prefix, claims[i].field, claims[i].prefix)
			}
		}
	}

	return errors.Join(errs...)
}

// containsPrefix сообщает, что inner целиком лежит внутри outer.
func containsPrefix(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}
