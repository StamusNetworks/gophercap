package filter

type YAMLConfig map[string]CombinedConfig

type CombinedConfig struct {
	Conditions []FilterItem `yaml:"conditions,omitempty"`
}

type FilterItem struct {
	Kind   string   `yaml:"kind,omitempty"`
	Negate bool     `yaml:"negate,omitempty"`
	Match  []string `yaml:"match,omitempty"`
}
