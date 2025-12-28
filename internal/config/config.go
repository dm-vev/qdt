package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string, out any) error {
	if path == "" {
		return fmt.Errorf("config path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}
