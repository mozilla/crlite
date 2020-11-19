package config

import (
	"gopkg.in/ini.v1"
	"testing"
)

func Test_Defaults(t *testing.T) {
	var section *ini.Section

	var u uint64
	confUint64(&u, section, "var", 99)
	if u != 99 {
		t.Errorf("Expected the default of 99, got %d", u)
	}

	var i int
	confInt(&i, section, "var", -99)
	if i != -99 {
		t.Errorf("Expected the default of -99, got %d", i)
	}

	var b bool
	confBool(&b, section, "var", true)
	if b != true {
		t.Errorf("Expected default of true")
	}

	confBool(&b, section, "var", false)
	if b != false {
		t.Errorf("Expected default of false")
	}

	var s string
	confString(&s, section, "var", "hotdog")
	if s != "hotdog" {
		t.Errorf("Expected the default of hotdog, got %s", s)
	}
}

func Test_SectionOverride(t *testing.T) {
	cfg := ini.Empty()
	section, err := cfg.NewSection("new section")
	if err != nil {
		t.Error(err)
	}

	_, _ = section.NewKey("signedint", "-42")

	var i int
	confInt(&i, section, "signedint", -99)
	if i != -42 {
		t.Errorf("Expected the config value of -42, got %d", i)
	}

	_, _ = section.NewKey("booltrue", "true")

	var b bool
	confBool(&b, section, "booltrue", false)
	if b != true {
		t.Error("Expected true")
	}

	_, _ = section.NewKey("boolfalse", "false")

	confBool(&b, section, "boolfalse", true)
	if b != false {
		t.Error("Expected false")
	}

	_, _ = section.NewKey("string", "sandwich")

	var s string
	confString(&s, section, "string", "doom")
	if s != "sandwich" {
		t.Errorf("Expected the value sandwich, got %s", s)
	}

	_, _ = section.NewKey("uint64", "935939539593953")

	var u uint64
	confUint64(&u, section, "uint64", 1234567890123456789)
	if u != 935939539593953 {
		t.Errorf("Expected the value 935939539593953, got %v", u)
	}
}
