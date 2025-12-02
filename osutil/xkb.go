package osutil

import (
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/snapcore/snapd/dbusutil"
)

func isNoServiceOrUnknownPropertyDbusErr(err error) bool {
	derr, ok := err.(dbus.Error)
	if !ok {
		return false
	}
	switch derr.Name {
	case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.UnknownProperty":
		return true
	}
	return false
}

type LocaleXKBConfig struct {
	Model   string
	Layout  string
	Variant string
	Options string
}

func (config *LocaleXKBConfig) KernelCommandLineArgValue() string {
	layout := strings.Split(config.Layout, ",")[0]
	model := strings.Split(config.Model, ",")[0]
	variant := strings.Split(config.Variant, ",")[0]
	return fmt.Sprintf("%s,%s,%s,%s", layout, model, variant, config.Options)
}

func SystemLocaleXKBConfig() (*LocaleXKBConfig, error) {
	conn, err := dbusutil.SystemBus()
	if err != nil {
		return nil, err
	}

	obj := conn.Object("org.freedesktop.locale1", "/org/freedesktop/locale1")
	properties := []string{"X11Layout", "X11Model", "X11Variant", "X11Options"}
	vals := make(map[string]string, 4)
	for _, property := range properties {
		dbusVal, err := obj.GetProperty(fmt.Sprintf("org.freedesktop.locale1.%s", property))
		if err != nil {
			if isNoServiceOrUnknownPropertyDbusErr(err) {
				return nil, err
			}
			return nil, err
		}

		val, ok := dbusVal.Value().(string)
		if !ok {
			return nil, fmt.Errorf("internal error: expected type string, found %T", dbusVal.Value())
		}
		vals[property] = val
	}

	// XXX: Fallback to parsing /etc/default/keyboard if we fail to obtain
	// values over dbus?

	config := &LocaleXKBConfig{
		Layout:  vals["X11Layout"],
		Model:   vals["X11Model"],
		Variant: vals["X11Variant"],
		Options: vals["X11Options"],
	}
	return config, nil
}
