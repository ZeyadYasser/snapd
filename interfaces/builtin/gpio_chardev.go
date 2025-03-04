// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/snapcore/snapd/features"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/kmod"
	"github.com/snapcore/snapd/interfaces/systemd"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/snap"
)

// TODO: Snapd should validate the correctness of slot declarations
// (i.e. lines across slots are unique) when installing the gadget
// snap e.g. when validating snap.yaml

// https://docs.kernel.org/userspace-api/gpio/chardev.html
// https://docs.kernel.org/admin-guide/gpio/gpio-aggregator.html
const gpioChardevSummary = `allows access to specific GPIO chardev lines`

const gpioChardevBaseDeclarationPlugs = `
  gpio-chardev:
    allow-installation: false
    deny-auto-connection: true
`

// TODO: Remove app snap type from slot allow-installation
const gpioChardevBaseDeclarationSlots = `
  gpio-chardev:
    allow-installation:
      slot-snap-type:
        - app
        - gadget
    deny-auto-connection: true
`

// XXX: What should be the limit on max range.
const maxLinesCount = 65536

func parseLineToken(lineToken string) ([]uint64, error) {
	if !strings.Contains(lineToken, "-") {
		line, err := strconv.ParseUint(lineToken, 10, 32)
		if err != nil {
			return nil, err
		}
		return []uint64{line}, nil
	}
	// Parse line range e.g. 2-5
	tokens := strings.SplitN(lineToken, "-", 2)
	if len(tokens) != 2 {
		return nil, fmt.Errorf("invalid line range %q", lineToken)
	}
	first, err := strconv.ParseUint(tokens[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid line range %q: %w", lineToken, err)
	}
	last, err := strconv.ParseUint(tokens[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid line range %q: %w", lineToken, err)
	}
	if last <= first {
		return nil, fmt.Errorf("invalid line range %q: range end has to be larger than range start", lineToken)
	}
	if last-first+1 > maxLinesCount {
		return nil, fmt.Errorf("invalid line range %q: range size cannot be more than %d", lineToken, maxLinesCount)
	}
	lines := make([]uint64, 0, last-first+1)
	for i := first; i <= last; i++ {
		lines = append(lines, i)
	}
	return lines, nil
}

func validateLines(linesAttr string) error {
	tokens := strings.Split(linesAttr, ",")

	lines := make(map[uint64]bool, len(tokens))
	for _, token := range tokens {
		tokenLines, err := parseLineToken(token)
		if err != nil {
			return err
		}
		for _, line := range tokenLines {
			if _, exists := lines[line]; exists {
				return fmt.Errorf(`duplicate line found "%d"`, line)
			}
			lines[line] = true
		}
	}

	return nil
}

type gpioChardevInterface struct {
	commonInterface
}

// BeforePrepareSlot checks validity of the defined slot.
func (iface *gpioChardevInterface) BeforePrepareSlot(slot *snap.SlotInfo) error {
	var sourceChip []string
	// "source-chip" attribute is mandatory.
	if err := slot.Attr("source-chip", &sourceChip); err != nil {
		return err
	}

	var lines string
	// "lines" attribute is mandatory.
	if err := slot.Attr("lines", &lines); err != nil {
		return err
	}
	if err := validateLines(lines); err != nil {
		return fmt.Errorf(`invalid "lines" attribute: %w`, err)
	}

	return nil
}

func (iface *gpioChardevInterface) BeforeConnectSlot(slot *interfaces.ConnectedSlot) error {
	if !features.GPIOChardevInterface.IsEnabled() {
		_, flag := features.GPIOChardevInterface.ConfigOption()
		return fmt.Errorf("gpio-chardev interface requires the %q flag to be set", flag)
	}
	return nil
}

func (iface *gpioChardevInterface) SystemdConnectedSlot(spec *systemd.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	var sourceChip []string
	if err := slot.Attr("source-chip", &sourceChip); err != nil {
		return err
	}
	var lines string
	if err := slot.Attr("lines", &lines); err != nil {
		return err
	}
	snapName := slot.Snap().InstanceName()
	slotName := slot.Name()

	serviceSuffix := fmt.Sprintf("gpio-chardev-%s", slotName)
	service := &systemd.Service{
		Type:            "oneshot",
		RemainAfterExit: true,
		ExecStart:       fmt.Sprintf("/usr/lib/snapd/snap-gpio-helper export-chardev %q %q %q %q", strings.Join(sourceChip, ","), lines, snapName, slotName),
		ExecStop:        fmt.Sprintf("/usr/lib/snapd/snap-gpio-helper unexport-chardev %q %q %q %q", strings.Join(sourceChip, ","), lines, snapName, slotName),
		WantedBy:        "snapd.gpio-chardev-setup.target",
		Before:          "snapd.gpio-chardev-setup.target",
	}
	return spec.AddService(serviceSuffix, service)
}

// KModConnectedSlot make sure gpio-aggregator module is loaded.
func (iface *gpioChardevInterface) KModConnectedSlot(spec *kmod.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	return spec.AddModule("gpio-aggregator")
}

func (iface *gpioChardevInterface) AppArmorConnectedPlug(spec *apparmor.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	slotSnapName := slot.Snap().InstanceName()
	plugSnapName := plug.Snap().InstanceName()
	// TODO: Share path with snap-gpio-helper
	snippet := "# Allow access to exported gpio chardev lines"
	snippet += fmt.Sprintf("/dev/snap/gpio-chardev/%s/%s rwk,\n", slotSnapName, slot.Name())
	snippet += fmt.Sprintf("/dev/snap/gpio-chardev/%s/ r,\n", plugSnapName)
	snippet += fmt.Sprintf("/dev/snap/gpio-chardev/%s/* r,", plugSnapName)
	spec.AddSnippet(snippet)

	return nil
}

func (iface *gpioChardevInterface) UDevConnectedPlug(spec *udev.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	// TODO: Share tag with snap-gpio-helper
	spec.TagDevice(fmt.Sprintf(`TAG=="snap_%s_interface_gpio_chardev_%s"`, slot.Snap().InstanceName(), slot.Name()))
	return nil
}

func (iface *gpioChardevInterface) SystemdConnectedPlug(spec *systemd.Specification, plug *interfaces.ConnectedPlug, slot *interfaces.ConnectedSlot) error {
	slotName := slot.Name()
	slotSnapName := slot.Snap().InstanceName()
	plugName := slot.Name()
	plugSnapName := plug.Snap().InstanceName()

	// TODO: Share path with snap-gpio-helper
	target := fmt.Sprintf("/dev/snap/gpio-chardev/%s/%s", slotSnapName, slotName)
	symlink := fmt.Sprintf("/dev/snap/gpio-chardev/%s/%s", plugSnapName, plugName)

	serviceSuffix := fmt.Sprintf("gpio-chardev-%s", plugName)
	service := &systemd.Service{
		Type:            "oneshot",
		RemainAfterExit: true,
		ExecStart:       fmt.Sprintf("/bin/sh -c 'mkdir -p %q && ln -s %q %q'", filepath.Dir(symlink), target, symlink),
		ExecStop:        fmt.Sprintf("/bin/sh -c 'rm -f %q'", symlink),
		WantedBy:        "snapd.gpio-chardev-setup.target",
		Before:          "snapd.gpio-chardev-setup.target",
	}
	return spec.AddService(serviceSuffix, service)
}

func init() {
	registerIface(&gpioChardevInterface{
		commonInterface{
			name:                 "gpio-chardev",
			summary:              gpioChardevSummary,
			baseDeclarationPlugs: gpioChardevBaseDeclarationPlugs,
			baseDeclarationSlots: gpioChardevBaseDeclarationSlots,
		},
	})
}
