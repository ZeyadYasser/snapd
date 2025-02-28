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

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/osutil/inotify"
	"golang.org/x/sys/unix"
)

func init() {
	// Reflect root dir updates for testing.
	dirs.AddRootDirCallback(func(s string) {
		udevRulesRunDir = filepath.Join(s, "/run/udev/rules.d")
		slotDeviceDir = filepath.Join(s, "/dev/snap/gpio-chardev")
	})
}

var aggregatorLockPath = "/sys/bus/platform/drivers/gpio-aggregator"

func lockAggregator() (unlocker func(), err error) {
	flock, err := osutil.OpenExistingLockForReading(aggregatorLockPath)
	if err != nil {
		return nil, err
	}
	if err := flock.Lock(); err != nil {
		return nil, err
	}
	return func() {
		flock.Close()
	}, nil
}

const aggregatorCreationTimeout = 120 * time.Second

func addAggregatedChip(sourceChip GPIOChardev, commaSeparatedLines string) (chip GPIOChardev, err error) {
	// Synchronize gpio helpers' access to the aggregator interface.
	unlocker, err := lockAggregator()
	if err != nil {
		return nil, err
	}
	defer unlocker()

	f, err := os.OpenFile("/sys/bus/platform/drivers/gpio-aggregator/new_device", os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	watcher, err := inotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = watcher.AddWatch("/dev", inotify.InCreate)
	if err != nil {
		return nil, err
	}

	// <label> <lines>
	cmd := fmt.Sprintf("%s %s", sourceChip.Label(), commaSeparatedLines)
	if _, err = f.WriteString(cmd); err != nil {
		return nil, err
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), aggregatorCreationTimeout)
	defer cancel()
	for {
		select {
		case event := <-watcher.Event:
			path := event.Name
			if strings.HasPrefix(path, "/dev/gpiochip") {
				return getChipInfo(path)
			}
		case <-ctxWithTimeout.Done():
			return nil, fmt.Errorf("max timeout passed")
		}
	}
}

func removeAggregatedChip(aggregatedChip GPIOChardev) error {
	// Synchronize gpio helpers' access to the aggregator interface.
	unlocker, err := lockAggregator()
	if err != nil {
		return err
	}
	defer unlocker()

	f, err := os.OpenFile("/sys/bus/platform/drivers/gpio-aggregator/delete_device", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(aggregatedChip.Label()); err != nil {
		return err
	}

	return nil
}

var udevRulesRunDir = "/run/udev/rules.d"

func aggregatedChipUdevRulePath(gadget, slot string) string {
	fname := fmt.Sprintf("69-snap.%s.interface.gpio-chardev-%s.rules", gadget, slot)
	return filepath.Join(udevRulesRunDir, fname)
}

func addEphermalUdevTaggingRule(chip GPIOChardev, gadget, slot string) error {
	if err := os.MkdirAll(udevRulesRunDir, 0755); err != nil {
		return err
	}

	tag := fmt.Sprintf("snap_%s_interface_gpio_chardev_%s", gadget, slot)
	rule := fmt.Sprintf("SUBSYSTEM==\"gpio\", KERNEL==\"%s\", TAG+=\"%s\"\n", chip.Name(), tag)

	path := aggregatedChipUdevRulePath(gadget, slot)
	if err := os.WriteFile(path, []byte(rule), 0644); err != nil {
		return err
	}

	// Make sure the rule we just dropped is loaded as sometimes it doesn't get
	// picked up right away.
	output, err := exec.Command("udevadm", "control", "--reload-rules").CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot reload udev rules: %s\nudev output:\n%s", err, string(output))
	}
	// Trigger the tagging rule.
	output, err = exec.Command("udevadm", "trigger", "--name-match", chip.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s\nudev output:\n%s", err, string(output))
	}

	return nil
}

func removeEphermalUdevTaggingRule(gadget, slot string) error {
	path := aggregatedChipUdevRulePath(gadget, slot)
	return os.Remove(path)
}

var slotDeviceDir = "/dev/snap/gpio-chardev"

func slotDevicePath(gadget, slot string) string {
	return filepath.Join(slotDeviceDir, gadget, slot)
}

func addGadgetSlotDevice(chip GPIOChardev, gadget, slot string) error {
	stat := &unix.Stat_t{}
	if err := unix.Stat(chip.Path(), stat); err != nil {
		return err
	}

	devPath := slotDevicePath(gadget, slot)
	if err := os.MkdirAll(filepath.Dir(devPath), 0755); err != nil {
		return err
	}
	if err := unix.Mknod(devPath, stat.Mode, int(stat.Rdev)); err != nil {
		return err
	}

	return nil
}

func removeGadgetSlotDevice(gadget, slot string) (aggregatedChip GPIOChardev, err error) {
	devPath := slotDevicePath(gadget, slot)
	aggregatedChip, err = getChipInfo(devPath)
	if err != nil {
		return nil, err
	}

	if err := os.Remove(devPath); err != nil {
		return nil, err
	}

	return aggregatedChip, nil
}

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

// TODO: share lines validation logic with gpio-chardev interface
func validateLines(chip GPIOChardev, linesArg string) error {
	tokens := strings.Split(linesArg, ",")

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

	for line := range lines {
		if line < 0 || uint(line) >= chip.NumLines() {
			return fmt.Errorf("invalid line offset %d", line)
		}
	}

	return nil
}
