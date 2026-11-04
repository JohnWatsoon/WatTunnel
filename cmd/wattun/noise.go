package main

// W7/F13 (3.3.0): command-line parsing for the two opt-in traffic-shaping knobs.
//
//	-shape-data PCT          -> wat.Config.ShapeData (fraction; 0 = off)
//	-noise MODE              -> off|low|med|custom -> wat.Config.NoiseBps
//	-noise-bps BYTES/S       -> the budget for -noise custom (64..1000000)
//	-noise-window HH:MM-HH:MM -> wat.Config.NoiseFrom/NoiseTo (local-clock minutes; empty = all day)
//
// Everything is validated at startup: a typo must not silently disable shaping or send noise around the clock.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	noiseLowBps     = 128  // bytes/s: about one small filler packet every second or two
	noiseMedBps     = 1024 // bytes/s: a light continuous trickle
	noiseMinBps     = 64
	noiseMaxBps     = 1_000_000
	shapeDataMaxPct = 25.0 // hard cap on the padding overhead
)

// shapeDataPct validates -shape-data (percent of the stream bytes sent) and returns the fraction wat.Config takes.
func shapeDataPct(pct float64) (float64, error) {
	// M12: NaN/Inf pass every range comparison (all comparisons with NaN are false), so reject them explicitly.
	if math.IsNaN(pct) || math.IsInf(pct, 0) || pct < 0 || pct > shapeDataMaxPct {
		return 0, fmt.Errorf("-shape-data must be 0 (off) .. %g percent, got %g", shapeDataMaxPct, pct)
	}
	return pct / 100, nil
}

// noiseBudget maps -noise/-noise-bps to a bytes/second budget; 0 = off.
func noiseBudget(mode string, bps int) (float64, error) {
	switch mode {
	case "", "off":
		if bps != 0 {
			return 0, fmt.Errorf("-noise-bps is only for -noise custom, got -noise %q", mode)
		}
		return 0, nil
	case "low":
		if bps != 0 {
			return 0, fmt.Errorf("-noise-bps is only for -noise custom, got -noise %q", mode)
		}
		return noiseLowBps, nil
	case "med":
		if bps != 0 {
			return 0, fmt.Errorf("-noise-bps is only for -noise custom, got -noise %q", mode)
		}
		return noiseMedBps, nil
	case "custom":
		if bps < noiseMinBps || bps > noiseMaxBps {
			return 0, fmt.Errorf("-noise custom needs -noise-bps between %d and %d, got %d", noiseMinBps, noiseMaxBps, bps)
		}
		return float64(bps), nil
	}
	return 0, fmt.Errorf("-noise must be off|low|med|custom, got %q", mode)
}

// parseNoiseWindow parses -noise-window "HH:MM-HH:MM" (local clock) into minute-of-day bounds. "" means all day; the
// window may wrap past midnight (22:00-06:00) and an end of 00:00 means midnight.
func parseNoiseWindow(s string) (from, to int, err error) {
	if strings.TrimSpace(s) == "" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf(`-noise-window wants "HH:MM-HH:MM", got %q`, s)
	}
	if from, err = parseClock(a); err != nil {
		return 0, 0, fmt.Errorf("-noise-window: %v", err)
	}
	if to, err = parseClock(b); err != nil {
		return 0, 0, fmt.Errorf("-noise-window: %v", err)
	}
	if from == to {
		return 0, 0, fmt.Errorf("-noise-window start and end are the same (%q); leave the flag empty to send noise all day", s)
	}
	return from, to, nil
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("want HH:MM, got %q", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || len(h) < 1 || len(h) > 2 || len(m) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("bad time %q (want HH:MM, 00:00-23:59)", s)
	}
	return hh*60 + mm, nil
}
