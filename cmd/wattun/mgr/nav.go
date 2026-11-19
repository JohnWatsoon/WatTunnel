package mgr

import (
	"fmt"
	"time"
)

// MainMenu mirrors main_menu() key-for-key: number = tunnel page, n = new,
// a = batch actions, m = live monitor, s = settings, u = update, q = quit,
// enter = redraw. The dashboard table/actions themselves are P2 screens pulled
// through screenRegistry (dash_table, dash_actions, stale_tunnels,
// auto_migrate_all, tunnel_page).
func MainMenu() int {
	for {
		tn := len(Tunnels())
		PageFull("Tunnels", fmt.Sprintf("%d total", tn))
		if registered("auto_migrate_all") {
			dispatch("auto_migrate_all", "1")
		}
		if registered("dash_table") {
			dispatch("dash_table")
		}
		if registered("stale_tunnels") {
			if st := dispatch("stale_tunnels"); st != 0 && st != 1 {
				// stale_tunnels prints its own warning; nothing more here
				_ = st
			}
		}
		if registered("dash_actions") {
			dispatch("dash_actions")
		}
		for {
			fmt.Fprintf(Stdout, "\r%s  %s▸%s %s%s%s", EL, CYN, RST, YEL, PMSG, RST)
			PMSG = ""
			key, _, ok := KeyRead(0)
			if !ok {
				fmt.Fprintln(Stdout)
				return 0 // EOF: the bash eof_exit path
			}
			fmt.Fprintf(Stdout, "\r%s", EL)
			if !IsTTY {
				fmt.Fprintln(Stdout)
			}
			handled := true
			switch {
			case len(key) == 1 && key[0] >= '1' && key[0] <= '9':
				names := Tunnels()
				num := key
				if len(names) > 9 {
					fmt.Fprint(Stdout, key)
					rest, more := ReadLine(5 * time.Second)
					if more {
						num = key + rest
					}
				}
				if isDigits(num) {
					if n := atoi(num); n >= 1 && n <= len(names) {
						dispatch("tunnel_page", names[n-1])
						break // a valid selection always breaks the read loop
					}
				}
				Flash(fmt.Sprintf("No tunnel number %s.", num))
				handled = false
			case key == "n" || key == "N":
				dispatch("new_tunnel")
			case key == "a" || key == "A":
				dispatch("batch_actions_menu")
			case key == "m" || key == "M":
				if tn > 0 {
					runFlow("live_monitor")
				}
			case key == "s" || key == "S":
				dispatch("settings_menu")
			case key == "u" || key == "U":
				Page("Update", "")
				fmt.Fprintln(Stdout)
				if dispatch("update") == 0 {
					fmt.Fprintln(Stdout)
					Hint("The manager reloads itself to show the new version.")
					Pause()
					return reloadRC // the caller re-execs the manager binary
				}
				Pause()
			case key == "q" || key == "Q":
				CurShow()
				fmt.Fprintln(Stdout)
				return 0
			case key == "enter":
				// redraw only
			default:
				handled = false
				if tn > 0 {
					Flash(fmt.Sprintf("Unknown key '%s'. Press a tunnel's number to manage it, or n, a, m, s, u, q.", key))
				} else {
					Flash(fmt.Sprintf("Unknown key '%s'. Press n to create your first tunnel.", key))
				}
			}
			if handled {
				break
			}
		}
	}
}

// reloadRC is returned after a successful self-update: Run's caller (the main
// package) re-execs the manager binary, like the bash `exec "$MGR"`.
const reloadRC = 42
