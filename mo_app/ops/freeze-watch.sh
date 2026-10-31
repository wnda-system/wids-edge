#!/bin/bash
# Runs once per boot (freeze-watch.service): records how the PREVIOUS boot
# ended, so freezes are logged even though a frozen machine can't log itself.
#
#   clean   — normal shutdown/reboot (journald logged its shutdown)
#   FROZE   — log simply stops: hard freeze or power loss
#   PANIC   — kernel lockup/panic detected (auto-reboot from 90-autoreboot-on-hang.conf)
#
# Output: /var/log/freeze-watch.log (readable by the adm group)
LOG=/var/log/freeze-watch.log
J="journalctl -b -1 --no-pager -q"

$J -n 1 >/dev/null 2>&1 || exit 0          # no previous boot recorded
started=$($J -o short-iso 2>/dev/null | head -1 | awk '{print $1}')
ended=$($J -n 1 -o short-iso 2>/dev/null | awk '{print $1}')
kernel=$($J -k 2>/dev/null | grep -iE "kernel panic|soft lockup|hard lockup|hung_task|blocked for more than|watchdog: BUG|Oops" | tail -3 | sed 's/^.*kernel: //' | tr '\n' '|')
pstore=$(ls /var/lib/systemd/pstore 2>/dev/null | wc -l)

if [ -n "$kernel" ] || [ "$pstore" -gt 0 ]; then
    status=PANIC
elif $J 2>/dev/null | grep -qE "systemd-shutdown|Journal stopped|Reached target .*(Shutdown|Reboot|Power-Off)"; then
    status=clean
else
    status=FROZE
fi

rtw=$($J -k 2>/dev/null | grep -c "rtw_8821ce.*timed out")
monitor=$($J -u wifi-capture.service 2>/dev/null | grep -c "promiscuous\|started on\|resumed monitoring")
[ "$monitor" -gt 0 ] && monitor=yes || monitor=no
[ "$($J -k 2>/dev/null | grep -c 'entered promiscuous')" -gt 0 ] && monitor=yes

echo "$(date '+%F %T') previous boot ${started} -> ${ended}: ${status} | internal-wifi tx-timeouts=${rtw} | monitor-active=${monitor} | pstore-files=${pstore}${kernel:+ | kernel: ${kernel}}" >> "$LOG"
chgrp adm "$LOG" 2>/dev/null; chmod 640 "$LOG"
