#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  sudo scripts/pktgen-udp64-flood.sh -i IFACE -d DST_IP [options]

Options:
  -i IFACE       Generator network interface, for example eth1
  -d DST_IP      Target IPv4 address
  -m DST_MAC     Destination Ethernet MAC. Defaults to resolved next-hop MAC
  -s SRC_IP      Source IPv4 address. Defaults to IFACE's first IPv4 address
  -p PORT        UDP destination port. Default: 12345
  -t SECONDS     Duration. Default: 30
  -q THREADS     pktgen kernel threads/queues to use. Default: 1
  -n COUNT       Packets per thread. Default: 0, meaning unlimited until duration
  -S SIZE        pktgen packet size. Default: 60 for minimum Ethernet frames
  -h             Show this help

Example:
  sudo scripts/pktgen-udp64-flood.sh -i eth1 -d 10.0.0.5 -p 12345 -t 60 -q 4

Notes:
  Run this only against machines and networks you control.
  For off-subnet targets, DST_MAC should be the gateway/next-hop MAC.
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

write_pg() {
    local file="$1"
    local value="$2"
    echo "$value" > "$file"
}

IFACE=""
DST_IP=""
DST_MAC=""
SRC_IP=""
UDP_PORT="12345"
DURATION="30"
THREADS="1"
COUNT="0"
PKT_SIZE="60"

PGSTART_PID=""
START_NS=""
STOP_NS=""
STOPPED=0
PRINTED=0

while getopts ":i:d:m:s:p:t:q:n:S:h" opt; do
    case "$opt" in
        i) IFACE="$OPTARG" ;;
        d) DST_IP="$OPTARG" ;;
        m) DST_MAC="$OPTARG" ;;
        s) SRC_IP="$OPTARG" ;;
        p) UDP_PORT="$OPTARG" ;;
        t) DURATION="$OPTARG" ;;
        q) THREADS="$OPTARG" ;;
        n) COUNT="$OPTARG" ;;
        S) PKT_SIZE="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) die "option -$OPTARG requires an argument" ;;
        \?) die "unknown option: -$OPTARG" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n "$IFACE" ]] || die "missing -i IFACE"
[[ -n "$DST_IP" ]] || die "missing -d DST_IP"
[[ -d "/sys/class/net/$IFACE" ]] || die "interface does not exist: $IFACE"

[[ "$DURATION" =~ ^[0-9]+$ ]] || die "duration must be an integer"
[[ "$THREADS" =~ ^[0-9]+$ ]] || die "threads must be an integer"
[[ "$COUNT" =~ ^[0-9]+$ ]] || die "count must be an integer"
[[ "$PKT_SIZE" =~ ^[0-9]+$ ]] || die "packet size must be an integer"
[[ "$UDP_PORT" =~ ^[0-9]+$ ]] || die "UDP port must be an integer"

[[ "$THREADS" -ge 1 ]] || die "threads must be >= 1"
[[ "$DURATION" -ge 1 ]] || die "duration must be >= 1"
[[ "$UDP_PORT" -ge 1 && "$UDP_PORT" -le 65535 ]] || die "UDP port must be 1..65535"

need_cmd ip
need_cmd awk
need_cmd modprobe
need_cmd ping
need_cmd date

if [[ -z "$SRC_IP" ]]; then
    SRC_IP="$(
        ip -4 -o addr show dev "$IFACE" scope global |
        awk 'NR == 1 { split($4, a, "/"); print a[1] }'
    )"
    [[ -n "$SRC_IP" ]] || die "could not infer source IPv4 for $IFACE; pass -s SRC_IP"
fi

if [[ -z "$DST_MAC" ]]; then
    NEXT_HOP="$(
        ip -4 route get "$DST_IP" oif "$IFACE" | awk -v dst="$DST_IP" '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i == "via") {
                        print $(i + 1)
                        exit
                    }
                }
                print dst
                exit
            }
        '
    )"

    ping -I "$IFACE" -c 1 -W 1 "$NEXT_HOP" >/dev/null 2>&1 || true

    DST_MAC="$(
        ip neigh get "$NEXT_HOP" dev "$IFACE" 2>/dev/null | awk '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i == "lladdr") {
                        print $(i + 1)
                        exit
                    }
                }
            }
        '
    )"

    if [[ -z "$DST_MAC" ]]; then
        DST_MAC="$(
            ip neigh show "$NEXT_HOP" dev "$IFACE" | awk '
                {
                    for (i = 1; i <= NF; i++) {
                        if ($i == "lladdr") {
                            print $(i + 1)
                            exit
                        }
                    }
                }
            '
        )"
    fi

    [[ "$DST_MAC" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || {
        ip route get "$DST_IP" oif "$IFACE" >&2 || true
        ip neigh show dev "$IFACE" >&2 || true
        die "could not resolve next-hop MAC for $NEXT_HOP on $IFACE; pass -m DST_MAC"
    }
fi

modprobe pktgen
[[ -d /proc/net/pktgen ]] || die "pktgen procfs is not available"

for ((thread = 0; thread < THREADS; thread++)); do
    [[ -e "/proc/net/pktgen/kpktgend_$thread" ]] || die "pktgen thread $thread is unavailable"
done

stop_pktgen() {
    if [[ "$STOPPED" -eq 0 ]]; then
        STOPPED=1
        STOP_NS="$(date +%s%N)"
        if [[ -e /proc/net/pktgen/pgctrl ]]; then
            write_pg /proc/net/pktgen/pgctrl "stop" || true
        fi
    fi
}

print_results() {
    if [[ "$PRINTED" -eq 1 ]]; then
        return
    fi
    PRINTED=1

    echo
    echo "pktgen results:"

    local total_pps=0
    local total_mbps=0

    for ((thread = 0; thread < THREADS; thread++)); do
        local dev="${IFACE}@${thread}"
        local file="/proc/net/pktgen/$dev"

        echo
        echo "== $dev =="

        if [[ ! -e "$file" ]]; then
            echo "missing pktgen device file: $file"
            continue
        fi

        awk '
            /Result:/ || /pps/ || /Mb\/sec/ || /Gb\/sec/ || /errors:/ || /flows:/ {
                print
            }
        ' "$file"

        # Try to extract pps from common pktgen output formats.
        local pps
        pps="$(
            awk '
                {
                    for (i = 1; i <= NF; i++) {
                        if ($i ~ /pps$/) {
                            x = $i
                            sub(/pps$/, "", x)
                            gsub(/[^0-9.]/, "", x)
                            if (x != "") print int(x)
                        }
                    }
                }
            ' "$file" | tail -n 1
        )"

        if [[ -n "${pps:-}" ]]; then
            total_pps=$((total_pps + pps))
        fi

        # Try to extract Mb/sec. If Gb/sec appears, convert to Mb/sec.
        local mbps
        mbps="$(
            awk '
                {
                    for (i = 1; i <= NF; i++) {
                        if ($i ~ /Mb\/sec$/) {
                            x = $i
                            sub(/Mb\/sec$/, "", x)
                            gsub(/[^0-9.]/, "", x)
                            if (x != "") print x
                        }
                        if ($i ~ /Gb\/sec$/) {
                            x = $i
                            sub(/Gb\/sec$/, "", x)
                            gsub(/[^0-9.]/, "", x)
                            if (x != "") print x * 1000
                        }
                    }
                }
            ' "$file" | tail -n 1
        )"

        if [[ -n "${mbps:-}" ]]; then
            total_mbps="$(
                awk -v a="$total_mbps" -v b="$mbps" 'BEGIN { printf "%.3f", a + b }'
            )"
        fi
    done

    echo
    echo "== total =="
    echo "total pps:  $total_pps"
    awk -v pps="$total_pps" 'BEGIN { printf "total Mpps: %.3f\n", pps / 1000000 }'
    echo "total Mbps: $total_mbps"
    awk -v mbps="$total_mbps" 'BEGIN { printf "total Gbps: %.3f\n", mbps / 1000 }'

    if [[ -n "${START_NS:-}" && -n "${STOP_NS:-}" ]]; then
        awk -v start="$START_NS" -v stop="$STOP_NS" '
            BEGIN {
                elapsed = (stop - start) / 1000000000
                if (elapsed > 0) {
                    printf "elapsed:    %.3fs\n", elapsed
                }
            }
        '
    fi
}

cleanup() {
    echo
    echo "stopping pktgen..."
    stop_pktgen

    if [[ -n "${PGSTART_PID:-}" ]]; then
        wait "$PGSTART_PID" 2>/dev/null || true
    fi

    print_results
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "configuring pktgen..."

for ((thread = 0; thread < THREADS; thread++)); do
    dev="${IFACE}@${thread}"

    write_pg "/proc/net/pktgen/kpktgend_$thread" "rem_device_all"
    write_pg "/proc/net/pktgen/kpktgend_$thread" "add_device $dev"

    pgdev="/proc/net/pktgen/$dev"
    [[ -e "$pgdev" ]] || die "pktgen device was not created: $pgdev"

    write_pg "$pgdev" "clone_skb 0"
    write_pg "$pgdev" "pkt_size $PKT_SIZE"
    write_pg "$pgdev" "count $COUNT"
    write_pg "$pgdev" "delay 0"
    write_pg "$pgdev" "flag NO_TIMESTAMP"
    write_pg "$pgdev" "flag QUEUE_MAP_CPU"

    write_pg "$pgdev" "dst_mac $DST_MAC"
    write_pg "$pgdev" "src_min $SRC_IP"
    write_pg "$pgdev" "src_max $SRC_IP"
    write_pg "$pgdev" "dst_min $DST_IP"
    write_pg "$pgdev" "dst_max $DST_IP"
    write_pg "$pgdev" "udp_dst_min $UDP_PORT"
    write_pg "$pgdev" "udp_dst_max $UDP_PORT"
done

echo
echo "pktgen UDP flood"
echo "  iface:      $IFACE"
echo "  src ip:     $SRC_IP"
echo "  dst ip:     $DST_IP"
echo "  dst mac:    $DST_MAC"
echo "  udp port:   $UDP_PORT"
echo "  pkt size:   $PKT_SIZE"
echo "  threads:    $THREADS"
echo "  count:      $COUNT"
echo "  duration:   ${DURATION}s"
echo

echo "starting pktgen..."
START_NS="$(date +%s%N)"

# Important:
# pgctrl start may block until pktgen stops. Run it in the background so
# this script can enforce the duration and still print results on Ctrl-C.
write_pg /proc/net/pktgen/pgctrl "start" &
PGSTART_PID=$!

sleep "$DURATION"

stop_pktgen

wait "$PGSTART_PID" 2>/dev/null || true
