# capJS-node
based on https://github.com/s77rt/capJS  
made for embedded systems (lowjs) and works well with node too

## Features
 - PCAP and PCAPNG Support
 - GZIP compressed files Support
 - Basic filters (select best, auth or not, etc...)
 - HCXDUMPTOOL Support
 - AP-LESS Passwords Feature

## Usage
```
Usage:
node capjs-node.js capture_file best_only export_unauthenticated ignore_ts ignore_ie debug
low "" capjs-node.js "capture_file best_only export_unauthenticated ignore_ts ignore_ie debug"

capture_file: string
best_only: bool
export_unauthenticated: bool
ignore_ts: bool
ignore_ie: bool
debug: bool

Examples:
node capjs-node.js capture.cap true false false false false
low "" capjs-node.js "capture.cap true false false false false"
```

## Contribute
If you are having issues with capJS-node or having any feature requests, feel free to open issues in the [capJS-node Github issues page](https://github.com/s77rt/capJS-node/issues/) as necessary.
