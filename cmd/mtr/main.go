package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/WinMTR/WinMTR-Official/internal/output"
	"github.com/WinMTR/WinMTR-Official/internal/trace"
)

// version is the build version. Overridden at link time via
// -ldflags "-X main.version=...". Keep as a var (not const) so ldflags works.
var version = "0.1.0"

func usage(out *os.File) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, " mtr [options] hostname")
	fmt.Fprintln(out)
	fmt.Fprintln(out, " -F, --filename FILE              read hostname(s) from a file")
	fmt.Fprintln(out, " -4                               use IPv4 only")
	fmt.Fprintln(out, " -6                               use IPv6 only")
	fmt.Fprintln(out, " -u, --udp                        use UDP instead of ICMP echo")
	fmt.Fprintln(out, " -T, --tcp                        use TCP instead of ICMP echo")
	fmt.Fprintln(out, " -I, --interface NAME             use named network interface")
	fmt.Fprintln(out, " -a, --address ADDRESS            bind the outgoing socket to ADDRESS")
	fmt.Fprintln(out, " -f, --first-ttl NUMBER           set what TTL to start")
	fmt.Fprintln(out, " -m, --max-ttl NUMBER             maximum number of hops")
	fmt.Fprintln(out, " -D, --due-ttl NUMBER             set what TTL must be reached")
	fmt.Fprintln(out, " -U, --max-unknown NUMBER         maximum unknown host")
	fmt.Fprintln(out, " -E, --max-display-path NUMBER    maximum number of ECMP paths to display")
	fmt.Fprintln(out, " -P, --port PORT                  target port number for TCP, SCTP, or UDP")
	fmt.Fprintln(out, " -L, --localport LOCALPORT        source port number for UDP")
	fmt.Fprintln(out, " -s, --psize PACKETSIZE           set the packet size used for probing")
	fmt.Fprintln(out, " -B, --bitpattern NUMBER          set bit pattern to use in payload")
	fmt.Fprintln(out, " -i, --interval SECONDS           ICMP echo request interval")
	fmt.Fprintln(out, " -G, --gracetime SECONDS          number of seconds to wait for responses")
	fmt.Fprintln(out, " -Q, --tos NUMBER                 type of service field in IP header")
	fmt.Fprintln(out, " -e, --mpls                       display information from ICMP extensions")
	fmt.Fprintln(out, " -Z, --timeout SECONDS            seconds to keep probe sockets open")
	fmt.Fprintln(out, " -M, --mark MARK                  mark each sent packet")
	fmt.Fprintln(out, " -r, --report                     output using report mode")
	fmt.Fprintln(out, " -w, --report-wide                output wide report")
	fmt.Fprintln(out, " -c, --report-cycles COUNT        set the number of pings sent")
	fmt.Fprintln(out, " -j, --json                       output json")
	fmt.Fprintln(out, " -x, --xml                        output xml")
	fmt.Fprintln(out, " -C, --csv                        output comma separated values")
	fmt.Fprintln(out, " -l, --raw                        output raw format")
	fmt.Fprintln(out, " -p, --split                      split output")
	fmt.Fprintln(out, " -t, --curses                     use curses terminal interface")
	fmt.Fprintln(out, "     --displaymode MODE           select initial display mode")
	fmt.Fprintln(out, " -n, --no-dns                     do not resolve host names")
	fmt.Fprintln(out, " -b, --show-ips                   show IP numbers and host names")
	fmt.Fprintln(out, " -o, --order FIELDS               select output fields")
	fmt.Fprintln(out, " -y, --ipinfo NUMBER              select IP information in output")
	fmt.Fprintln(out, " -z, --aslookup                   display AS number")
	fmt.Fprintln(out, " -h, --help                       display this help and exit")
	fmt.Fprintln(out, " -v, --version                    output version information and exit")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "See the 'man 8 mtr' for details.")
	if out == os.Stderr {
		os.Exit(1)
	}
	os.Exit(0)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "mtr: "+format+"\n", args...)
	os.Exit(1)
}

// parseArgs parses the given argument slice into cfg, returning any positional
// (non-flag) arguments (hostnames). It operates solely on the provided slice
// and does not touch os.Args.
func parseArgs(cfg *trace.Config, args []string) []string {
	var hostnames []string
	i := 0
	for i < len(args) {
		arg := args[i]

		// Positional argument (hostname).
		if !strings.HasPrefix(arg, "-") {
			hostnames = append(hostnames, arg)
			i++
			continue
		}

		// Consume the next arg as value for flags that need it.
		needVal := func() string {
			if i+1 >= len(args) {
				fatalf("option %s requires an argument", arg)
			}
			i++
			return args[i]
		}

		// Handle --long=value style.
		longName := arg
		longVal := ""
		hasLongVal := false
		if strings.HasPrefix(arg, "--") {
			if eqIdx := strings.IndexByte(arg, '='); eqIdx >= 0 {
				longName = arg[:eqIdx]
				longVal = arg[eqIdx+1:]
				hasLongVal = true
			}
		}
		longNeedVal := func() string {
			if hasLongVal {
				return longVal
			}
			return needVal()
		}
		longParseInt := func() int {
			s := longNeedVal()
			v, err := strconv.Atoi(s)
			if err != nil {
				fatalf("invalid argument: %s", s)
			}
			return v
		}
		longParseFloat := func() float64 {
			s := longNeedVal()
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				fatalf("invalid argument: %s", s)
			}
			return v
		}

		switch longName {
		case "-h", "--help":
			usage(os.Stdout)
		case "-v", "--version":
			fmt.Printf("mtr %s\n", version)
			os.Exit(0)

		case "-4", "--inet":
			cfg.AF = 4
		case "-6", "--inet6":
			cfg.AF = 6

		case "-F", "--filename":
			cfg.FilenameHosts = longNeedVal()
		case "-r", "--report":
			cfg.Display = trace.DisplayReport
		case "-w", "--report-wide":
			cfg.ReportWide = true
			cfg.Display = trace.DisplayReport
		case "-t", "--curses":
			cfg.Display = trace.DisplayCurses
		case "-l", "--raw":
			cfg.Display = trace.DisplayRaw
		case "-C", "--csv":
			cfg.Display = trace.DisplayCSV
		case "-j", "--json":
			cfg.Display = trace.DisplayJSON
		case "-x", "--xml":
			cfg.Display = trace.DisplayXML
		case "-p", "--split":
			cfg.Display = trace.DisplaySplit
		case "--displaymode":
			cfg.DisplayModeN = longParseInt()

		case "-c", "--report-cycles":
			cfg.MaxPing = longParseInt()
			cfg.ForceMaxPing = true
			if cfg.MaxPing < 1 {
				fatalf("report cycles must be at least 1")
			}
			if cfg.MaxPing > 1000000 {
				fatalf("report cycles must not exceed 1000000")
			}
		case "-s", "--psize":
			ps := longParseInt()
			if abs(ps) < trace.MinPacket || abs(ps) > trace.MaxPacket {
				fatalf("value out of range (%d - %d)", trace.MinPacket, trace.MaxPacket)
			}
			cfg.PacketSize = ps
		case "-I", "--interface":
			cfg.InterfaceName = longNeedVal()
		case "-a", "--address":
			cfg.InterfaceAddress = longNeedVal()
		case "-e", "--mpls":
			cfg.EnableMPLS = true
		case "-n", "--no-dns":
			cfg.DNS = false
		case "-i", "--interval":
			cfg.WaitTime = longParseFloat()
			if cfg.WaitTime < 0.001 {
				fatalf("interval must be at least 0.001 seconds")
			}
		case "-f", "--first-ttl":
			cfg.FstTTL = longParseInt()
			if cfg.FstTTL < 1 {
				cfg.FstTTL = 1
			}
		case "-m", "--max-ttl":
			cfg.MaxTTL = longParseInt()
			if cfg.MaxTTL > trace.MaxHost-1 {
				cfg.MaxTTL = trace.MaxHost - 1
			}
			if cfg.MaxTTL < 1 {
				cfg.MaxTTL = 1
			}
		case "-D", "--due-ttl":
			cfg.DueTTL = longParseInt()
			if cfg.DueTTL > trace.MaxHost-1 {
				cfg.DueTTL = trace.MaxHost - 1
			}
			if cfg.DueTTL <= 0 {
				fatalf("due TTL must be greater than 0")
			}
		case "-U", "--max-unknown":
			cfg.MaxUnknown = longParseInt()
			if cfg.MaxUnknown < 1 {
				cfg.MaxUnknown = 1
			}
		case "-E", "--max-display-path":
			cfg.MaxDisplayPath = longParseInt()
			if cfg.MaxDisplayPath > trace.MaxPath {
				cfg.MaxDisplayPath = trace.MaxPath
			}
		case "-o", "--order":
			val := longNeedVal()
			if len(val) > trace.MaxFld {
				fatalf("Too many fields: %s", val)
			}
			avail := trace.AvailableOptions()
			for _, c := range val {
				if !strings.ContainsRune(avail, c) {
					fatalf("Unknown field identifier: %c", c)
				}
			}
			cfg.FldActive = val
		case "-B", "--bitpattern":
			cfg.BitPattern = longParseInt()
			if cfg.BitPattern > 255 {
				cfg.BitPattern = -1
			}
		case "-G", "--gracetime":
			cfg.GraceTime = longParseFloat()
			if cfg.GraceTime <= 0.0 {
				fatalf("wait time must be positive")
			}
		case "-Q", "--tos":
			cfg.TOS = longParseInt()
			if cfg.TOS > 255 || cfg.TOS < 0 {
				cfg.TOS = 0
			}
		case "-u", "--udp":
			if cfg.Protocol != trace.ProtoICMP {
				fatalf("-u, -T and -S are mutually exclusive")
			}
			cfg.Protocol = trace.ProtoUDP
		case "-T", "--tcp":
			if cfg.Protocol != trace.ProtoICMP {
				fatalf("-u, -T and -S are mutually exclusive")
			}
			if cfg.RemotePort == 0 {
				cfg.RemotePort = 80
			}
			cfg.Protocol = trace.ProtoTCP
		case "-b", "--show-ips":
			cfg.ShowIPs = true
		case "-P", "--port":
			cfg.RemotePort = longParseInt()
			if cfg.RemotePort < 1 || cfg.RemotePort > trace.MaxPort {
				fatalf("Illegal port number: %d", cfg.RemotePort)
			}
		case "-L", "--localport":
			cfg.LocalPort = longParseInt()
			if cfg.LocalPort < trace.MinPort || cfg.LocalPort > trace.MaxPort {
				fatalf("Illegal port number: %d", cfg.LocalPort)
			}
		case "-Z", "--timeout":
			v := longParseInt()
			if v < 0 || v > 3600 {
				fatalf("timeout must be between 0 and 3600 seconds")
			}
			cfg.ProbeTimeout = v * 1000000
		case "-M", "--mark":
			v := longParseInt()
			cfg.Mark = uint32(v)
		case "-y", "--ipinfo":
			cfg.IPInfoNo = longParseInt()
			if cfg.IPInfoNo < 0 || cfg.IPInfoNo > 4 {
				fatalf("value %d out of range (0 - 4)", cfg.IPInfoNo)
			}
		case "-z", "--aslookup":
			cfg.IPInfoNo = 0

		default:
			// Handle combined short flags: -wzbc 50 means -w -z -b -c 50
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2 {
				expanded, consumed := expandShortFlags(arg[1:], args[i+1:])
				// Replace current position with expanded flags, skipping consumed remaining args.
				rest := args[i+1+consumed:]
				args = append(args[:i], append(expanded, rest...)...)
				continue // re-parse from same position
			}
			fmt.Fprintf(os.Stderr, "mtr: unknown option: %s\n", arg)
			usage(os.Stderr)
		}
		i++
	}
	return hostnames
}

func parseEnvOptions(cfg *trace.Config, opts string) {
	fields := strings.Fields(opts)
	if len(fields) == 0 {
		return
	}
	parseArgs(cfg, fields)
}

func main() {
	cfg := trace.DefaultConfig()

	// Parse env options first (like real mtr).
	if envOpts := os.Getenv("MTR_OPTIONS"); envOpts != "" {
		parseEnvOptions(cfg, envOpts)
	}

	// Then parse command-line args.
	hostnames := parseArgs(cfg, os.Args[1:])
	cfg.Hostnames = append(cfg.Hostnames, hostnames...)

	// Validate TTL relationships.
	if cfg.FstTTL > cfg.MaxTTL {
		fatalf("firstTTL(%d) cannot be larger than maxTTL(%d)", cfg.FstTTL, cfg.MaxTTL)
	}
	if cfg.DueTTL > 0 && cfg.DueTTL < cfg.FstTTL {
		fatalf("dueTTL(%d) cannot be less than firstTTL(%d)", cfg.DueTTL, cfg.FstTTL)
	}
	if cfg.DueTTL > cfg.MaxTTL {
		fatalf("dueTTL(%d) cannot be larger than maxTTL(%d)", cfg.DueTTL, cfg.MaxTTL)
	}

	// Set Interactive=false for non-interactive modes.
	switch cfg.Display {
	case trace.DisplayReport, trace.DisplayTXT, trace.DisplayJSON,
		trace.DisplayXML, trace.DisplayRaw, trace.DisplayCSV:
		cfg.Interactive = false
	}

	// Read hostnames from file if specified.
	if cfg.FilenameHosts != "" {
		names, err := readHostsFile(cfg.FilenameHosts)
		if err != nil {
			fatalf("open %s: %v", cfg.FilenameHosts, err)
		}
		cfg.Hostnames = append(cfg.Hostnames, names...)
	}

	// Default to localhost if no hostname given.
	if len(cfg.Hostnames) == 0 {
		cfg.Hostnames = []string{"localhost"}
	}

	// Get local hostname.
	cfg.LocalHostname, _ = os.Hostname()
	if cfg.LocalHostname == "" {
		cfg.LocalHostname = "UNKNOWNHOST"
	}

	// Set up a signal-aware context so Ctrl-C cancels the trace.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Run trace for each target.
	exitVal := 0
	for _, hostname := range cfg.Hostnames {
		cfg.Hostname = hostname

		// Resolve hostname.
		addr, err := resolveHostname(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mtr: Failed to resolve host: %s: %v\n", hostname, err)
			if cfg.Interactive {
				os.Exit(1)
			}
			exitVal = 1
			continue
		}
		cfg.RemoteAddr = addr

		// Create and run trace engine.
		engine := trace.NewEngine(cfg)
		engine.Run(ctx)

		// Output results.
		hops := engine.Snapshots()
		maxHop := engine.MaxHop()

		switch cfg.Display {
		case trace.DisplayReport:
			output.Report(os.Stdout, cfg, hops, maxHop)
		case trace.DisplayCSV:
			output.CSV(os.Stdout, cfg, hops, maxHop)
		case trace.DisplayJSON:
			output.JSON(os.Stdout, cfg, hops, maxHop)
		case trace.DisplayXML:
			output.XML(os.Stdout, cfg, hops, maxHop)
		case trace.DisplayRaw:
			output.Raw(os.Stdout, cfg, hops, maxHop)
		case trace.DisplaySplit:
			output.Split(os.Stdout, cfg, hops, maxHop)
		case trace.DisplayCurses:
			// TODO: TUI mode
			output.Report(os.Stdout, cfg, hops, maxHop)
		default:
			output.Report(os.Stdout, cfg, hops, maxHop)
		}

		if cfg.Interactive {
			break
		}
	}

	os.Exit(exitVal)
}

// expandShortFlags expands combined short flags like "wzbc" into individual flags.
// Flags that take a value consume the next positional arg.
// Returns the expanded flags and the number of remaining args consumed.
func expandShortFlags(flags string, remaining []string) ([]string, int) {
	var result []string
	valFlags := map[byte]bool{
		'c': true, 's': true, 'I': true, 'a': true, 'i': true,
		'f': true, 'm': true, 'D': true, 'U': true, 'E': true,
		'o': true, 'B': true, 'G': true, 'Q': true, 'P': true,
		'L': true, 'Z': true, 'M': true, 'y': true, 'F': true,
	}
	remIdx := 0
	for j := 0; j < len(flags); j++ {
		flag := flags[j]
		result = append(result, "-"+string(flag))
		if valFlags[flag] {
			// If there are more characters in this group, they're the value.
			if j+1 < len(flags) {
				result = append(result, flags[j+1:])
				return result, remIdx
			}
			// Otherwise consume next positional arg.
			if remIdx < len(remaining) {
				result = append(result, remaining[remIdx])
				remIdx++
			}
		}
	}
	return result, remIdx
}

const maxHosts = 10000

func readHostsFile(filename string) ([]string, error) {
	var f *os.File
	var err error
	if filename == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			names = append(names, name)
			if len(names) >= maxHosts {
				return names, fmt.Errorf("too many hosts in file (max %d)", maxHosts)
			}
		}
	}
	return names, scanner.Err()
}

func resolveHostname(cfg *trace.Config) (net.IP, error) {
	// If it's already an IP, use it directly.
	if ip := net.ParseIP(cfg.Hostname); ip != nil {
		return ip, nil
	}

	network := "ip"
	switch cfg.AF {
	case 4:
		network = "ip4"
	case 6:
		network = "ip6"
	}

	addrs, err := net.ResolveIPAddr(network, cfg.Hostname)
	if err != nil {
		return nil, err
	}
	return addrs.IP, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
