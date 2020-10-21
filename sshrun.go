package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/logutils"
	"github.com/jessevdk/go-flags"
)

var (
	version string
	commit  string
	branch  string
)

var (
	options Options
	parser  = flags.NewParser(&options, flags.PrintErrors|flags.PassDoubleDash)
	command []string
)

var (
	maxHostLength int
	maxNumLength  int
)

var (
	cyan   = color.New(color.FgCyan).SprintFunc()
	cyanb  = color.New(color.Bold, color.FgCyan).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	greenb = color.New(color.Bold, color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	redb   = color.New(color.Bold, color.FgRed).SprintFunc()
)

const (
	sshPort      = 22
	defaultState = "pending"
)

// Options reprsents all of the possible command options
type Options struct {
	HostsFile string `long:"hosts_file"  short:"h"              `
	HostsList string `long:"hosts_list"  short:"H"              `
	Parallel  int    `long:"parallel"    short:"p"  default:"16"`
	Timeout   int    `long:"timeout"     short:"t"  default:"15"`
	Opts      string `long:"opts"        short:"o"              `
	SSHOpts   string `long:"ssh_opts"    short:"s"              `
	Archive   bool   `long:"archive"     short:"a"              `
	Identity  string `long:"identity"    short:"y"              `
	User      string `long:"user"        short:"u"              `
	Dir       string `long:"dir"         short:"d"              `
	Inline    bool   `long:"inline"      short:"i"              `
	Head      int    `long:"head"                   default:"-1"`
	Tail      int    `long:"tail"                   default:"-1"`
	NoStatus  bool   `long:"no-status"                          `
	Version   bool   `long:"version"                            `
	Help      bool   `long:"help"                               `
	Debug     bool   `long:"debug"                              `
}

func usage() {
	usageText := `
Usage:
  sshrun   [OPTIONS] cmd...
  scprun   [OPTIONS] src dir
  rsyncrun [OPTIONS] src dir

Application Options:
  -h, --hosts_file= file containing host targets (delim = ' '|\t|\n)
  -H, --hosts_list= string containing host targets (delim = ,|' ')
  -p, --parallel=   number of concurrent runs to perform (default = 16)
  -t, --timeout=    timeout (seconds) of each run (default = 15)
  -o, --opts=       additional options for ssh|scp|rsync !(opt=val opt=val ...)
  -s, --ssh_opts=   additional options for ssh (opt=val opt=val ...)
  -a, --archive     use archive mode for rsync runs
  -y, --identity=   identity file for ssh|scp|rsync
  -u, --user=       user on remote for ssh|scp|rsync
  -d, --dir=        output directory for stdout/stderr files
  -i, --inline      display stdout & stderr inline
      --head=       display first X number of stdout bytes inline
      --tail=       display last X number of stdout bytes inline
      --version     display version and exit
      --no-status   do not print status of each run to stdout
      --debug       print debug output

      targets can be formated as host | user@host | host:port | user@host:port

Help Options:
      --help        Show this help message
`
	fmt.Println(usageText)
}

func parseOpts() {
	parser.Usage = "[OPTIONS] cmd"
	var err error // need this as using a short declaration below would mask package scoped command varaiable
	command, err = parser.Parse()
	if err != nil {
		usage()
		os.Exit(1) // errors already written to system err
	}
	if options.Help {
		usage()
		os.Exit(0)
	}
	if options.Version {
		fmt.Println(myVersion())
		os.Exit(0)
	}
	if options.HostsFile == "" && options.HostsList == "" {
		fmt.Fprintf(os.Stderr, "\nMust specify one or both --hosts_file=|--hosts_list=\n")
		usage()
		os.Exit(1)
	}
	if options.Head != -1 && options.Tail != -1 {
		fmt.Fprintf(os.Stderr, "\nCan not specify both --head and --tail\n")
		usage()
		os.Exit(1)
	}
	if options.Inline && (options.Head != -1 || options.Tail != -1) {
		fmt.Fprintf(os.Stderr, "\nCan not specify both --inline and --head|--tail\n")
		usage()
		os.Exit(1)
	}
}

func myVersion() string {
	var parts = []string{"SSHrun"}

	if version != "" {
		parts = append(parts, version)
	} else {
		parts = append(parts, "unknown")
	}

	if branch != "" || commit != "" {
		if branch == "" {
			branch = "unknown"
		}
		if commit == "" {
			commit = "unknown"
		}
		git := fmt.Sprintf("(git: %s %s)", branch, commit)
		parts = append(parts, git)
	}

	return strings.Join(parts, " ")
}

// Every host will get allocated a Hostrun struct so that we have the
// ability to deal with interrupted runs. Hostrun allows us to know which
// runs are pending and which ones are running so we can kill the running
// ones before exiting.

// Hostrun allows us to deal with interrupted runs.
type Hostrun struct {
	User    string
	Port    int
	Process *os.Process
	Start   time.Time
	State   string // (pending|running|complete|cancelled|terminated)
	Dir     string
}

// Each completed run will send an SSHrun over a channel to the dispatcher
// for display and possible stderr/stdout persistence.

// SSHrun allows for the capture of telemetry of runs.
type SSHrun struct {
	Host     string
	Exit     int
	Stdout   string
	Stderr   string
	Context  error
	Duration time.Duration
	Complete bool
}

// return a slice from a comma or whitespace delimited string
func parseList(list string) []string {
	list = strings.ReplaceAll(list, ",", " ")
	return strings.Fields(list)
}

// return a slice from a newline|space|tab delimited file
func parseFile(file string) []string {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalf("Could not read file %s: %s\n", file, err)
	}
	// replace multiple tabs|spaces with single space
	re := regexp.MustCompile(`[\t| ]+`)
	f := re.ReplaceAllString(string(bytes), " ")
	// replace single space with newline
	f = strings.Replace(f, " ", "\n", -1)
	return deleteEmpty(strings.Split(f, "\n"))
}

// remove all empty elements from a slice
func deleteEmpty(slice []string) []string {
	var r []string
	for _, s := range slice {
		if s != "" {
			r = append(r, s)
		}
	}
	return r
}

// remove all duplicate elements from set of slices and return
// a single slice
func dedupe(slice ...[]string) []string {
	var r []string
	seen := make(map[string]bool)
	for _, s := range slice {
		for _, host := range s {
			if !seen[host] {
				r = append(r, host)
				seen[host] = true
			}
		}
	}
	return r
}

// return a slice from a comma or whitespace delimited string
// adding -o between each item
func parseSSHOpts(list string) []string {
	var sshopts []string
	list = strings.ReplaceAll(list, "-o", "")
	for _, opt := range parseList(list) {
		sshopts = append(sshopts, "-o", opt)
	}
	return sshopts
}

// convert a slice that has 4 possible formats: host, user@host, host:port,
// and user@host:port into map[host]*Hostrun. To be used if a run is
// interrupted and as a the list of the overall targets.
func parseHosts(rawHosts []string) map[string]*Hostrun {
	var hosts = make(map[string]*Hostrun)
	for _, r := range rawHosts {
		var name string
		var h Hostrun
		s0 := strings.Split(r, "@")
		s1 := strings.Split(r, ":")
		// user@name:port
		if len(s0) > 1 && len(s1) > 1 {
			s2 := strings.Split(s0[1], ":")
			port, _ := strconv.Atoi(s2[1])
			name = s2[0]
			h = Hostrun{
				User: s0[0],
				Port: port,
			}
			// user@name
		} else if len(s0) > 1 {
			name = s0[1]
			h = Hostrun{
				User: s0[0],
				Port: sshPort,
			}
			// name:port
		} else if len(s1) > 1 {
			port, _ := strconv.Atoi(s1[1])
			name = s1[0]
			h = Hostrun{
				User: "",
				Port: port,
			}
			// name
		} else {
			name = r
			h = Hostrun{
				User: "",
				Port: sshPort,
			}
		}
		h.State = defaultState
		hosts[name] = &h
	}
	return hosts
}

func sshCmd() string {
	if val, ok := os.LookupEnv("SSH_CMD"); ok {
		return val
	}
	return "ssh"
}

func scpCmd() string {
	if val, ok := os.LookupEnv("SCP_CMD"); ok {
		return val
	}
	return "scp"
}

func rsyncCmd() string {
	if val, ok := os.LookupEnv("RSYNC_CMD"); ok {
		return val
	}
	return "rsync"
}

func binCmd(base string) string {
	switch base {
	case "sshrun":
		return sshCmd()
	case "scprun":
		return scpCmd()
	case "rsyncrun":
		return rsyncCmd()
	}
	return ""
}

// Take all of the differnt ways that options can be specified and create
// a slice in the format that is correct for SSH
func genSSHOpts(hostrun *Hostrun) ([]string, []string) {
	var opts []string
	// port
	opts = append(opts, "-p", strconv.Itoa(hostrun.Port))
	// user
	if options.User != "" {
		opts = append(opts, "-l", options.User)
	} else if hostrun.User != "" {
		opts = append(opts, "-l", hostrun.User)
	}
	// identity
	if options.Identity != "" {
		opts = append(opts, "-i", options.Identity)
	}
	// SSH not the -o opts
	if options.Opts != "" {
		opts = append(opts, parseList(options.Opts)...)
	}
	// SSH -o opts
	if options.SSHOpts != "" {
		opts = append(opts, parseSSHOpts(options.SSHOpts)...)
	}
	return opts, nil
}

// Take all of the differnt ways that options can be specified and create
// a slice in the format that is correct for SCP
func genSCPOpts(hostrun *Hostrun) ([]string, []string) {
	var opts []string
	// port
	opts = append(opts, "-P", strconv.Itoa(hostrun.Port))
	// user
	if options.User != "" {
		opts = append(opts, "-l", options.User)
	} else if hostrun.User != "" {
		opts = append(opts, "-l", hostrun.User)
	}
	// identity
	if options.Identity != "" {
		opts = append(opts, "-i", options.Identity)
	}
	// SCP opts
	if options.Opts != "" {
		opts = append(opts, parseList(options.Opts)...)
	}
	// SSH -o opts
	if options.SSHOpts != "" {
		opts = append(opts, parseSSHOpts(options.SSHOpts)...)
	}
	return opts, nil
}

// Take all of the differnt ways that options can be specified and create
// a slice in the format that is correct for RSYNC
func genRsyncOpts(hostrun *Hostrun) ([]string, []string) {
	var opts, rsyncSSH []string
	// ssh command
	rsyncSSH = append(rsyncSSH, sshCmd())
	// port
	rsyncSSH = append(rsyncSSH, "-p", strconv.Itoa(hostrun.Port))
	// user
	if options.User != "" {
		rsyncSSH = append(rsyncSSH, "-l", options.User)
	} else if hostrun.User != "" {
		rsyncSSH = append(rsyncSSH, "-l", hostrun.User)
	}
	// identity
	if options.Identity != "" {
		rsyncSSH = append(rsyncSSH, "-i", options.Identity)
	}
	// SSH -o opts
	if options.SSHOpts != "" {
		rsyncSSH = append(rsyncSSH, parseSSHOpts(options.SSHOpts)...)
	}
	// archive
	if options.Archive {
		opts = append(opts, "-a")
	}
	// RSYNC opts
	if options.Opts != "" {
		opts = append(opts, parseList(options.Opts)...)
	}
	return opts, rsyncSSH
}

func genOpts(base string, hostrun *Hostrun) ([]string, []string) {
	switch base {
	case "sshrun":
		return genSSHOpts(hostrun)
	case "scprun":
		return genSCPOpts(hostrun)
	case "rsyncrun":
		return genRsyncOpts(hostrun)
	}
	return nil, nil
}

func runCmd(
	bin string,
	opts []string,
	rsyncSSH []string,
	host string,
	hostrun *Hostrun,
	runs chan SSHrun,
	sema chan struct{},
	interrupt chan struct{},
) {
	var stdout, stderr bytes.Buffer
	var run SSHrun

	// get run token, this is how parallelism is enforced
	sema <- struct{}{}
	log.Printf("[DEBUG]: %s: Run token obtained\n", host)

	// release run token
	defer func() {
		<-sema
		log.Printf("[DEBUG]: %s: Run token released\n", host)
	}()

	// when we get a chance to run check to see if the overall run has
	// been cancelled. If so we are done.
	select {
	case <-interrupt:
		hostrun.State = "cancelled"
		log.Printf("[DEBUG]: %s: Run cancelled in token wait\n", host)
		return
	default:
		break
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second)
	defer cancel()

	if rsyncSSH != nil {
		s := strings.Join(rsyncSSH, " ")
		os.Setenv("RSYNC_RSH", s)
		log.Printf("[DEBUG]: %s: RSYNC_RSH: %s\n", host, s)
	}

	switch path.Base(bin) {
	case "ssh":
		opts = append(opts, host)
		opts = append(opts, command...)
	case "scp", "rsync":
		opts = append(opts, command[0], host+":"+command[1])
	}

	cmd := exec.CommandContext(ctx, bin, opts...)

	// The shell will signal the entire process group when you press ctrl+c.
	// To prevent the shell from signaling the children, you need to start the
	// command in its own process group before starting the processes. We do
	// this so that "WE" control the terminating of the sub process that are in
	// flight. If we did not set this then when ctrl+c is pressed the shell
	// starts reaping process and we lose the state info around completed vs
	// interrupted tasks.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if options.Debug {
		log.Printf("[DEBUG]: %s: Cmd.Path: %v\n", host, cmd.Path)
		log.Printf("[DEBUG]: %s: Cmd.Args: %v\n", host, cmd.Args)
		log.Printf("[DEBUG]: %s: Cmd.Env: %v\n", host, cmd.Env)
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Start()
	if options.Debug {
		log.Printf("[DEBUG]: %s: Cmd started\n", host)
	}
	if err != nil {
		hostrun.State = "complete"
		run = SSHrun{
			Host:   host,
			Exit:   1,
			Stderr: fmt.Sprintf("cmd.Start() failed with '%s'\n", err),
		}
		if options.Debug {
			log.Printf("[DEBUG]: %s: Cmd complete with cmd.Start() failure\n", host)
		}
		return
	}

	hostrun.Process = cmd.Process
	hostrun.Start = time.Now()
	hostrun.State = "running"

	// we need a way to know when the command is done so we call
	// cmd.Wait. We send that (error or nil) into a chanel that we can
	// select on to know when it is complete.
	wait := make(chan error, 1)
	go func(wait chan error) {
		wait <- cmd.Wait()
	}(wait)

	var complete bool

	select {
	case err = <-wait:
		hostrun.State = "complete"
		complete = true
	case <-interrupt:
		hostrun.State = "terminated"
		err = errors.New("terminated")
		_ = cmd.Process.Kill() // try and kill the process just in case.
	}

	run = SSHrun{
		Host:     host,
		Exit:     0,
		Stdout:   string(stdout.Bytes()),
		Stderr:   string(stderr.Bytes()),
		Context:  ctx.Err(),
		Duration: time.Now().Sub(hostrun.Start),
		Complete: complete,
	}

	if err != nil {
		run.Exit = 1
	}

	log.Printf("[DEBUG]: %s: Cmd complete with error: %v\n", host, err)

	// each goroutine is responsible for writing stdout and stderr to
	// disk if that was requested. We do not care if this fails as we
	// could not handle it anyway.
	if hostrun.Dir != "" {
		outPath := filepath.Join(hostrun.Dir, host+"-stdout")
		errPath := filepath.Join(hostrun.Dir, host+"-stderr")

		if len(stdout.Bytes()) > 0 {
			err := ioutil.WriteFile(outPath, stdout.Bytes(), 0640)
			if err != nil {
				log.Printf("[DEBUG]: %s: error writing to outPath %s: %s ", host, outPath, err)
			}
		}
		if len(stderr.Bytes()) > 0 {
			err := ioutil.WriteFile(errPath, stderr.Bytes(), 0640)
			if err != nil {
				log.Printf("[DEBUG]: %s: error writing to errPath %s: %s ", host, errPath, err)
			}
		}
	}

	// send state back to dispatcher for admin and printing
	runs <- run
	return
}

func maxLengths(hosts map[string]*Hostrun) {
	maxNumLength = len(strconv.Itoa(len(hosts)))
	for name := range hosts {
		if len(name) > maxHostLength {
			maxHostLength = len(name)
		}
	}
}

func printRun(run SSHrun, i int) {
	if options.NoStatus {
		return
	}
	status := greenb("SUCCESS")
	if run.Exit != 0 {
		status = redb("FAILURE")
	}
	if !run.Complete {
		status = redb("INTERRU")
	}

	iter := fmt.Sprintf(fmt.Sprintf("%%0%dd", maxNumLength), i)
	host := fmt.Sprintf(fmt.Sprintf("%%%ds", maxHostLength), run.Host)

	seconds := int(run.Duration.Seconds())
	hours := int(math.Floor(float64(seconds) / 60 / 60))
	minutes := int(math.Floor(float64(seconds) / 60))

	dura := fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds%60)

	var head, tail string

	switch {
	case options.Head > 0:
		head = strings.TrimSuffix(run.Stdout, "\n")
		if len(head) > options.Head {
			head = head[:options.Head]
		}
		fmt.Printf("[%s] %s [%7s] [%s] %s\n", cyanb(iter), host, status, dura, head)
	case options.Tail > 0:
		tail = strings.TrimSuffix(run.Stdout, "\n")
		if len(tail) > options.Tail {
			tail = tail[len(tail)-options.Tail:]
		}
		fmt.Printf("[%s] %s [%7s] [%s] %s\n", cyanb(iter), host, status, dura, tail)
	default:
		fmt.Printf("[%s] %s [%7s] [%s]\n", cyanb(iter), host, status, dura)
	}

	if options.Inline {
		if len(run.Stdout) != 0 {
			fmt.Printf("%s", green(run.Stdout))
		}
		if len(run.Stderr) != 0 {
			fmt.Printf("%s", red(run.Stderr))
		}
	}
}

func endRuns(hosts map[string]*Hostrun, i int) {
	if options.NoStatus {
		return
	}
	status := redb("CANCELD")
	for k, v := range hosts {
		if v.State == "cancelled" {
			iter := fmt.Sprintf(fmt.Sprintf("%%0%dd", maxNumLength), i)
			host := fmt.Sprintf(fmt.Sprintf("%%%ds", maxHostLength), k)
			dura := fmt.Sprintf("%02d:%02d:%02d", 0, 0, 0)
			fmt.Printf("[%s] %s [%7s] [%s]\n", cyanb(iter), host, status, dura)
			i++
		}
	}
}

func main() {
	parseOpts()
	logLevel := "WARN"
	if options.Debug {
		logLevel = "DEBUG"
	}

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel(logLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

	base := path.Base(os.Args[0])
	switch base {
	case "sshrun", "scprun", "rsyncrun":
	default:
		log.Fatalf("%s is not a vaild program\n", base)
	}
	bin := binCmd(base)

	// combine the two ways one can specify hosts into a single
	// deduped slice of hosts.
	var rawHosts []string
	if options.HostsList != "" && options.HostsFile != "" {
		rawHosts = dedupe(parseList(options.HostsList), parseFile(options.HostsFile))
	} else if options.HostsList != "" {
		rawHosts = dedupe(parseList(options.HostsList))
	} else {
		rawHosts = dedupe(parseFile(options.HostsFile))
	}

	// map[name]*Hostrun where each name is a target host
	hosts := parseHosts(rawHosts)

	// channel to pass back info for a completed run
	runs := make(chan SSHrun, len(hosts))

	// channel to limit number of simultaneous runs
	sema := make(chan struct{}, options.Parallel)

	// channel to inform all runs that we are ending
	interrupt := make(chan struct{})

	// signal handler to allow user to cancel runs
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// create directory for stdout|stderr persistence and embed that in
	// each Hostrun struct
	if options.Dir != "" {
		epoch := fmt.Sprintf("%d", time.Now().Unix())
		path := filepath.Join(options.Dir, base+"-"+epoch)
		if err := os.MkdirAll(path, 0750); err != nil {
			log.Fatalf("Could not mkdir %s: %s\n", path, err)
		}
		for _, hostrun := range hosts {
			hostrun.Dir = path
		}
	}

	// create a go routine for each host. A semaphone limits the
	// number than can run simultaneously
	for host, hostrun := range hosts {
		opts, rsyncSSH := genOpts(base, hostrun)
		go runCmd(bin, opts, rsyncSSH, host, hostrun, runs, sema, interrupt)
	}

	// mutating of global vars that I will get hate mail about.
	maxLengths(hosts)

	// print output or deal with sigint/sigterm
	for i := 1; i <= len(hosts); i++ {
		select {
		case run := <-runs:
			printRun(run, i)
		case <-sigs:
			// tell all goroutines we are terminting
			close(interrupt)
			// Allow go routines see signal and write to channel
			time.Sleep(250 * time.Millisecond)
			// drain any remaining runs
			close(runs)
			for run := range runs {
				printRun(run, i)
				i++
			}
			// print the cancelled runs (if any)
			endRuns(hosts, i)
			os.Exit(1)
		}
	}
	os.Exit(0)
}
