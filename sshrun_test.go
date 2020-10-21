package main

import (
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	var hosts = []string{
		"host001",
		"host002:2222",
		"user001@host003",
		"user002@host004:2223",
	}

	type host struct {
		User string
		Port int
	}

	expected := map[string]host{
		"host001": host{"", sshPort},
		"host002": host{"", 2222},
		"host003": host{"user001", sshPort},
		"host004": host{"user002", 2223},
	}

	result := parseHosts(hosts)

	for k, v := range expected {
		if result[k].User != v.User || result[k].Port != v.Port {
			t.Errorf("%s expected User = %s Port = %d, got %s, %d", k, v.User, v.Port, result[k].User, result[k].Port)
		}
	}
}

func TestGenSSHOpts(t *testing.T) {
	thr := Hostrun{User: "toor", Port: 222}
	options.Opts = ""
	options.SSHOpts = ""
	options.Identity = ""
	options.User = ""
	opts, _ := genSSHOpts(&thr)
	expected := "-p 222 -l toor"
	if strings.Join(opts, " ") != expected {
		t.Errorf("SSHOpts exepected %s, got %s", strings.Fields(expected), strings.Join(opts, " "))
	}

	thr = Hostrun{User: "oort", Port: sshPort}
	options.Opts = "-A -q -6 -p 222"
	options.SSHOpts = "-o BatchMode=yes -o Compression=yes"
	options.Identity = "/toor/.ssh/id_rsa"
	options.User = "toor"
	opts, _ = genSSHOpts(&thr)
	expected = "-p 22 -l toor -i /toor/.ssh/id_rsa -A -q -6 -p 222 -o BatchMode=yes -o Compression=yes"
	if strings.Join(opts, " ") != expected {
		t.Errorf("SSHOpts expected %s, got %s", strings.Fields(expected), strings.Join(opts, " "))
	}
}

func TestGenSCPOpts(t *testing.T) {
	thr := Hostrun{User: "toor", Port: 222}
	options.Opts = ""
	options.SSHOpts = ""
	options.Identity = ""
	options.User = ""
	opts, _ := genSCPOpts(&thr)
	expected := "-P 222 -l toor"
	if strings.Join(opts, " ") != expected {
		t.Errorf("SCPOpts exepected %s, got %s", expected, strings.Join(opts, " "))
	}

	thr = Hostrun{User: "oort", Port: sshPort}
	options.Opts = "-r -q -6 -P 222"
	options.SSHOpts = "-o BatchMode=yes -o Compression=yes"
	options.Identity = "/toor/.ssh/id_rsa"
	options.User = "toor"
	opts, _ = genSCPOpts(&thr)
	expected = "-P 22 -l toor -i /toor/.ssh/id_rsa -r -q -6 -P 222 -o BatchMode=yes -o Compression=yes"
	if strings.Join(opts, " ") != expected {
		t.Errorf("SCPOpts expected %s, got %s", expected, strings.Join(opts, " "))
	}
}

func TestGenRsyncOpts(t *testing.T) {
	thr := Hostrun{User: "toor", Port: 222}
	options.Opts = ""
	options.SSHOpts = ""
	options.Identity = ""
	options.User = ""
	opts, rsyncSSH := genRsyncOpts(&thr)
	optsExpected := ""
	rsyncSSHExpected := "ssh -p 222 -l toor"
	if strings.Join(opts, " ") != optsExpected {
		t.Errorf("RsyncOpts opts expected %s, got %s", optsExpected, strings.Join(opts, " "))
	}
	if strings.Join(rsyncSSH, " ") != rsyncSSHExpected {
		t.Errorf("RsyncOpts ssh expected %s, got %s", rsyncSSHExpected, strings.Join(rsyncSSH, " "))
	}

	thr = Hostrun{User: "oort", Port: sshPort}
	options.Opts = "-q -6 -i"
	options.SSHOpts = "-o BatchMode=yes -o Compression=yes"
	options.Identity = "/toor/.ssh/id_rsa"
	options.User = "toor"
	options.Archive = true
	opts, rsyncSSH = genRsyncOpts(&thr)
	optsExpected = "-a -q -6 -i"
	rsyncSSHExpected = "ssh -p 22 -l toor -i /toor/.ssh/id_rsa -o BatchMode=yes -o Compression=yes"
	if strings.Join(opts, " ") != optsExpected {
		t.Errorf("RsyncOpts opts expected %s, got %s", optsExpected, strings.Join(opts, " "))
	}
	if strings.Join(rsyncSSH, " ") != rsyncSSHExpected {
		t.Errorf("RsyncOpts ssh expected %s, got %s", rsyncSSHExpected, strings.Join(rsyncSSH, " "))
	}
}
