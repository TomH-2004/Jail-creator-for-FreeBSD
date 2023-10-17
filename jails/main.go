package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	config = struct {
		privateKeyPath string
		remoteUsername string
		remoteAddress  string
		jailConfigPath string
		rcConfPath     string
		pfConfPath     string
	}{
		privateKeyPath: "/home/tom/.ssh/id_rsa",
		remoteUsername: "tom",
		remoteAddress:  "10.1.0.134:22",
		jailConfigPath: "/etc/jail.conf",
		rcConfPath:     "/etc/rc.conf",
		pfConfPath:     "/etc/pf.conf",
	}

	phpPackages = []string{"php80", "php81", "php82", "php83"}
	idePackages = []string{"vim", "neovim", "nano"}
	enterJail   string
)

func getPassword() (string, error) {
	fmt.Print("Enter the passphrase for your private key: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return string(password), err
}

func SSHConnection() (*ssh.Client, error) {
	password, err := getPassword()
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := ioutil.ReadFile(config.privateKeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(password))
	if err != nil {
		return nil, err
	}

	clientConfig := &ssh.ClientConfig{
		User: config.remoteUsername,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},

		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", config.remoteAddress, clientConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func appendToFile(filePath, text string) error {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return err
	}

	return nil
}

func findAvailableIP(configPath string) (string, error) {
	usedIPs := make(map[string]struct{})

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ip4.addr") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				ip := strings.Trim(parts[2], "\";")
				usedIPs[ip] = struct{}{}
			}
		}
	}

	for i := 2; i <= 254; i++ {
		ip := fmt.Sprintf("10.80.0.%d", i)
		if _, used := usedIPs[ip]; !used {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no available IP addresses")
}

func findAvailablePort(basePort int, configFile string) (int, error) {
	usedPorts := make(map[int]struct{})

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return 0, err
	}

	portPattern := regexp.MustCompile(`rdr pass on \$ext_if proto tcp from any to \$ext_if port (\d+) -> 10\.80\.0\.\d+ port \d+ #\w+`)

	matches := portPattern.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		if len(match) == 2 {
			port, _ := strconv.Atoi(match[1])
			usedPorts[port] = struct{}{}
		}
	}

	for port := basePort; port < basePort+100; port++ {
		if _, used := usedPorts[port]; !used {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available port found")
}

func addPFRuleToConf(pfConfPath, rule string) error {
	data, err := ioutil.ReadFile(pfConfPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")

	var passLineNum int
	for i, line := range lines {
		if strings.Contains(line, "pass on $bridge_if all") {
			passLineNum = i
			break
		}
	}

	lines = append(lines[:passLineNum], append([]string{rule}, lines[passLineNum:]...)...)

	updatedConf := strings.Join(lines, "\n")

	err = ioutil.WriteFile(pfConfPath, []byte(updatedConf), 0644)
	if err != nil {
		return err
	}

	return nil
}

func createFreeBSDJail(jailName string, client *ssh.Client, selectedIDE int, selectedPHP int, installApache int) (string, int, error) {
	jailDir := fmt.Sprintf("/usr/jail/%s", jailName)
	if err := os.MkdirAll(jailDir, 0755); err != nil {
		return "", 0, err
	}

	ip, err := findAvailableIP(config.jailConfigPath)
	if err != nil {
		return "", 0, err
	}

	assignedPort, err := findAvailablePort(2225, config.pfConfPath)
	if err != nil {
		return "", 0, err
	}

	jailConfig := fmt.Sprintf(`
%s {
    host.hostname = "%s.com";
    ip4.addr = "%s";
    path = "%s";
    interface = "bridge0";
}
`, jailName, jailName, ip, jailDir)

	if err := appendToFile(config.jailConfigPath, jailConfig); err != nil {
		return "", 0, err
	}

	pfRule := fmt.Sprintf("rdr pass on $ext_if proto tcp from any to $ext_if port %d -> %s port %d #%s", assignedPort, ip, assignedPort, jailName)
	if err := addPFRuleToConf(config.pfConfPath, pfRule); err != nil {
		return "", 0, err
	}

	fmt.Printf("Jail config added to %s\n", config.jailConfigPath)

	rcConfIP := fmt.Sprintf("%s/24", ip)
	if err := addIPToRCConf(rcConfIP); err != nil {
		return "", 0, err
	}

	fmt.Printf("IP address %s added to %s\n", rcConfIP, config.rcConfPath)

	cmd := exec.Command("bsdinstall", "jail", jailDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return "", 0, err
	}

	if err := execCmd("sudo", "pfctl", "-F", "all", "-f", config.pfConfPath); err != nil {
		return "", 0, err
	}

	fmt.Println("Reset pf settings and restarting netif...")

	if err := execCmd("sudo", "service", "netif", "restart"); err != nil {
		return "", 0, err
	}

	fmt.Printf("Waiting for the jail '%s' to be restarted...\n", jailName)
	if err := execCmd("sudo", "service", "jail", "restart", jailName); err != nil {
		return "", 0, err
	}

	fmt.Printf("Please wait while the jail '%s' is being restarted...\n", jailName)

	fmt.Println("Waiting for the jail's network to become available...")

	if selectedIDE >= 0 && selectedIDE < len(idePackages) {
		ideName := idePackages[selectedIDE]
		fmt.Printf("Installing %s in the jail...\n", ideName)
		if err := execCmd("sudo", "pkg", "-j", jailName, "install", ideName); err != nil {
			return "", 0, err
		}
		fmt.Printf("%s has been installed in the jail.\n", ideName)
	}

	if selectedPHP >= 0 && selectedPHP < len(phpPackages) {
		phpVersion := phpPackages[selectedPHP]
		fmt.Printf("Installing %s in the jail...\n", phpVersion)
		if err := execCmd("sudo", "pkg", "-j", jailName, "install", phpVersion); err != nil {
			return "", 0, err
		}
		fmt.Printf("%s has been installed in the jail.\n", phpVersion)
	}

	if installApache == 1 {
		fmt.Printf("Installing Apache 2.4 in the jail...\n")
		if err := execCmd("sudo", "pkg", "-j", jailName, "install", "apache24"); err != nil {
			return "", 0, err
		}
		fmt.Printf("Apache 2.4 has been installed in the jail.\n")
	}

	fmt.Printf("FreeBSD jail %s has been created successfully.\n", jailName)

	if err := editSSHDConfigInJail(jailName, assignedPort); err != nil {
		return "", 0, err
	}

	return ip, assignedPort, nil
}

func execCmd(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func addIPToRCConf(ip string) error {
	data, err := ioutil.ReadFile(config.rcConfPath)
	if err != nil {
		return err
	}

	rcConf := string(data)

	pattern := regexp.MustCompile(`ipv4_addrs_lo1="([^"]+)"`)

	matches := pattern.FindStringSubmatch(rcConf)

	if len(matches) < 2 {
		return fmt.Errorf("ipv4_addrs_lo1 line not found in %s", config.rcConfPath)
	}

	existingIPs := strings.Split(matches[1], " ")

	existingIPs = append(existingIPs, ip)

	updatedIPs := strings.Join(existingIPs, " ")

	rcConf = pattern.ReplaceAllString(rcConf, `ipv4_addrs_lo1="`+updatedIPs+`"`)

	err = ioutil.WriteFile(config.rcConfPath, []byte(rcConf), 0644)
	if err != nil {
		return err
	}

	return nil
}

func editSSHDConfigInJail(jailName string, port int) error {

	sshdConfigPath := fmt.Sprintf("/usr/jail/%s/etc/ssh/sshd_config", jailName)

	data, err := ioutil.ReadFile(sshdConfigPath)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	isPortLine := false
	var newSSHDConfig []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#Port") {
			newLine := fmt.Sprintf("Port %d", port)
			newSSHDConfig = append(newSSHDConfig, newLine)
			isPortLine = true
		} else {
			newSSHDConfig = append(newSSHDConfig, line)
		}
	}

	if !isPortLine {

		newLine := fmt.Sprintf("Port %d", port)
		newSSHDConfig = append(newSSHDConfig, newLine)
	}

	updatedSSHDConfig := strings.Join(newSSHDConfig, "\n")
	err = ioutil.WriteFile(sshdConfigPath, []byte(updatedSSHDConfig), 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	client, err := SSHConnection()
	if err != nil {
		log.Fatalf("Failed to connect to the server: %v", err)
	}
	defer client.Close()

	var jailName string
	fmt.Print("Enter the name of the jail: ")
	_, err = fmt.Scan(&jailName)
	if err != nil {
		log.Fatalf("Failed to read the jail name: %v", err)
	}

	fmt.Print("Do you want to enter the jail? (yes/no): ")
	_, err = fmt.Scan(&enterJail)
	if err != nil {
		log.Fatalf("Failed to read user input: %v", err)
	}

	fmt.Println("Select a PHP version to install:")
	for i, phpVersion := range phpPackages {
		fmt.Printf("%d. %s\n", i+1, phpVersion)
	}

	var selectedPHP int
	fmt.Print("Enter the number corresponding to the PHP version you want to install (0 to skip): ")
	_, err = fmt.Scan(&selectedPHP)
	if err != nil {
		log.Fatalf("Failed to read the selected PHP version: %v", err)
	}

	fmt.Println("Select an IDE to install:")
	for i, ide := range idePackages {
		fmt.Printf("%d. %s\n", i+1, ide)
	}

	var selectedIDE int
	fmt.Print("Enter the number corresponding to the IDE you want to install (0 to skip): ")
	_, err = fmt.Scan(&selectedIDE)
	if err != nil {
		log.Fatalf("Failed to read the selected IDE: %v", err)
	}

	var installApache int
	fmt.Print("Do you want to install Apache 2.4? (1: Yes, 2: No): ")
	_, err = fmt.Scan(&installApache)
	if err != nil || (installApache != 1 && installApache != 2) {
		log.Fatalf("Invalid selection for Apache installation")
	}

	var assignedPort int
	assignedIP, assignedPort, err := createFreeBSDJail(jailName, client, selectedIDE-1, selectedPHP-1, installApache)
	if err != nil {
		log.Fatalf("Failed to create the directory and add jail config: %v", err)
	}

	fmt.Printf("Restarting the jail '%s'...\n", jailName)
	if err := execCmd("sudo", "service", "jail", "restart", jailName); err != nil {
		log.Fatalf("Failed to restart the jail: %v", err)
	}

	clearCmd := exec.Command("clear")
	clearCmd.Stdout = os.Stdout
	clearCmd.Stderr = os.Stderr
	clearCmd.Stdin = os.Stdin
	if err := clearCmd.Run(); err != nil {
		log.Fatalf("Failed to run 'clear' command: %v", err)
	}

	log.Printf("FreeBSD jail %s has been created successfully with IP address %s.", jailName, assignedIP)

	jlsCmd := exec.Command("jls")
	jlsCmd.Stdout = os.Stdout
	jlsCmd.Stderr = os.Stderr
	jlsCmd.Stdin = os.Stdin
	if err := jlsCmd.Run(); err != nil {
		log.Fatalf("Failed to run 'jls' command: %v", err)
	}

	log.Printf("Use \"sudo jexec %s\" to enter the new jail\n", jailName)

	fmt.Printf("\033[31m%s is now listening on port %d\033[0m\n", jailName, assignedPort)

	if strings.ToLower(enterJail) == "yes" {
		fmt.Printf("Entering the jail '%s'...\n", jailName)
		if err := execCmd("sudo", "jexec", jailName); err != nil {
			log.Fatalf("Failed to enter the jail: %v", err)
		}
	}
}
