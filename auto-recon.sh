#!/bin/bash

# Auto-Recon - Automated Reconnaissance Script
# Author: Boni Yeamin
# GitHub: https://github.com/boniyeamincse
# Description: A powerful automated reconnaissance tool for bug bounty hunters and penetration testers
# Version: 1.0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo " ____              _    _____          _     ____                        "
    echo "| __ )  ___  _ __ (_)  |  ___|__  _ _| |_  |  _ \ ___  ___ ___  _ __  "
    echo "|  _ \ / _ \| '_ \| |  | |_ / _ \| '__| __| | |_) / _ \/ __/ _ \| '_ \ "
    echo "| |_) | (_) | | | | |  |  _| (_) | |  | |_  |  _ <  __/ (_| (_) | | | |"
    echo "|____/ \___/|_| |_|_|  |_|  \___/|_|   \__| |_| \_\___|\___\___/|_| |_|"
    echo "                                                                               "
    echo -e "${NC}"
    echo -e "${YELLOW}[*] Boni Fort Recon - Advanced Reconnaissance Tool${NC}"
    echo -e "${YELLOW}[*] Created by: Boni Yeamin${NC}"
    echo -e "${PURPLE}[*] Version: 1.0${NC}"
    echo "------------------------------------------------"
}

# Check if required tools are installed
check_requirements() {
    echo -e "\n${BLUE}[*] Checking required tools...${NC}"
    
    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "${GREEN}[+] Detected OS: $NAME${NC}"
    else
        echo -e "${RED}[-] Could not detect OS${NC}"
        exit 1
    fi
    
    # Check root privileges
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] Please run as root${NC}"
        exit 1
    fi
    
    # Required tools and their installation commands
    declare -A tools=(
        ["go"]="apt install -y golang"
        ["nmap"]="apt install -y nmap"
        ["nikto"]="apt install -y nikto"
        ["subfinder"]="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["amass"]="go install github.com/owasp-amass/amass/v3/...@latest"
        ["dnsx"]="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["httpx"]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["naabu"]="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["assetfinder"]="go install github.com/tomnomnom/assetfinder@latest"
        ["findomain"]="curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux && chmod +x findomain-linux && mv findomain-linux /usr/bin/findomain"
    )
    
    # Check and install tools
    for tool in "${!tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}[*] Installing $tool...${NC}"
            eval "${tools[$tool]}" &>/dev/null
            if ! command -v "$tool" &> /dev/null; then
                echo -e "${RED}[-] Failed to install $tool${NC}"
                exit 1
            fi
        else
            echo -e "${GREEN}[+] $tool is installed${NC}"
        fi
    done
    
    # Setup Go environment if not already set
    if [ -z "$GOPATH" ]; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        source ~/.bashrc
    fi
}

# Help menu
show_help() {
    echo "Usage: $0 -d domain.com [options]"
    echo
    echo "Options:"
    echo "  -d    Target domain"
    echo "  -o    Output directory (default: results)"
    echo "  -p    Ports to scan (default: top 1000)"
    echo "  -t    Number of threads (default: 50)"
    echo "  -w    Timeout in seconds (default: 30)"
    echo "  -v    Enable vulnerability scanning (Nikto & Nmap vuln scripts)"
    echo "  -n    Enable Nmap scanning (default: disabled)"
    echo "  -s    Nmap scan type (default: -sV -sC)"
    echo "  -q    Quick scan mode (faster results)"
    echo "  -f    Full scan mode (comprehensive but slower)"
    echo "  -h    Show this help message"
    echo
    echo "Example:"
    echo "  $0 -d example.com -p 80,443,8080 -t 100 -o my_results -n -s '-sV -sC -A'"
    echo
    exit 1
}

# Create output directory
setup_workspace() {
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
    fi
    if [ ! -d "$output_dir/subdomains" ]; then
        mkdir -p "$output_dir/subdomains"
    fi
    if [ ! -d "$output_dir/scanning" ]; then
        mkdir -p "$output_dir/scanning"
    fi
}

# Subdomain enumeration
enumerate_subdomains() {
    echo -e "\n${BLUE}[*] Starting subdomain enumeration...${NC}"
    
    local date_str=$(date +%Y%m%d_%H%M%S)
    local domain_dir="$output_dir/${domain}_${date_str}"
    mkdir -p "$domain_dir/subdomains"
    mkdir -p "$domain_dir/active"
    
    # Run all tools in parallel
    (subfinder -d "$domain" -t $SUBFINDER_THREADS -silent | sort -u > "$domain_dir/subdomains/subfinder.txt") &
    (amass enum -passive -d "$domain" -timeout $AMASS_TIMEOUT -o "$domain_dir/subdomains/amass.txt") &
    (assetfinder --subs-only "$domain" | sort -u > "$domain_dir/subdomains/assetfinder.txt") &
    (findomain -t "$domain" -q > "$domain_dir/subdomains/findomain.txt") &
    
    # Wait for all background processes to complete
    wait
    
    # Combine results
    cat "$domain_dir/subdomains/"*.txt | sort -u > "$domain_dir/all_subdomains.txt"
    
    # Create a dated copy of all subdomains
    cp "$domain_dir/all_subdomains.txt" "$domain_dir/subdomains_${date_str}.txt"
    
    echo -e "${GREEN}[+] Found $(wc -l < "$domain_dir/all_subdomains.txt") unique subdomains${NC}"
}

# DNS resolution
resolve_dns() {
    echo -e "\n${BLUE}[*] Resolving DNS...${NC}"
    dnsx -l "$domain_dir/all_subdomains.txt" -silent -a -aaaa -cname \
        -o "$domain_dir/active/resolved.txt"
    
    # Save only active domains
    cat "$domain_dir/active/resolved.txt" | cut -f1 -d'[' > "$domain_dir/active/active_domains.txt"
}

# HTTP probe with optimizations
probe_http() {
    echo -e "\n${BLUE}[*] Probing for HTTP/HTTPS services...${NC}"
    cat "$domain_dir/active/active_domains.txt" | httpx -silent \
        -title -status-code -tech-detect \
        -threads "$threads" \
        -rate-limit $HTTPX_RATE \
        -timeout $timeout \
        -retries 2 \
        -skip-cdn-check \
        -no-color \
        -o "$domain_dir/active/http_probe.txt"
}

# Optimized port scanning
port_scan() {
    echo -e "\n${BLUE}[*] Starting port scan...${NC}"
    
    # Quick initial scan
    echo -e "${YELLOW}[*] Quick scan of common ports...${NC}"
    naabu -l "$domain_dir/active/active_domains.txt" \
        -p "$QUICK_PORTS" \
        -rate $NAABU_RATE \
        -silent -o "$domain_dir/active/port_scan/quick_ports.txt"
    
    # Full port scan in background
    if [ "$enable_full_scan" = true ]; then
        echo -e "${YELLOW}[*] Starting full port scan in background...${NC}"
        naabu -l "$domain_dir/active/active_domains.txt" \
            -p "$ports" \
            -rate $NAABU_RATE \
            -silent -o "$domain_dir/active/port_scan/full_ports.txt" &
    fi
}

# Vulnerability scanning function
vulnerability_scan() {
    echo -e "\n${BLUE}[*] Starting vulnerability scanning...${NC}"
    mkdir -p "$domain_dir/vulnerabilities"
    
    # Nikto scan for web vulnerabilities
    if [ "$enable_vuln_scan" = true ]; then
        echo -e "${YELLOW}[*] Running Nikto web vulnerability scans...${NC}"
        while IFS= read -r target; do
            if grep -q "^http" <<< "$target"; then
                local domain_name=$(echo "$target" | awk -F[/:] '{print $4}')
                echo -e "${BLUE}[*] Scanning $target with Nikto${NC}"
                nikto -h "$target" -output "$domain_dir/vulnerabilities/nikto_${domain_name}.txt" \
                    -Format txt -nointeractive
            fi
        done < "$domain_dir/active/http_probe.txt"
        
        # Combine Nikto results
        echo -e "${BLUE}[*] Generating combined Nikto report...${NC}"
        echo "Combined Nikto Scan Results" > "$domain_dir/vulnerabilities/nikto_combined.txt"
        echo "================================" >> "$domain_dir/vulnerabilities/nikto_combined.txt"
        cat "$domain_dir/vulnerabilities/nikto_"*.txt >> "$domain_dir/vulnerabilities/nikto_combined.txt"
    fi
    
    # Nmap vulnerability scripts
    if [ "$enable_vuln_scan" = true ]; then
        echo -e "${YELLOW}[*] Running Nmap vulnerability scripts...${NC}"
        while IFS= read -r host; do
            echo -e "${BLUE}[*] Running vulnerability scan on $host${NC}"
            
            # Extract ports from previous Nmap results
            local host_ports=$(grep "^$host:" "$domain_dir/active/port_scan/naabu_ports.txt" | cut -d ':' -f2 | tr ',' ' ')
            
            if [ ! -z "$host_ports" ]; then
                # Run Nmap vulnerability scripts
                nmap -sV --script vuln,exploit,auth,default,version \
                    -p$host_ports $host \
                    -oN "$domain_dir/vulnerabilities/nmap_vuln_${host}.txt" \
                    -oX "$domain_dir/vulnerabilities/nmap_vuln_${host}.xml" \
                    --reason --stats-every 10s
                
                # Generate HTML report for vulnerabilities
                xsltproc "$domain_dir/vulnerabilities/nmap_vuln_${host}.xml" \
                    -o "$domain_dir/vulnerabilities/nmap_vuln_${host}.html" 2>/dev/null
            fi
        done < "$domain_dir/active/active_domains.txt"
        
        # Combine Nmap vulnerability results
        echo -e "${BLUE}[*] Generating combined Nmap vulnerability report...${NC}"
        echo "Combined Nmap Vulnerability Scan Results" > "$domain_dir/vulnerabilities/nmap_vuln_combined.txt"
        echo "=======================================" >> "$domain_dir/vulnerabilities/nmap_vuln_combined.txt"
        cat "$domain_dir/vulnerabilities/nmap_vuln_"*.txt >> "$domain_dir/vulnerabilities/nmap_vuln_combined.txt"
    fi
}

# Quick vulnerability scan
quick_vuln_scan() {
    echo -e "\n${BLUE}[*] Running quick vulnerability checks...${NC}"
    
    # Run Nmap with specific scripts
    while IFS= read -r host; do
        nmap -sV --script "vuln and safe" -p80,443 $host \
            -oN "$domain_dir/vulnerabilities/quick_${host}.txt" &
    done < "$domain_dir/active/active_domains.txt"
    wait
}

# Generate report
generate_report() {
    local report_file="$domain_dir/reconnaissance_report.txt"
    
    echo "Reconnaissance Report for $domain" > "$report_file"
    echo "Date: $(date)" >> "$report_file"
    echo "----------------------------------------" >> "$report_file"
    echo "Total Subdomains Found: $(wc -l < "$domain_dir/all_subdomains.txt")" >> "$report_file"
    echo "Active Domains: $(wc -l < "$domain_dir/active/active_domains.txt")" >> "$report_file"
    echo "HTTP/HTTPS Services: $(wc -l < "$domain_dir/active/http_probe.txt")" >> "$report_file"
    echo "Open Ports Found: $(wc -l < "$domain_dir/active/port_scan/naabu_ports.txt")" >> "$report_file"
    if [ "$enable_nmap" = true ]; then
        echo "----------------------------------------" >> "$report_file"
        echo "Nmap Scan Results:" >> "$report_file"
        echo "----------------------------------------" >> "$report_file"
        cat "$domain_dir/active/port_scan/nmap_combined.txt" >> "$report_file"
    fi
    
    if [ "$enable_vuln_scan" = true ]; then
        echo -e "\n=== Vulnerability Scan Results ===" >> "$report_file"
        echo -e "\nNikto Web Vulnerability Findings:" >> "$report_file"
        echo "----------------------------------------" >> "$report_file"
        cat "$domain_dir/vulnerabilities/nikto_combined.txt" >> "$report_file"
        
        echo -e "\nNmap Vulnerability Scan Findings:" >> "$report_file"
        echo "----------------------------------------" >> "$report_file"
        cat "$domain_dir/vulnerabilities/nmap_vuln_combined.txt" >> "$report_file"
    fi
}

# Progress bar function
show_progress() {
    local duration=$1
    local prefix=$2
    local size=50
    local progress=0
    
    while [ $progress -le 100 ]; do
        local filled=$(( progress*size/100 ))
        local empty=$(( size-filled ))
        printf "\r${prefix} [${GREEN}"
        printf "%${filled}s" '' | tr ' ' '█'
        printf "${NC}%${empty}s] ${progress}%%" '' 
        progress=$(( progress+2 ))
        sleep $(echo "scale=2; $duration/50" | bc)
    done
    echo
}

# Time tracking
start_time() {
    start_time=$(date +%s)
}

end_time() {
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    echo -e "${BLUE}[*] Total execution time: ${YELLOW}$(date -u -d @${total_time} +"%T")${NC}"
}

# Error handling
set -e  # Exit on error
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5
    
    echo -e "${RED}[ERROR] Exit code: $exit_code${NC}"
    echo -e "${RED}[ERROR] Last command: $last_command${NC}"
    echo -e "${RED}[ERROR] Line: $line_no${NC}"
    echo -e "${RED}[ERROR] Function trace: $func_trace${NC}"
    
    # Log error to file
    echo "[$(date)] ERROR: $last_command (exit code: $exit_code) at line $line_no" >> "$domain_dir/error.log"
}

# Logging function
log() {
    local level=$1
    local message=$2
    echo "[$(date)] [$level] $message" >> "$domain_dir/scan.log"
}

# Save scan state
save_state() {
    local state_file="$domain_dir/.scan_state"
    echo "DOMAIN=$domain" > "$state_file"
    echo "PROGRESS=$1" >> "$state_file"
    echo "START_TIME=$start_time" >> "$state_file"
}

# Resume from last state
resume_scan() {
    local state_file="$domain_dir/.scan_state"
    if [ -f "$state_file" ]; then
        source "$state_file"
        echo -e "${YELLOW}[*] Resuming previous scan for $DOMAIN${NC}"
        return 0
    fi
    return 1
}

# Parallel processing function
run_parallel() {
    local max_jobs=$1
    shift
    local commands=("$@")
    
    for cmd in "${commands[@]}"; do
        while [ $(jobs -r | wc -l) -ge $max_jobs ]; do
            sleep 1
        done
        eval "$cmd" &
    done
    wait
}

# Rate limiting function
rate_limit() {
    local requests=$1
    local interval=$2
    local last_request_file="/tmp/last_request"
    
    if [ -f "$last_request_file" ]; then
        local last_request=$(cat "$last_request_file")
        local current_time=$(date +%s)
        local time_diff=$((current_time - last_request))
        
        if [ $time_diff -lt $interval ]; then
            sleep $((interval - time_diff))
        fi
    fi
    date +%s > "$last_request_file"
}

# Main
main() {
    # Load configuration
    if [ -f "config.conf" ]; then
        source "config.conf"
    fi

    # Start timing
    start_time

    print_banner
    check_requirements
    
    # Try to resume previous scan
    if resume_scan; then
        echo -e "${GREEN}[+] Resuming from previous state${NC}"
    fi
    
    # Default values
    output_dir="reconnaissance_results"
    ports="top-1000"
    threads=50
    timeout=30
    enable_nmap=false
    enable_vuln_scan=false
    nmap_options="-sV -sC"
    quick_scan=false
    enable_full_scan=false
    
    # Parse arguments
    while getopts "d:o:p:t:w:nsvqfh" opt; do
        case $opt in
            d) domain="$OPTARG" ;;
            o) output_dir="$OPTARG" ;;
            p) ports="$OPTARG" ;;
            t) threads="$OPTARG" ;;
            w) timeout="$OPTARG" ;;
            v) enable_vuln_scan=true ;;
            n) enable_nmap=true ;;
            s) nmap_options="$OPTARG" ;;
            q) quick_scan=true ;;
            f) enable_full_scan=true ;;
            h) show_help ;;
            *) show_help ;;
        esac
    done
    
    # Check if domain is provided
    if [ -z "$domain" ]; then
        echo -e "${RED}[-] Please provide a target domain${NC}"
        show_help
    fi
    
    # Set scan parameters based on mode
    if [ "$quick_scan" = true ]; then
        ports="$QUICK_PORTS"
        threads=150
        timeout=10
        enable_nmap=false
        enable_vuln_scan=false
    fi
    
    # Start reconnaissance
    setup_workspace
    echo -e "\n${BLUE}[*] Target: ${YELLOW}$domain${NC}"
    echo -e "${BLUE}[*] Output Directory: ${YELLOW}$output_dir${NC}"
    echo -e "${BLUE}[*] Ports: ${YELLOW}$ports${NC}"
    echo -e "${BLUE}[*] Threads: ${YELLOW}$threads${NC}"
    echo -e "${BLUE}[*] Timeout: ${YELLOW}${timeout}s${NC}\n"
    
    # Run scans in parallel where possible
    run_parallel $MAX_THREADS \
        "enumerate_subdomains" \
        "resolve_dns" \
        "probe_http"
    
    # Show progress
    show_progress 2 "Processing"
    
    # Rate limit intensive operations
    rate_limit $RATE_LIMIT_REQUESTS $RATE_LIMIT_INTERVAL
    
    port_scan
    
    # Run vulnerability scans if enabled
    if [ "$enable_vuln_scan" = true ]; then
        vulnerability_scan
    fi
    
    # Generate report
    generate_report
    
    # Summary
    echo -e "\n${GREEN}[+] Reconnaissance Summary:${NC}"
    echo -e "${BLUE}[*] Subdomains found: ${YELLOW}$(wc -l < "$output_dir/all_subdomains.txt")${NC}"
    echo -e "${BLUE}[*] Active domains: ${YELLOW}$(wc -l < "$output_dir/active/active_domains.txt")${NC}"
    echo -e "${BLUE}[*] HTTP services: ${YELLOW}$(wc -l < "$output_dir/active/http_probe.txt")${NC}"
    echo -e "${BLUE}[*] Open ports: ${YELLOW}$(wc -l < "$output_dir/active/port_scan/naabu_ports.txt")${NC}"
    if [ "$enable_vuln_scan" = true ]; then
        echo -e "${BLUE}[*] Vulnerability scans completed:${NC}"
        echo -e "  ${YELLOW}- Nikto web scans: $(ls -1 "$output_dir/vulnerabilities/nikto_"*.txt 2>/dev/null | wc -l)${NC}"
        echo -e "  ${YELLOW}- Nmap vuln scans: $(ls -1 "$output_dir/vulnerabilities/nmap_vuln_"*.txt 2>/dev/null | wc -l)${NC}"
    fi
    echo -e "\n${GREEN}[+] Reconnaissance completed! Results saved in: $output_dir${NC}"
    
    end_time

    # Save final state
    save_state "completed"
}

# Run main function
main "$@"
