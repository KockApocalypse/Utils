#!/bin/bash

# =============================================================================
# Comprehensive Nmap Scanner Script
# Author: AxelChan/Claude
# Description: Automated nmap scanning with multiple scan types
# MIT License
# =============================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 打印带颜色的输出
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_scan() {
    echo -e "${PURPLE}[SCAN]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Usage: $0 <IP_ADDRESS> [OPTIONS]

Description:
    Comprehensive nmap scanner that performs multiple scan types

Arguments:
    IP_ADDRESS    Target IP address to scan

Options:
    -h, --help    Show this help message
    -v, --verbose Enable verbose output
    -q, --quiet   Quiet mode (minimal output)
    -o, --output  Output directory (default: current directory)

Examples:
    $0 192.168.1.100
    $0 10.0.0.1 -v
    $0 target.com --output ./scan_results

Scan Types:
    1. Port Discovery Scan  (-p-)
    2. Service Version Scan (-sT -sV -sC)
    3. Vulnerability Scan   (--script=vuln)
    4. UDP Scan            (-sU)

EOF
}

# 检查依赖
check_dependencies() {
    if ! command -v nmap &> /dev/null; then
        print_error "nmap is not installed. Please install nmap first."
        exit 1
    fi
}

# 验证IP地址格式
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    elif [[ $ip =~ ^[a-zA-Z0-9.-]+$ ]]; then
        # 域名格式，简单验证
        return 0
    else
        return 1
    fi
}

# 检查目标是否在线
check_host_alive() {
    local target=$1
    print_status "Checking if target $target is alive..."
    
    if ping -c 1 -W 3 "$target" &> /dev/null; then
        print_success "Target $target is responding to ping"
        return 0
    else
        print_warning "Target $target is not responding to ping (may still be scannable)"
        return 1
    fi
}

# 创建输出目录结构
setup_output() {
    local target=$1
    local base_dir="$OUTPUT_DIR"
    
    # 创建基础目录
    TARGET_DIR="${base_dir}/nmap_scan_${target}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$TARGET_DIR"
    
    print_status "Created output directory: $TARGET_DIR"
    
    # 创建日志文件
    LOG_FILE="$TARGET_DIR/scan.log"
    touch "$LOG_FILE"
}

# 记录日志
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
    
    if [[ $VERBOSE == true ]]; then
        echo -e "${CYAN}[LOG]${NC} $message"
    fi
}

# 显示进度条
show_progress() {
    local current=$1
    local total=$2
    local desc="$3"
    local percent=$((current * 100 / total))
    local completed=$((current * 30 / total))
    
    printf "\r${BLUE}[%s]${NC} [" "$desc"
    for ((i=0; i<completed; i++)); do printf "="; done
    for ((i=completed; i<30; i++)); do printf " "; done
    printf "] %d%% (%d/%d)" "$percent" "$current" "$total"
}

# 步骤1：端口发现扫描
port_discovery_scan() {
    local target=$1
    local output_file="$TARGET_DIR/01_port_discovery.txt"
    local xml_file="$TARGET_DIR/01_port_discovery.xml"
    
    print_scan "Step 1/4: Port Discovery Scan"
    log_message "Starting port discovery scan for $target"
    
    # 显示扫描命令
    if [[ $VERBOSE == true ]]; then
        print_status "Command: nmap -p- --open -T4 --min-rate=1000 -oN $output_file -oX $xml_file $target"
    fi
    
    # 执行扫描
    if [[ $QUIET == false ]]; then
        nmap -p- --open -T4 --min-rate=1000 \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" | while IFS= read -r line; do
            echo "$line"
            echo "$line" >> "$LOG_FILE"
        done
    else
        nmap -p- --open -T4 --min-rate=1000 \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" >> "$LOG_FILE" 2>&1
    fi
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Port discovery scan completed"
        log_message "Port discovery scan completed successfully"
        
        # 提取开放端口
        OPEN_PORTS=$(grep -E "^[0-9]+/tcp.*open" "$output_file" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        
        if [[ -n $OPEN_PORTS ]]; then
            print_status "Open ports found: $OPEN_PORTS"
            log_message "Open ports: $OPEN_PORTS"
            echo "$OPEN_PORTS" > "$TARGET_DIR/open_ports.txt"
            return 0
        else
            print_warning "No open ports found"
            log_message "No open ports detected"
            return 1
        fi
    else
        print_error "Port discovery scan failed"
        log_message "Port discovery scan failed with exit code $exit_code"
        return 1
    fi
}

# 步骤2：服务版本扫描
service_version_scan() {
    local target=$1
    local output_file="$TARGET_DIR/02_service_version.txt"
    local xml_file="$TARGET_DIR/02_service_version.xml"
    
    if [[ -z $OPEN_PORTS ]]; then
        print_warning "Skipping service version scan - no open ports found"
        return 1
    fi
    
    print_scan "Step 2/4: Service Version Scan"
    log_message "Starting service version scan for ports: $OPEN_PORTS"
    
    if [[ $VERBOSE == true ]]; then
        print_status "Command: nmap -sT -sV -sC -p $OPEN_PORTS -oN $output_file -oX $xml_file $target"
    fi
    
    # 执行版本扫描
    if [[ $QUIET == false ]]; then
        nmap -sT -sV -sC -p "$OPEN_PORTS" \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" | while IFS= read -r line; do
            echo "$line"
            echo "$line" >> "$LOG_FILE"
        done
    else
        nmap -sT -sV -sC -p "$OPEN_PORTS" \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" >> "$LOG_FILE" 2>&1
    fi
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Service version scan completed"
        log_message "Service version scan completed successfully"
        return 0
    else
        print_error "Service version scan failed"
        log_message "Service version scan failed with exit code $exit_code"
        return 1
    fi
}

# 步骤3：漏洞脚本扫描
vulnerability_scan() {
    local target=$1
    local output_file="$TARGET_DIR/03_vulnerability_scan.txt"
    local xml_file="$TARGET_DIR/03_vulnerability_scan.xml"
    
    if [[ -z $OPEN_PORTS ]]; then
        print_warning "Skipping vulnerability scan - no open ports found"
        return 1
    fi
    
    print_scan "Step 3/4: Vulnerability Scan"
    log_message "Starting vulnerability scan for ports: $OPEN_PORTS"
    
    if [[ $VERBOSE == true ]]; then
        print_status "Command: nmap --script=vuln -p $OPEN_PORTS -oN $output_file -oX $xml_file $target"
    fi
    
    # 执行漏洞扫描
    if [[ $QUIET == false ]]; then
        nmap --script=vuln -p "$OPEN_PORTS" \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" | while IFS= read -r line; do
            echo "$line"
            echo "$line" >> "$LOG_FILE"
        done
    else
        nmap --script=vuln -p "$OPEN_PORTS" \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" >> "$LOG_FILE" 2>&1
    fi
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "Vulnerability scan completed"
        log_message "Vulnerability scan completed successfully"
        return 0
    else
        print_error "Vulnerability scan failed"
        log_message "Vulnerability scan failed with exit code $exit_code"
        return 1
    fi
}

# 步骤4：UDP扫描
udp_scan() {
    local target=$1
    local output_file="$TARGET_DIR/04_udp_scan.txt"
    local xml_file="$TARGET_DIR/04_udp_scan.xml"
    
    print_scan "Step 4/4: UDP Scan"
    log_message "Starting UDP scan for $target"
    
    if [[ $VERBOSE == true ]]; then
        print_status "Command: nmap -sU --top-ports 1000 -T4 -oN $output_file -oX $xml_file $target"
    fi
    
    # 执行UDP扫描（扫描常见的1000个UDP端口）
    if [[ $QUIET == false ]]; then
        nmap -sU --top-ports 1000 -T4 \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" | while IFS= read -r line; do
            echo "$line"
            echo "$line" >> "$LOG_FILE"
        done
    else
        nmap -sU --top-ports 1000 -T4 \
             -oN "$output_file" \
             -oX "$xml_file" \
             "$target" >> "$LOG_FILE" 2>&1
    fi
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -eq 0 ]]; then
        print_success "UDP scan completed"
        log_message "UDP scan completed successfully"
        return 0
    else
        print_error "UDP scan failed"
        log_message "UDP scan failed with exit code $exit_code"
        return 1
    fi
}

# 生成扫描报告摘要
generate_summary() {
    local target=$1
    local summary_file="$TARGET_DIR/00_scan_summary.txt"
    
    print_status "Generating scan summary..."
    
    cat > "$summary_file" << EOF
=============================================================================
Nmap Scan Summary Report
=============================================================================
Target: $target
Scan Date: $(date '+%Y-%m-%d %H:%M:%S')
Output Directory: $TARGET_DIR

=== SCAN RESULTS ===
EOF
    
    # TCP端口摘要
    if [[ -f "$TARGET_DIR/01_port_discovery.txt" ]]; then
        echo "" >> "$summary_file"
        echo "TCP Ports:" >> "$summary_file"
        grep -E "^[0-9]+/tcp.*open" "$TARGET_DIR/01_port_discovery.txt" >> "$summary_file" || echo "No open TCP ports found" >> "$summary_file"
    fi
    
    # UDP端口摘要
    if [[ -f "$TARGET_DIR/04_udp_scan.txt" ]]; then
        echo "" >> "$summary_file"
        echo "UDP Ports:" >> "$summary_file"
        grep -E "^[0-9]+/udp.*open" "$TARGET_DIR/04_udp_scan.txt" >> "$summary_file" || echo "No open UDP ports found" >> "$summary_file"
    fi
    
    # 服务版本摘要
    if [[ -f "$TARGET_DIR/02_service_version.txt" ]]; then
        echo "" >> "$summary_file"
        echo "=== SERVICE DETECTION ===" >> "$summary_file"
        grep -A 50 "SERVICE VERSION" "$TARGET_DIR/02_service_version.txt" | head -20 >> "$summary_file" 2>/dev/null || echo "Service version data not found" >> "$summary_file"
    fi
    
    # 漏洞摘要
    if [[ -f "$TARGET_DIR/03_vulnerability_scan.txt" ]]; then
        echo "" >> "$summary_file"
        echo "=== VULNERABILITIES ===" >> "$summary_file"
        grep -E "(VULNERABLE|CVE-)" "$TARGET_DIR/03_vulnerability_scan.txt" >> "$summary_file" || echo "No vulnerabilities detected" >> "$summary_file"
    fi
    
    cat >> "$summary_file" << EOF

=== FILES GENERATED ===
01_port_discovery.txt     - TCP port discovery scan
01_port_discovery.xml     - TCP port discovery (XML format)
02_service_version.txt    - Service version detection
02_service_version.xml    - Service version (XML format)  
03_vulnerability_scan.txt - Vulnerability script scan
03_vulnerability_scan.xml - Vulnerability scan (XML format)
04_udp_scan.txt          - UDP port scan
04_udp_scan.xml          - UDP scan (XML format)
scan.log                 - Detailed scan log
open_ports.txt           - List of open ports

=============================================================================
EOF
    
    print_success "Scan summary generated: $summary_file"
    
    # 显示简要摘要
    if [[ $QUIET == false ]]; then
        echo ""
        print_status "=== QUICK SUMMARY ==="
        if [[ -n $OPEN_PORTS ]]; then
            print_success "Open TCP ports: $OPEN_PORTS"
        else
            print_warning "No open TCP ports found"
        fi
        
        if [[ -f "$TARGET_DIR/04_udp_scan.txt" ]]; then
            local udp_ports=$(grep -E "^[0-9]+/udp.*open" "$TARGET_DIR/04_udp_scan.txt" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
            if [[ -n $udp_ports ]]; then
                print_success "Open UDP ports: $udp_ports"
            fi
        fi
        
        print_status "All results saved to: $TARGET_DIR"
    fi
}

# 清理和退出处理
cleanup() {
    if [[ -n $TARGET_DIR ]] && [[ -f "$LOG_FILE" ]]; then
        log_message "Scan process interrupted or completed"
    fi
}

trap cleanup EXIT INT TERM

# 主函数
main() {
    local target=""
    
    # 参数解析
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -*)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [[ -z $target ]]; then
                    target="$1"
                else
                    print_error "Multiple targets not supported"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # 检查必要参数
    if [[ -z $target ]]; then
        print_error "Target IP address is required"
        show_help
        exit 1
    fi
    
    # 验证IP地址
    if ! validate_ip "$target"; then
        print_error "Invalid IP address or hostname format: $target"
        exit 1
    fi
    
    # 显示开始信息
    echo ""
    print_status "=== Comprehensive Nmap Scanner ==="
    print_status "Target: $target"
    print_status "Start time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # 检查依赖
    check_dependencies
    
    # 检查目标是否在线
    check_host_alive "$target"
    
    # 设置输出目录
    setup_output "$target"
    
    log_message "Starting comprehensive scan for $target"
    
    # 执行扫描步骤
    local start_time=$(date +%s)
    local failed_scans=0
    
    # Step 1: 端口发现
    show_progress 1 4 "Port Discovery"
    if ! port_discovery_scan "$target"; then
        ((failed_scans++))
    fi
    echo ""
    
    # Step 2: 服务版本扫描
    show_progress 2 4 "Service Version"
    if ! service_version_scan "$target"; then
        ((failed_scans++))
    fi
    echo ""
    
    # Step 3: 漏洞扫描
    show_progress 3 4 "Vulnerability Scan"
    if ! vulnerability_scan "$target"; then
        ((failed_scans++))
    fi
    echo ""
    
    # Step 4: UDP扫描
    show_progress 4 4 "UDP Scan"
    if ! udp_scan "$target"; then
        ((failed_scans++))
    fi
    echo ""
    
    # 计算总用时
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    local minutes=$((total_time / 60))
    local seconds=$((total_time % 60))
    
    # 生成报告摘要
    generate_summary "$target"
    
    # 显示完成信息
    echo ""
    print_success "=== SCAN COMPLETED ==="
    print_status "Total time: ${minutes}m ${seconds}s"
    
    if [[ $failed_scans -eq 0 ]]; then
        print_success "All scans completed successfully"
        log_message "All scans completed successfully in ${total_time}s"
    else
        print_warning "$failed_scans scan(s) failed - check logs for details"
        log_message "$failed_scans scan(s) failed"
    fi
    
    print_status "Results directory: $TARGET_DIR"
    echo ""
}

# 默认变量
VERBOSE=false
QUIET=false
OUTPUT_DIR="."
OPEN_PORTS=""
TARGET_DIR=""
LOG_FILE=""

# 检查是否以root用户运行（UDP扫描需要）
if [[ $EUID -ne 0 ]] && [[ "$*" != *"-h"* ]] && [[ "$*" != *"--help"* ]]; then
    print_warning "Some scans (like UDP) may require root privileges"
    print_status "Consider running with sudo for complete functionality"
fi

# 运行主函数
main "$@"
