#!/bin/bash

entry_port_list() {
    local count="${1:?instance count is required}"
    local instance
    local ports=""
    for instance in $(seq 1 "$count"); do
        ports="${ports:+$ports,}$(proxy_instance_port "$instance")"
    done
    printf '%s\n' "$ports"
}

entry_ufw_port_spec() {
    local count="${1:?instance count is required}"
    local final_port
    final_port="$(proxy_instance_port "$count")"
    if [ "$count" = 1 ]; then
        printf '80\n'
    else
        printf '80:%s\n' "$final_port"
    fi
}

entry_firewalld_port_spec() {
    local count="${1:?instance count is required}"
    local final_port
    final_port="$(proxy_instance_port "$count")"
    if [ "$count" = 1 ]; then
        printf '80\n'
    else
        printf '80-%s\n' "$final_port"
    fi
}

configure_ufw() {
    local count="$1"
    local ports
    local port_spec
    ports="$(entry_port_list "$count")"
    port_spec="$(entry_ufw_port_spec "$count")"
    install -d -m 0755 /etc/ufw/applications.d
    cat >/etc/ufw/applications.d/ppaass-proxy-entry <<EOF
[PPAASS Proxy Entry]
title=PPAASS Proxy Entry
description=TCP and encrypted UDP listeners managed by the PPAASS deploy workflow
ports=$port_spec/tcp|$port_spec/udp
EOF
    ufw app update "PPAASS Proxy Entry"
    ufw allow "PPAASS Proxy Entry"
    echo "UFW allows Proxy Entry TCP and UDP ports: $ports"
}

configure_firewalld() {
    local count="$1"
    local port_spec
    port_spec="$(entry_firewalld_port_spec "$count")"
    install -d -m 0755 /etc/firewalld/services
    {
        printf '%s\n' '<?xml version="1.0" encoding="utf-8"?>'
        printf '%s\n' '<service>'
        printf '%s\n' '  <short>PPAASS Proxy Entry</short>'
        printf '%s\n' '  <description>PPAASS Proxy Entry listeners</description>'
        printf '  <port protocol="tcp" port="%s"/>\n' "$port_spec"
        printf '  <port protocol="udp" port="%s"/>\n' "$port_spec"
        printf '%s\n' '</service>'
    } >/etc/firewalld/services/ppaass-proxy-entry.xml
    firewall-cmd --reload
    firewall-cmd --permanent --add-service=ppaass-proxy-entry
    firewall-cmd --reload
    echo "firewalld allows Proxy Entry TCP and UDP ports: $(entry_port_list "$count")"
}

configure_entry_firewall() {
    local count="$1"
    if command -v ufw >/dev/null 2>&1 && \
       LC_ALL=C ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null; then
        configure_ufw "$count"
    elif command -v firewall-cmd >/dev/null 2>&1 && \
         firewall-cmd --state >/dev/null 2>&1; then
        configure_firewalld "$count"
    else
        echo "No active supported host firewall detected; no host firewall rule was changed."
        echo "Any external cloud firewall must allow the same TCP and UDP ports: $(entry_port_list "$count")"
    fi
}
