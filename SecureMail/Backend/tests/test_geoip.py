"""
Unit tests for the GeoIP & SMTP Hop Trajectory Engine (Phase 2.1).
"""

import pytest
from app.services.geoip_service import (
    is_private_or_reserved_ip,
    parse_header_timestamp,
    geolocate_ip,
    analyze_hop_trajectory
)
from app.services.email_parser import audit_received_hops


def test_private_ip_detection():
    """Verify accurate classification of RFC-1918 and loopback IP addresses."""
    assert is_private_or_reserved_ip("192.168.1.1") is True
    assert is_private_or_reserved_ip("10.200.1.50") is True
    assert is_private_or_reserved_ip("172.16.5.20") is True
    assert is_private_or_reserved_ip("127.0.0.1") is True
    assert is_private_or_reserved_ip("8.8.8.8") is False
    assert is_private_or_reserved_ip("185.234.218.47") is False


def test_known_cloud_providers_geolocated():
    """Verify known enterprise mail providers resolve to realistic geographic hubs."""
    google_geo = geolocate_ip("209.85.218.41", host_hint="mail-wm1-f41.google.com")
    assert google_geo["country_code"] == "US"
    assert google_geo["isp"] == "Google LLC"
    assert google_geo["latitude"] != 0.0

    ms_geo = geolocate_ip("40.107.240.50", host_hint="nam04-sn1-obe.outbound.protection.outlook.com")
    assert ms_geo["country_code"] == "US"
    assert ms_geo["isp"] == "Microsoft Corporation"

    proton_geo = geolocate_ip("185.70.40.101", host_hint="mail.protonmail.ch")
    assert proton_geo["country_code"] == "CH"
    assert proton_geo["city"] == "Geneva"


def test_private_ip_geolocation():
    """Verify private IPs return LAN indicator and zero coordinates."""
    lan_geo = geolocate_ip("192.168.0.10")
    assert lan_geo["is_private"] is True
    assert lan_geo["country_code"] == "LAN"


def test_timestamp_parsing():
    """Verify RFC-2822 header timestamp extraction."""
    hdr = "from mail.sender.com by mx.google.com; Wed, 12 Aug 2026 10:15:30 +0000"
    dt = parse_header_timestamp(hdr)
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 8
    assert dt.day == 12
    assert dt.hour == 10
    assert dt.minute == 15


def test_multi_hop_trajectory_analysis():
    """Verify chronological trajectory mapping, latency deltas, and coordinates."""
    # Top = Final Destination, Bottom = Originating sender
    received_headers = [
        "Received: from relay-us.google.com (mail.google.com [209.85.218.41]) by mx.customer.de with ESMTP; Wed, 12 Aug 2026 12:00:25 +0000",
        "Received: from gateway.eu.fastmail.com (fastmail.com [66.111.4.10]) by relay-us.google.com with ESMTP; Wed, 12 Aug 2026 12:00:15 +0000",
        "Received: from client.evil.ru (mail.evil.ru [185.234.218.47]) by gateway.eu.fastmail.com with ESMTP; Wed, 12 Aug 2026 12:00:00 +0000"
    ]
    
    trajectory = analyze_hop_trajectory(received_headers)
    assert trajectory["total_hops"] == 3
    assert trajectory["total_transit_seconds"] == 25
    assert len(trajectory["trajectory_coordinates"]) >= 2
    
    # Hop 1 should be the originating sender (Bottom of raw headers)
    hop1 = trajectory["hops"][0]
    assert hop1["hop_number"] == 1
    assert hop1["is_origin"] is True
    assert hop1["ip"] == "185.234.218.47"
    
    # Hop 3 should be the destination MX (Top of raw headers)
    hop3 = trajectory["hops"][2]
    assert hop3["hop_number"] == 3
    assert hop3["is_destination"] is True
    assert hop3["ip"] == "209.85.218.41"
    assert hop3["delay_seconds"] == 10  # 12:00:25 - 12:00:15


def test_hop_anomalies_high_latency_and_long_chain():
    """Verify high latency delays and excessively long chains trigger anomalies."""
    headers = [
        f"Received: from hop{i}.com ([198.51.100.{i}]) by hop{i+1}.com; Wed, 12 Aug 2026 {12+i//60:02d}:{i%60:02d}:00 +0000"
        for i in range(7)
    ]
    trajectory = analyze_hop_trajectory(headers)
    assert trajectory["total_hops"] == 7
    assert any("long relay chain" in a.lower() for a in trajectory["anomalies"])


def test_audit_received_hops_integration():
    """Verify audit_received_hops returns backward-compatible keys and enriched trajectory."""
    headers = [
        "Received: from mail.evil.ru (mail.evil.ru [185.234.218.47]) by mx.example.com with ESMTP id abc123",
        "Received: from 192.168.1.50 by mail.evil.ru with ESMTP"
    ]
    audit = audit_received_hops(headers)
    assert audit["hop_count"] == 2
    assert len(audit["hops"]) == 2
    assert audit["hops"][0]["ip"] == "185.234.218.47"
    assert "latitude" in audit["hops"][0]
    assert "trajectory" in audit
    assert audit["trajectory"]["total_hops"] == 2
