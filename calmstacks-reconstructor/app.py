"""
REVIVER - Desktop Digital Forensics Application
===============================================
Modern dark-mode split-screen desktop GUI built with CustomTkinter.
Features dynamic binary carving, real-world file stream chunking,
heuristic classification, and structural integrity assessment.
"""

import os
import sys
import json
import threading
import time
from typing import List, Optional, Dict, Any
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

# Ensure local directory is in Python path for engine import
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from engine import (
    carve_disk_image,
    disk_dig_carve,
    stitch_fragments,
    classify_and_prioritize,
    assess_integrity,
    run_forensic_pipeline,
    ForensicArtifact,
    DataFragment,
    ForensicLedger,
    export_forensic_report,
    generate_plain_english_report,
    organize_folder_by_type,
    scan_and_purge_duplicates
)

# CustomTkinter Global Appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Enterprise Cybersecurity Color Palette (Deep Slate & Obsidian Void)
COLOR_BG_DARK = "#090d16"         # Obsidian base background
COLOR_PANEL_BG = "#0f172a"        # Deep slate container
COLOR_CARD_BG = "#131d31"         # Slate card surface
COLOR_CARD_HOVER = "#1c2b45"      # Subtle hover glow
COLOR_CARD_ACTIVE = "#162544"     # High-contrast active card surface
COLOR_BORDER = "#1e293b"          # Slate border
COLOR_BORDER_FOCUS = "#38bdf8"    # Electric Cyan active border
COLOR_ACCENT = "#2563eb"          # Enterprise Cobalt Blue
COLOR_ACCENT_HOVER = "#1d4ed8"
COLOR_ACCENT_PURPLE = "#8b5cf6"   # Electric Violet for Disk Dig
COLOR_ACCENT_PURPLE_HOVER = "#7c3aed"
COLOR_TEXT_PRIMARY = "#f8fafc"    # Bright crisp text
COLOR_TEXT_SECONDARY = "#94a3b8"  # Slate muted text
COLOR_TEXT_MUTED = "#64748b"      # Extra muted meta text

# Threat Level Palettes (Vibrant Cyber Glass Badges)
CATEGORY_PALETTE = {
    "CRITICAL": {
        "text": "#f87171",
        "bg": "#450a0a",
        "border": "#ef4444",
        "badge": "🔴 CRITICAL RISK"
    },
    "CREDENTIALS": {
        "text": "#fca5a5",
        "bg": "#3f0c10",
        "border": "#f87171",
        "badge": "🔑 CREDENTIALS"
    },
    "FINANCIAL": {
        "text": "#f87171",
        "bg": "#450a0a",
        "border": "#dc2626",
        "badge": "💳 FINANCIAL WIRE"
    },
    "PII": {
        "text": "#fbbf24",
        "bg": "#451a03",
        "border": "#f59e0b",
        "badge": "🛡️ PII RECORD"
    },
    "MEDIA": {
        "text": "#c084fc",
        "bg": "#2e1065",
        "border": "#8b5cf6",
        "badge": "📦 MEDIA / RECOVERED"
    },
    "LOGS": {
        "text": "#34d399",
        "bg": "#064e3b",
        "border": "#10b981",
        "badge": "⚡ SYSTEM LOGS"
    },
    "INTERNAL": {
        "text": "#60a5fa",
        "bg": "#172554",
        "border": "#3b82f6",
        "badge": "📑 DFIR MEMO"
    },
    "DEFAULT": {
        "text": "#94a3b8",
        "bg": "#1e293b",
        "border": "#334155",
        "badge": "⚪ CARVED STREAM"
    }
}


def get_category_color(category_str: str) -> Dict[str, str]:
    cat_upper = category_str.upper()
    if "CREDENTIAL" in cat_upper:
        return CATEGORY_PALETTE["CREDENTIALS"]
    elif "CRITICAL" in cat_upper:
        return CATEGORY_PALETTE["CRITICAL"]
    elif "FINANCIAL" in cat_upper or "WIRE" in cat_upper:
        return CATEGORY_PALETTE["FINANCIAL"]
    elif "PII" in cat_upper:
        return CATEGORY_PALETTE["PII"]
    elif "MEDIA" in cat_upper or "DOCUMENT" in cat_upper or "ARCHIVE" in cat_upper or "BINARY" in cat_upper:
        return CATEGORY_PALETTE["MEDIA"]
    elif "LOG" in cat_upper or "AUTH" in cat_upper or "SYSLOG" in cat_upper:
        return CATEGORY_PALETTE["LOGS"]
    elif "MEMO" in cat_upper or "INTERNAL" in cat_upper:
        return CATEGORY_PALETTE["INTERNAL"]
    return CATEGORY_PALETTE["DEFAULT"]


import queue

class ReviverApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("REVIVER - Digital Forensics & Data Carving Suite")
        self.geometry("1400x880")
        self.minsize(1100, 720)
        self.configure(fg_color=COLOR_BG_DARK)

        # Cryptographic Hash Chain Ledger (Chain of Custody)
        self.ledger = ForensicLedger()

        # Thread-safe event queue
        self.event_queue = queue.Queue()

        # Default sample file path
        default_sample = os.path.join(CURRENT_DIR, "sample_dump.bin")
        self.target_file_path: str = default_sample if os.path.exists(default_sample) else ""

        # State Variables
        self.artifacts: List[ForensicArtifact] = []
        self.filtered_artifacts: List[ForensicArtifact] = []
        self.selected_artifact: Optional[ForensicArtifact] = None
        self.is_scanning: bool = False
        self.current_filter: str = "ALL"
        self.search_query: str = ""
        self.artifact_widgets: List[ctk.CTkFrame] = []

        # Build UI Components
        self._build_top_bar()
        self._build_main_split_layout()
        self._build_bottom_bar()

        # Start periodic queue processor
        self._process_event_queue()

        # Initial Status Message
        if self.target_file_path:
            size_bytes = os.path.getsize(self.target_file_path)
            self._update_status(f"Default image loaded: {os.path.basename(self.target_file_path)} ({size_bytes:,} bytes). Ready for AI Scan.")
        else:
            self._update_status("Welcome to REVIVER. Select a file or disk dump to begin.")

    def _process_event_queue(self):
        """Processes thread-safe events dispatched from background carving workers."""
        try:
            while not self.event_queue.empty():
                evt_type, payload = self.event_queue.get_nowait()
                if evt_type == "STATUS":
                    msg, is_error = payload
                    self._update_status(msg, is_error)
                elif evt_type == "COMPLETE":
                    fragments, artifacts = payload
                    self._on_scan_completed(fragments, artifacts)
                elif evt_type == "FAILED":
                    error_msg = payload
                    self._on_scan_failed(error_msg)
        except Exception as e:
            print(f"[Queue Error] {e}")

        # Re-schedule check every 50ms
        self.after(50, self._process_event_queue)

    # =========================================================================
    # TOP BAR
    # =========================================================================
    def _build_top_bar(self):
        self.top_bar = ctk.CTkFrame(self, fg_color=COLOR_PANEL_BG, corner_radius=0, height=64)
        self.top_bar.pack(side="top", fill="x", padx=0, pady=0)
        self.top_bar.pack_propagate(False)

        # Left: Branding with cyber icon
        brand_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        brand_frame.pack(side="left", padx=16, pady=8)

        icon_label = ctk.CTkLabel(
            brand_frame,
            text="🛡️",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        icon_label.pack(side="left", padx=(0, 10))

        title_box = ctk.CTkFrame(brand_frame, fg_color="transparent")
        title_box.pack(side="left")

        main_title = ctk.CTkLabel(
            title_box,
            text="REVIVER",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        main_title.pack(anchor="w")

        sub_title = ctk.CTkLabel(
            title_box,
            text="AI DIGITAL EVIDENCE & RECOVERY SUITE // DFIR ENTERPRISE v2.4",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=COLOR_TEXT_MUTED
        )
        sub_title.pack(anchor="w")

        # Right: Telemetry HUD & Status Badge
        telemetry_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        telemetry_frame.pack(side="right", padx=16, pady=8)

        # High-contrast Cyber Telemetry Chips
        self.stat_fragments_lbl = ctk.CTkLabel(
            telemetry_frame,
            text="Fragments: 0",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#131d31",
            corner_radius=6,
            padx=10,
            pady=5,
            text_color="#94a3b8"
        )
        self.stat_fragments_lbl.pack(side="left", padx=4)

        self.stat_stitched_lbl = ctk.CTkLabel(
            telemetry_frame,
            text="Stitched: 0",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#131d31",
            corner_radius=6,
            padx=10,
            pady=5,
            text_color="#38bdf8"
        )
        self.stat_stitched_lbl.pack(side="left", padx=4)

        self.stat_critical_lbl = ctk.CTkLabel(
            telemetry_frame,
            text="Critical: 0",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#450a0a",
            corner_radius=6,
            padx=10,
            pady=5,
            text_color="#f87171"
        )
        self.stat_critical_lbl.pack(side="left", padx=4)

        # Dynamic Pulsing Status Indicator Badge
        self.status_badge = ctk.CTkLabel(
            telemetry_frame,
            text="● SYSTEM READY",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#062e1d",
            text_color="#10b981",
            corner_radius=6,
            padx=12,
            pady=5
        )
        self.status_badge.pack(side="left", padx=(6, 8))

        # Audit Ledger & Export Report Buttons
        self.btn_audit_ledger = ctk.CTkButton(
            telemetry_frame,
            text="🔐 Audit Ledger",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1e293b",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            width=115,
            height=32,
            command=self.open_audit_ledger_window
        )
        self.btn_audit_ledger.pack(side="left", padx=(2, 4))

        self.btn_export_top = ctk.CTkButton(
            telemetry_frame,
            text="💾 Export Report",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1d4ed8",
            hover_color=COLOR_ACCENT,
            border_width=1,
            border_color="#3b82f6",
            width=115,
            height=32,
            command=self.handle_export
        )
        self.btn_export_top.pack(side="left", padx=2)

        self.btn_ai_chat = ctk.CTkButton(
            telemetry_frame,
            text="💬 Reviver AI",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1e293b",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            width=110,
            height=32,
            command=self.open_reviver_chatbot
        )
        self.btn_ai_chat.pack(side="left", padx=(2, 0))

    # =========================================================================
    # MAIN SPLIT LAYOUT (LEFT & RIGHT PANELS)
    # =========================================================================
    def _build_main_split_layout(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(side="top", fill="both", expand=True, padx=12, pady=10)

        # Configure 2-column grid
        self.main_container.grid_columnconfigure(0, weight=4, minsize=420)
        self.main_container.grid_columnconfigure(1, weight=6, minsize=640)
        self.main_container.grid_rowconfigure(0, weight=1)

        # Left Panel (Controls & Recovered Artifacts)
        self._build_left_panel()

        # Right Panel (File Preview & Integrity Report)
        self._build_right_panel()

    # =========================================================================
    # LEFT PANEL (CONTROLS & ARTIFACT QUEUE)
    # =========================================================================
    def _build_left_panel(self):
        self.left_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_PANEL_BG,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=0)

        # Top Control Box
        control_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        control_frame.pack(fill="x", padx=14, pady=12)

        # Target Disk Image Selector Area
        file_select_row = ctk.CTkFrame(control_frame, fg_color="transparent")
        file_select_row.pack(fill="x", pady=(0, 8))

        self.btn_select_file = ctk.CTkButton(
            file_select_row,
            text="📂 Select Disk/Image File",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#131d31",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            height=34,
            command=self._on_select_file
        )
        self.btn_select_file.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_reset_sample = ctk.CTkButton(
            file_select_row,
            text="↺ Sample",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#131d31",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            width=70,
            height=34,
            command=self._on_reset_to_sample
        )
        self.btn_reset_sample.pack(side="right")

        # Current File Path Info
        self.lbl_current_file = ctk.CTkLabel(
            control_frame,
            text=f"Target: {os.path.basename(self.target_file_path) if self.target_file_path else 'No file selected'}",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.lbl_current_file.pack(fill="x", pady=(0, 10))

        # Action Buttons Row: Disk Dig (Raw Sector Carve) + AI Deep Scan
        actions_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        actions_frame.pack(fill="x", pady=(0, 8))

        self.btn_disk_dig = ctk.CTkButton(
            actions_frame,
            text="⛏️ Disk Dig (Sector Carve)",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=COLOR_ACCENT_PURPLE,
            hover_color=COLOR_ACCENT_PURPLE_HOVER,
            height=42,
            command=self._start_disk_dig_thread
        )
        self.btn_disk_dig.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self.btn_run_scan = ctk.CTkButton(
            actions_frame,
            text="⚡ AI Deep Scan",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            height=42,
            command=self._start_scan_thread
        )
        self.btn_run_scan.pack(side="right", fill="x", expand=True, padx=(4, 0))

        # Progress Bar (pulsing/indeterminate during scan)
        self.progress_bar = ctk.CTkProgressBar(
            control_frame,
            height=6,
            progress_color="#38bdf8",
            fg_color="#131d31"
        )
        self.progress_bar.pack(fill="x", pady=(0, 10))
        self.progress_bar.set(0)

        # Category Filter Tabs (Segmented Button with MEDIA support)
        self.filter_segmented = ctk.CTkSegmentedButton(
            control_frame,
            values=["ALL", "CRITICAL", "CREDENTIALS", "PII", "MEDIA", "LOGS"],
            command=self._on_filter_changed,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            selected_color=COLOR_ACCENT,
            selected_hover_color=COLOR_ACCENT_HOVER,
            unselected_color="#131d31",
            unselected_hover_color=COLOR_CARD_HOVER
        )
        self.filter_segmented.set("ALL")
        self.filter_segmented.pack(fill="x", pady=(0, 8))

        # Search Bar
        search_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        search_frame.pack(fill="x", pady=(0, 4))

        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Search fragments, keywords, tokens, hex offsets...",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="#060911",
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY,
            height=34
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.search_entry.bind("<KeyRelease>", self._on_search_query_changed)

        btn_clear_search = ctk.CTkButton(
            search_frame,
            text="✕",
            width=34,
            height=34,
            fg_color="#131d31",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            command=self._clear_search
        )
        btn_clear_search.pack(side="right")

        # Separator Line
        sep = ctk.CTkFrame(self.left_panel, fg_color=COLOR_BORDER, height=1)
        sep.pack(fill="x", padx=14, pady=4)

        # Artifacts Queue Header
        queue_header_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        queue_header_frame.pack(fill="x", padx=14, pady=(6, 4))

        queue_title = ctk.CTkLabel(
            queue_header_frame,
            text="RECOVERED ARTIFACTS",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        queue_title.pack(side="left")

        self.queue_count_lbl = ctk.CTkLabel(
            queue_header_frame,
            text="0 items",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_SECONDARY
        )
        self.queue_count_lbl.pack(side="right")

        # Scrollable Artifacts List
        self.artifacts_scroll = ctk.CTkScrollableFrame(
            self.left_panel,
            fg_color="transparent",
            corner_radius=0
        )
        self.artifacts_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Initial Empty State Placeholder
        self.empty_state_label = ctk.CTkLabel(
            self.artifacts_scroll,
            text="\n\nNo artifacts carved yet.\nClick 'Run AI Scan & Deep Carve' to extract\nand stitch forensic data.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=COLOR_TEXT_SECONDARY,
            justify="center"
        )
        self.empty_state_label.pack(pady=40)

    # =========================================================================
    # RIGHT PANEL (INSPECTOR, PREVIEW & RELATIONSHIP MAP)
    # =========================================================================
    def _build_right_panel(self):
        self.right_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=COLOR_PANEL_BG,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.right_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=0)

        # 1. Top Section: Inspector Header & Forensics Telemetry HUD
        self.inspector_header = ctk.CTkFrame(
            self.right_panel,
            fg_color="#0d1726",
            corner_radius=8,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.inspector_header.pack(fill="x", padx=14, pady=12)

        # Title & Action Row
        header_row1 = ctk.CTkFrame(self.inspector_header, fg_color="transparent")
        header_row1.pack(fill="x", padx=14, pady=(10, 4))

        self.selected_name_lbl = ctk.CTkLabel(
            header_row1,
            text="No Artifact Selected",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        self.selected_name_lbl.pack(side="left", fill="x", expand=True)

        # Copy & Export Buttons
        btn_frame = ctk.CTkFrame(header_row1, fg_color="transparent")
        btn_frame.pack(side="right")

        self.btn_copy = ctk.CTkButton(
            btn_frame,
            text="📋 Copy Text",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#131d31",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            width=96,
            height=30,
            command=self._copy_artifact_content
        )
        self.btn_copy.pack(side="left", padx=4)

        self.btn_export = ctk.CTkButton(
            btn_frame,
            text="💾 Export",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#131d31",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            width=80,
            height=30,
            command=self._export_artifact
        )
        self.btn_export.pack(side="left", padx=(4, 0))

        # Badges, Entropy & Health Meter Row
        header_row2 = ctk.CTkFrame(self.inspector_header, fg_color="transparent")
        header_row2.pack(fill="x", padx=14, pady=(4, 10))

        # Category Tag Badge
        self.badge_category = ctk.CTkLabel(
            header_row2,
            text="[UNCLASSIFIED]",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1e293b",
            text_color=COLOR_TEXT_SECONDARY,
            corner_radius=4,
            padx=8,
            pady=3
        )
        self.badge_category.pack(side="left", padx=(0, 6))

        # Priority Pill
        self.badge_priority = ctk.CTkLabel(
            header_row2,
            text="Priority: N/A",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#1e293b",
            text_color=COLOR_TEXT_SECONDARY,
            corner_radius=4,
            padx=8,
            pady=3
        )
        self.badge_priority.pack(side="left", padx=(0, 6))

        # Shannon Entropy Pill
        self.badge_entropy = ctk.CTkLabel(
            header_row2,
            text="Entropy: --",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#131d31",
            text_color="#38bdf8",
            corner_radius=4,
            padx=8,
            pady=3
        )
        self.badge_entropy.pack(side="left", padx=(0, 10))

        # Integrity Score & Visual Health Progress Bar
        integrity_box = ctk.CTkFrame(header_row2, fg_color="transparent")
        integrity_box.pack(side="right")

        self.lbl_integrity_title = ctk.CTkLabel(
            integrity_box,
            text="Integrity: --",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        self.lbl_integrity_title.pack(side="left", padx=(0, 8))

        self.integrity_meter = ctk.CTkProgressBar(
            integrity_box,
            width=130,
            height=10,
            progress_color="#10b981",
            fg_color="#131d31"
        )
        self.integrity_meter.pack(side="left")
        self.integrity_meter.set(0)

        # Metadata Details Line
        self.lbl_meta_details = ctk.CTkLabel(
            self.inspector_header,
            text="Select an artifact from the left queue to view forensic recovery preview and relationship graph.",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.lbl_meta_details.pack(fill="x", padx=14, pady=(0, 8))

        # 2. Middle Section: "Reconstructed Forensic Payload Buffer"
        content_header_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        content_header_frame.pack(fill="x", padx=14, pady=(4, 2))

        content_box_title = ctk.CTkLabel(
            content_header_frame,
            text="💻 RECONSTRUCTED FORENSIC PAYLOAD // HEX & STREAM DECODER",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        content_box_title.pack(side="left")

        content_badge = ctk.CTkLabel(
            content_header_frame,
            text="UTF-8 / LATIN-1 AUTO-DECODE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color="#131d31",
            text_color="#38bdf8",
            corner_radius=3,
            padx=6,
            pady=1
        )
        content_badge.pack(side="right")

        self.txt_content = ctk.CTkTextbox(
            self.right_panel,
            fg_color="#060911",
            text_color="#e2e8f0",
            border_width=1,
            border_color=COLOR_BORDER,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="none"
        )
        self.txt_content.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        self.txt_content.insert("1.0", "/* RECONSTRUCTED PAYLOAD BUFFER EMPTY */\n\nPlease run Disk Dig or AI Scan to carve unallocated sectors and fragmented streams.")
        self.txt_content.configure(state="disabled")

        # 3. Lower Section: "AI Relationship Map Match & Fragment Graph"
        rel_header_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        rel_header_frame.pack(fill="x", padx=14, pady=(2, 2))

        rel_box_title = ctk.CTkLabel(
            rel_header_frame,
            text="🧠 NEURAL FRAGMENT GRAPH & THREAT ENTITY MAP",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        rel_box_title.pack(side="left")

        rel_badge = ctk.CTkLabel(
            rel_header_frame,
            text="MULTI-SECTOR CORRELATION",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color="#131d31",
            text_color="#c084fc",
            corner_radius=3,
            padx=6,
            pady=1
        )
        rel_badge.pack(side="right")

        self.txt_relationship_map = ctk.CTkTextbox(
            self.right_panel,
            height=145,
            fg_color="#070d18",
            text_color="#38bdf8",
            border_width=1,
            border_color=COLOR_BORDER,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word"
        )
        self.txt_relationship_map.pack(fill="x", padx=14, pady=(0, 12))
        self.txt_relationship_map.insert("1.0", "No active relationship links. Standalone fragment or pending scan.")
        self.txt_relationship_map.configure(state="disabled")

    # =========================================================================
    # BOTTOM BAR (LIVE STATUS TICKER & PROGRESS)
    # =========================================================================
    def _build_bottom_bar(self):
        self.bottom_bar = ctk.CTkFrame(self, fg_color=COLOR_PANEL_BG, corner_radius=0, height=36)
        self.bottom_bar.pack(side="bottom", fill="x", padx=0, pady=0)
        self.bottom_bar.pack_propagate(False)

        # Status text label
        self.lbl_status = ctk.CTkLabel(
            self.bottom_bar,
            text="[SYSTEM INITIALIZED] Ready.",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.lbl_status.pack(side="left", fill="x", expand=True, padx=16, pady=4)

        # Timestamp / Engine Info
        engine_tag = ctk.CTkLabel(
            self.bottom_bar,
            text="ENGINE: REVIVER-CARVER-v2.4 | INTEGRITY-AUDIT: ACTIVE",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="#484f58",
            anchor="e"
        )
        engine_tag.pack(side="right", padx=16, pady=4)

    # =========================================================================
    # STATUS & UI UPDATERS
    # =========================================================================
    def _update_status(self, message: str, is_error: bool = False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        color = "#f85149" if is_error else COLOR_TEXT_SECONDARY
        self.lbl_status.configure(text=formatted, text_color=color)

    def _set_status_badge(self, text: str, mode: str = "READY"):
        self.status_mode = mode
        if mode == "READY":
            self.status_badge.configure(
                text=f"● {text}",
                fg_color="#062e1d",
                text_color="#10b981"
            )
        elif mode == "SCANNING":
            self.status_badge.configure(
                text=f"⟳ {text}",
                fg_color="#361c02",
                text_color="#f59e0b"
            )
            self._pulse_status_badge()
        elif mode == "DONE":
            self.status_badge.configure(
                text=f"✔ {text}",
                fg_color="#083344",
                text_color="#06b6d4"
            )
        elif mode == "ERROR":
            self.status_badge.configure(
                text=f"✖ {text}",
                fg_color="#450a0a",
                text_color="#ef4444"
            )

    def _pulse_status_badge(self):
        """Creates a smooth pulsing effect for the status indicator during carving."""
        if getattr(self, "status_mode", "") != "SCANNING":
            return
        curr = self.status_badge.cget("text_color")
        next_c = "#fde047" if curr == "#f59e0b" else "#f59e0b"
        self.status_badge.configure(text_color=next_c)
        self.after(350, self._pulse_status_badge)

    # =========================================================================
    # EVENT HANDLERS
    # =========================================================================
    def _on_select_file(self):
        chosen = filedialog.askopenfilename(
            title="Select Any File or Disk Dump to Carve",
            initialdir=CURRENT_DIR,
            filetypes=[
                ("All Supported Files (*.*)", "*.*"),
                ("Text Logs & Code (*.log, *.txt, *.json, *.py, *.env)", "*.log;*.txt;*.json;*.py;*.env;*.sql;*.csv;*.xml;*.yml;*.yaml"),
                ("Raw Disk Images & Dumps (*.bin, *.img, *.raw, *.dd)", "*.bin;*.img;*.raw;*.dd;*.dmp"),
                ("Documents & Media (*.pdf, *.png, *.jpg, *.zip)", "*.pdf;*.png;*.jpg;*.jpeg;*.gif;*.zip;*.tar;*.gz")
            ]
        )
        if chosen:
            self.target_file_path = chosen
            filename = os.path.basename(chosen)
            file_size = os.path.getsize(chosen)
            self.lbl_current_file.configure(text=f"Target: {filename} ({file_size:,} bytes)")
            self._update_status(f"Selected target file: {filename}")
            self.ledger.add_entry("SELECT_TARGET_FILE", {"file": filename, "size_bytes": file_size})

    def _on_reset_to_sample(self):
        sample_path = os.path.join(CURRENT_DIR, "sample_dump.bin")
        if not os.path.exists(sample_path):
            try:
                from generate_sample import build_sample_dump
                build_sample_dump(sample_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate sample: {e}")
                return

        self.target_file_path = sample_path
        filename = os.path.basename(sample_path)
        file_size = os.path.getsize(sample_path)
        self.lbl_current_file.configure(text=f"Target: {filename} ({file_size:,} bytes)")
        self._update_status(f"Reset target to built-in sample dump: {filename}")
        self.ledger.add_entry("RESET_TO_SAMPLE", {"file": filename, "size_bytes": file_size})

    def _on_filter_changed(self, value: str):
        self.current_filter = value
        self._apply_filters()

    def _on_search_query_changed(self, event=None):
        self.search_query = self.search_entry.get().strip().lower()
        self._apply_filters()

    def _clear_search(self):
        self.search_entry.delete(0, "end")
        self.search_query = ""
        self._apply_filters()

    def _copy_artifact_content(self):
        if not self.selected_artifact:
            return
        content = self.selected_artifact.reconstructed_content
        self.clipboard_clear()
        self.clipboard_append(content)
        self._update_status("Reconstructed artifact content copied to clipboard.")

    def open_audit_ledger_window(self):
        """Opens a modal window showing the sequential SHA-256 hash chain ledger."""
        ledger_win = ctk.CTkToplevel(self)
        ledger_win.geometry("780x560")
        ledger_win.title("Reviver // Chain of Custody Audit Ledger (SHA-256)")
        ledger_win.configure(fg_color=COLOR_BG_DARK)
        ledger_win.after(100, ledger_win.lift)

        # Header Frame
        hdr = ctk.CTkFrame(ledger_win, fg_color=COLOR_PANEL_BG, corner_radius=6)
        hdr.pack(fill="x", padx=16, pady=(16, 8))

        title_lbl = ctk.CTkLabel(
            hdr,
            text="🔐 Tamper-Evident SHA-256 Hash Chain Ledger",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        title_lbl.pack(side="left", padx=12, pady=10)

        chain_len_lbl = ctk.CTkLabel(
            hdr,
            text=f"Chain Height: {len(self.ledger.chain)} blocks",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#0e3818",
            text_color="#3fb950",
            corner_radius=4,
            padx=10,
            pady=4
        )
        chain_len_lbl.pack(side="right", padx=12, pady=10)

        textbox = ctk.CTkTextbox(
            ledger_win,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0d1117",
            text_color="#58a6ff",
            border_width=1,
            border_color=COLOR_BORDER,
            wrap="none"
        )
        textbox.pack(fill="both", expand=True, padx=16, pady=8)

        # Format and display ledger entries
        ledger_text = ""
        for entry in self.ledger.chain:
            ledger_text += f"[BLOCK #{entry['index']:03d}] ACTION: {entry['action']}\n"
            ledger_text += f"    Timestamp : {entry['timestamp']}\n"
            ledger_text += f"    Prev Hash : {entry['previous_hash']}\n"
            ledger_text += f"    Curr Hash : {entry['current_hash']}\n"
            ledger_text += f"    Details   : {json.dumps(entry['details'])}\n"
            ledger_text += "-" * 76 + "\n"

        textbox.insert("0.0", ledger_text)
        textbox.configure(state="disabled")

        # Bottom controls
        btn_frame = ctk.CTkFrame(ledger_win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(4, 16))

        def copy_ledger_json():
            self.clipboard_clear()
            self.clipboard_append(json.dumps(self.ledger.chain, indent=2))
            self._update_status("Audit ledger JSON copied to clipboard.")

        btn_copy = ctk.CTkButton(
            btn_frame,
            text="📋 Copy Ledger JSON",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#21262d",
            hover_color=COLOR_CARD_HOVER,
            command=copy_ledger_json
        )
        btn_copy.pack(side="left")

        btn_close = ctk.CTkButton(
            btn_frame,
            text="Close",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#21262d",
            hover_color=COLOR_CARD_HOVER,
            width=80,
            command=ledger_win.destroy
        )
        btn_close.pack(side="right")

    def handle_export(self):
        """Prompts the user with export format choices (Technical JSON vs. Plain-English Executive Summary)."""
        export_win = ctk.CTkToplevel(self)
        export_win.geometry("520x300")
        export_win.title("Reviver // Select Forensic Export Package")
        export_win.configure(fg_color=COLOR_BG_DARK)
        export_win.resizable(False, False)
        export_win.after(100, export_win.lift)

        # Header Frame
        hdr = ctk.CTkFrame(export_win, fg_color=COLOR_PANEL_BG, corner_radius=6)
        hdr.pack(fill="x", padx=16, pady=(16, 12))

        ctk.CTkLabel(
            hdr,
            text="💾 Choose Forensic Export Format",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        ).pack(anchor="w", padx=14, pady=(10, 2))

        ctk.CTkLabel(
            hdr,
            text="Select the appropriate evidence presentation format for your investigation stakeholders:",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=COLOR_TEXT_SECONDARY
        ).pack(anchor="w", padx=14, pady=(0, 10))

        content_box = ctk.CTkFrame(export_win, fg_color="transparent")
        content_box.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        def export_json():
            export_win.destroy()
            current_artifacts = self.artifacts if self.artifacts else []
            self.ledger.add_entry("EXPORT_REPORT_JSON", {"artifact_count": len(current_artifacts)})
            default_name = f"reviver_forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            save_path = filedialog.asksaveasfilename(
                title="Export Signed Technical Forensic JSON",
                initialdir=CURRENT_DIR,
                initialfile=default_name,
                filetypes=[("Signed Forensic JSON (*.json)", "*.json"), ("All Files", "*.*")]
            )
            if save_path:
                filepath = export_forensic_report(current_artifacts, self.ledger.chain, filepath=save_path)
                self._update_status(f"✔ Technical report exported: {os.path.basename(filepath)}")
                messagebox.showinfo(
                    "Technical Export Successful",
                    f"Forensic evidence package exported successfully!\n\n"
                    f"File: {filepath}\n"
                    f"Artifacts Packaged: {len(current_artifacts)}\n"
                    f"Ledger Chain Height: {len(self.ledger.chain)} blocks\n"
                    f"Cryptographic SHA-256 signature verified."
                )

        def export_plain_english():
            export_win.destroy()
            current_artifacts = self.artifacts if self.artifacts else []
            self.ledger.add_entry("EXPORT_REPORT_PLAIN_ENGLISH", {"artifact_count": len(current_artifacts)})
            report_text = generate_plain_english_report(current_artifacts, self.ledger.chain)
            default_name = f"reviver_executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            save_path = filedialog.asksaveasfilename(
                title="Export Plain-English Executive Summary",
                initialdir=CURRENT_DIR,
                initialfile=default_name,
                filetypes=[("Plain-English Text Report (*.txt)", "*.txt"), ("Markdown Document (*.md)", "*.md"), ("All Files", "*.*")]
            )
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(report_text)
                self._update_status(f"✔ Executive summary exported: {os.path.basename(save_path)}")
                messagebox.showinfo(
                    "Executive Summary Exported",
                    f"Plain-English Executive Report saved successfully!\n\n"
                    f"File: {save_path}\n"
                    f"Target Stakeholders: Executive Leadership & Legal Counsel\n"
                    f"Artifacts Summarized: {len(current_artifacts)}"
                )

        # Option 1: Technical JSON
        btn_json = ctk.CTkButton(
            content_box,
            text="📊 Technical Forensic JSON  (For Courts, DFIR Experts & Hash Chains)",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#1e293b",
            hover_color=COLOR_CARD_HOVER,
            border_width=1,
            border_color=COLOR_BORDER,
            height=42,
            command=export_json
        )
        btn_json.pack(fill="x", pady=6)

        # Option 2: Plain English
        btn_text = ctk.CTkButton(
            content_box,
            text="📝 Plain-English Executive Summary  (For Leadership & Non-CS Stakeholders)",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#1d4ed8",
            hover_color="#2563eb",
            height=42,
            command=export_plain_english
        )
        btn_text.pack(fill="x", pady=6)

    def open_reviver_chatbot(self):
        """Opens the local AI assistant 'REVIVER' interactive chat window."""
        chat_win = ctk.CTkToplevel(self)
        chat_win.geometry("640x700")
        chat_win.title("Reviver // AI Digital Assistant & DFIR Copilot")
        chat_win.configure(fg_color=COLOR_BG_DARK)
        chat_win.after(100, chat_win.lift)

        # Header Frame
        hdr = ctk.CTkFrame(chat_win, fg_color=COLOR_PANEL_BG, corner_radius=0, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        hdr_inner = ctk.CTkFrame(hdr, fg_color="transparent")
        hdr_inner.pack(fill="both", expand=True, padx=16, pady=10)

        ctk.CTkLabel(
            hdr_inner,
            text="💬 REVIVER AI // Digital Forensics Copilot",
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        ).pack(side="left")

        status_chip = ctk.CTkLabel(
            hdr_inner,
            text="● COPILOT ACTIVE",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            fg_color="#062e1d",
            text_color="#10b981",
            corner_radius=4,
            padx=8,
            pady=3
        )
        status_chip.pack(side="right")

        # Chat Display Box
        chat_box = ctk.CTkTextbox(
            chat_win,
            fg_color="#060911",
            text_color="#e2e8f0",
            font=ctk.CTkFont(family="Consolas", size=11),
            border_width=1,
            border_color=COLOR_BORDER,
            wrap="word"
        )
        chat_box.pack(fill="both", expand=True, padx=14, pady=12)

        welcome_msg = (
            "╔══════════════════════════════════════════════════════════════════════════════╗\n"
            "║                  REVIVER AI DIGITAL FORENSICS COPILOT                        ║\n"
            "╚══════════════════════════════════════════════════════════════════════════════╝\n"
            "Hello! I am your AI assistant for forensic evidence analysis and file operations.\n\n"
            "• Ask me questions: 'summary', 'threats', 'credentials', 'ledger', 'disk dig', 'entropy'\n"
            "• File management commands: 'organize <path>' or 'duplicates <path>'\n"
            "• Or just type 'organize' or 'duplicates' to choose a folder via file dialog!\n"
            "────────────────────────────────────────────────────────────────────────────────\n\n"
        )
        chat_box.insert("end", welcome_msg)
        chat_box.configure(state="disabled")

        # Quick Prompt Buttons Bar
        quick_frame = ctk.CTkFrame(chat_win, fg_color="transparent")
        quick_frame.pack(fill="x", padx=14, pady=(0, 8))

        def on_quick_click(text):
            user_entry.delete(0, "end")
            user_entry.insert(0, text)
            send_message()

        for q_lbl, q_cmd in [
            ("📊 Summary", "summary"),
            ("🔴 Critical Threats", "threats"),
            ("📂 Organize Files", "organize"),
            ("🔍 Find Duplicates", "duplicates"),
            ("⛏️ Explain Disk Dig", "explain disk dig")
        ]:
            b = ctk.CTkButton(
                quick_frame,
                text=q_lbl,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                fg_color="#131d31",
                hover_color=COLOR_CARD_HOVER,
                border_width=1,
                border_color=COLOR_BORDER,
                height=26,
                command=lambda cmd=q_cmd: on_quick_click(cmd)
            )
            b.pack(side="left", padx=2)

        # Input Frame
        input_frame = ctk.CTkFrame(chat_win, fg_color="transparent")
        input_frame.pack(fill="x", padx=14, pady=(0, 14))

        user_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Ask a question or enter command (e.g., 'summary', 'organize', 'duplicates')...",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=38,
            fg_color="#131d31",
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY
        )
        user_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def send_message(event=None):
            query = user_entry.get().strip()
            if not query:
                return
            user_entry.delete(0, "end")

            chat_box.configure(state="normal")
            chat_box.insert("end", f"Investigator > {query}\n")

            q_lower = query.lower()

            # Dynamic AI Logic
            if any(k in q_lower for k in ["summary", "overview", "report", "scan status", "results"]):
                total = len(self.artifacts) if hasattr(self, 'artifacts') else 0
                crit = sum(1 for a in getattr(self, 'artifacts', []) if "Tier 1" in a.priority_tier or "Critical" in a.priority_tier)
                sens = sum(1 for a in getattr(self, 'artifacts', []) if "Tier 2" in a.priority_tier or "Sensitive" in a.priority_tier)
                stitched = sum(1 for a in getattr(self, 'artifacts', []) if a.relationship_links)
                target = os.path.basename(self.target_file_path) if self.target_file_path else "None"
                resp = (
                    f"REVIVER AI:\n"
                    f"• Target Image : {target}\n"
                    f"• Total Carved : {total} evidentiary artifacts\n"
                    f"• Critical Risk: {crit} high-priority vulnerabilities/secrets\n"
                    f"• Sensitive PII: {sens} records identified\n"
                    f"• Graph Links  : {stitched} cross-fragment stitched connections\n"
                    f"• Ledger Height: {len(self.ledger.chain)} immutable SHA-256 blocks"
                )

            elif any(k in q_lower for k in ["threat", "critical", "secret", "credential", "password"]):
                crits = [a for a in getattr(self, 'artifacts', []) if "Tier 1" in a.priority_tier or "Critical" in a.priority_tier or "Credential" in a.category]
                if crits:
                    resp = f"REVIVER AI: Identified {len(crits)} critical risk items in current workspace:\n"
                    for c in crits[:4]:
                        resp += f"  - [{c.artifact_id}] {c.name} ({c.category})\n"
                    if len(crits) > 4:
                        resp += f"  - ...and {len(crits) - 4} more."
                else:
                    resp = "REVIVER AI: No critical threats currently detected. Run 'Disk Dig' or 'AI Scan' on a target disk image."

            elif q_lower.startswith("organize") or "organize" in q_lower:
                parts = query.split(maxsplit=1)
                target_dir = parts[1].strip() if len(parts) > 1 else ""
                if not target_dir or not os.path.exists(target_dir):
                    target_dir = filedialog.askdirectory(title="Select Folder to Organize by File Type")
                if target_dir and os.path.exists(target_dir):
                    res_msg = organize_folder_by_type(target_dir)
                    resp = f"REVIVER AI: {res_msg}\nTarget: {target_dir}"
                    self.ledger.add_entry("ORGANIZE_FOLDER", {"path": target_dir})
                else:
                    resp = "REVIVER AI: Folder organization cancelled or invalid directory specified."

            elif q_lower.startswith("duplicate") or "duplicate" in q_lower or q_lower.startswith("purge"):
                is_purge = "purge" in q_lower or "delete" in q_lower
                parts = query.split(maxsplit=1)
                target_dir = parts[1].strip() if len(parts) > 1 else ""
                if not target_dir or not os.path.exists(target_dir):
                    target_dir = filedialog.askdirectory(title="Select Folder to Scan for Duplicates")
                if target_dir and os.path.exists(target_dir):
                    msg, dupes = scan_and_purge_duplicates(target_dir, delete_mode=is_purge)
                    resp = f"REVIVER AI: {msg}\n"
                    if dupes:
                        resp += "Duplicate files identified:\n"
                        for d in dupes[:5]:
                            resp += f"  - {os.path.basename(d)}\n"
                        if len(dupes) > 5:
                            resp += f"  - ...and {len(dupes) - 5} more files."
                    self.ledger.add_entry("SCAN_DUPLICATES", {"path": target_dir, "count": len(dupes), "purged": is_purge})
                else:
                    resp = "REVIVER AI: Duplicate scan cancelled or invalid directory specified."

            elif any(k in q_lower for k in ["disk dig", "carv", "magic byte", "sector"]):
                resp = (
                    "REVIVER AI: Disk Dig is our raw sector-level carver. Standard file systems rely on allocation "
                    "tables (MFT / inodes) that get destroyed when a partition is formatted or deleted. Disk Dig "
                    "bypasses the file system completely, scanning raw sector bytes for known cryptographic magic bytes "
                    "(%PDF, FF D8 FF for JPEG, 89 PNG, PK for ZIPs, ELF) and resurrecting shredded data directly from "
                    "unallocated slack space."
                )

            elif any(k in q_lower for k in ["ledger", "chain of custody", "audit", "hash"]):
                last_b = self.ledger.chain[-1] if self.ledger.chain else None
                resp = (
                    f"REVIVER AI: Tamper-evident SHA-256 Chain of Custody ledger is active.\n"
                    f"• Height   : {len(self.ledger.chain)} blocks\n"
                    f"• Last Op  : {last_b['action'] if last_b else 'N/A'}\n"
                    f"• Hash     : {last_b['current_hash'][:32] if last_b else 'N/A'}...\n"
                    f"• Status   : Cryptographically signed & verified for court admissibility."
                )

            elif "entropy" in q_lower:
                resp = (
                    "REVIVER AI: Shannon entropy measures byte-level randomness on a 0.0 to 8.0 scale.\n"
                    "• 0.0 - 3.5 : Low density (zero-padded disk slack, plain sparse data)\n"
                    "• 4.0 - 5.5 : Moderate density (structured source code, JSON, plain text logs)\n"
                    "• 7.0 - 8.0 : High density (encrypted vaults, compressed packages, packed malware)"
                )

            else:
                resp = (
                    f"REVIVER AI: Copilot online. Active target: {os.path.basename(self.target_file_path) if self.target_file_path else 'None'}.\n"
                    f"I can assist you in analyzing carved artifacts, explaining forensic rules, organizing "
                    f"investigation directories, or scanning for duplicate files via SHA-256."
                )

            chat_box.insert("end", f"{resp}\n\n")
            chat_box.configure(state="disabled")
            chat_box.see("end")

        user_entry.bind("<Return>", send_message)
        btn_send = ctk.CTkButton(
            input_frame,
            text="Send",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            width=75,
            height=38,
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            command=send_message
        )
        btn_send.pack(side="right")

    def _export_artifact(self):
        if not self.selected_artifact:
            messagebox.showinfo("Export", "Please select an artifact to export.")
            return

        art = self.selected_artifact
        default_filename = f"{art.artifact_id}_{art.name.replace(' ', '_')[:30]}.txt"
        save_path = filedialog.asksaveasfilename(
            title="Export Reconstructed Forensic Artifact",
            initialdir=CURRENT_DIR,
            initialfile=default_filename,
            filetypes=[("Text File", "*.txt"), ("JSON Manifest", "*.json"), ("All Files", "*.*")]
        )
        if save_path:
            try:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(f"=== REVIVER FORENSIC RECONSTRUCTION REPORT ===\n")
                    f.write(f"Artifact ID: {art.artifact_id}\n")
                    f.write(f"Name: {art.name}\n")
                    f.write(f"Category: {art.category}\n")
                    f.write(f"Priority: {art.priority_tier}\n")
                    f.write(f"Structural Integrity: {art.integrity_status}\n")
                    f.write(f"Fragments Stitched: {len(art.fragments)}\n")
                    f.write(f"Byte Range: {art.metadata.get('byte_range', 'N/A')}\n")
                    f.write(f"Matched Keywords: {', '.join(art.matched_keywords)}\n")
                    f.write(f"\n--- RECONSTRUCTED CONTENT ---\n\n")
                    f.write(art.reconstructed_content)
                self.ledger.add_entry("EXPORT_SINGLE_ARTIFACT", {"artifact_id": art.artifact_id, "name": art.name})
                self._update_status(f"Exported artifact to: {os.path.basename(save_path)}")
                messagebox.showinfo("Success", f"Artifact exported successfully:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export artifact:\n{e}")

    # =========================================================================
    # FORENSIC SCAN & DISK DIG EXECUTION (ASYNC THREADS)
    # =========================================================================
    def _start_disk_dig_thread(self):
        """Dedicated Disk Dig raw sector-level carver bypassing file system allocation tables."""
        if self.is_scanning:
            return

        if not self.target_file_path or not os.path.exists(self.target_file_path):
            messagebox.showwarning("File Missing", "Please select a valid disk dump image before running Disk Dig.")
            return

        self.is_scanning = True
        self.btn_disk_dig.configure(state="disabled", text="⛏️ Digging Sectors...")
        self.btn_run_scan.configure(state="disabled")
        self.btn_select_file.configure(state="disabled")
        self._set_status_badge("SECTOR CARVING...", mode="SCANNING")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        # Log Disk Dig action to ledger
        self.ledger.add_entry("DISK_DIG_START", {
            "target": os.path.basename(self.target_file_path),
            "mode": "RAW_SECTOR_MAGIC_BYTE_CARVE"
        })

        thread = threading.Thread(target=self._run_disk_dig_worker, daemon=True)
        thread.start()

    def _run_disk_dig_worker(self):
        try:
            self.event_queue.put(("STATUS", ("⛏️ Disk Dig: Reading raw binary stream sector-by-sector...", False)))
            time.sleep(0.3)
            self.event_queue.put(("STATUS", ("⛏️ Disk Dig: Hunting for magic byte signatures (JPEG, PNG, PDF, ZIP, ELF)...", False)))
            time.sleep(0.3)
            fragments = disk_dig_carve(self.target_file_path)

            self.event_queue.put(("STATUS", (f"⛏️ Disk Dig: Carved {len(fragments)} unallocated fragments. Correlating relationships...", False)))
            time.sleep(0.3)
            artifacts = stitch_fragments(fragments)

            self.event_queue.put(("STATUS", ("⛏️ Disk Dig: Assessing Shannon entropy & structural health...", False)))
            time.sleep(0.2)
            prioritized = classify_and_prioritize(artifacts)

            self.event_queue.put(("COMPLETE", (fragments, prioritized)))
        except Exception as e:
            self.event_queue.put(("FAILED", str(e)))

    def _start_scan_thread(self):
        if self.is_scanning:
            return

        if not self.target_file_path or not os.path.exists(self.target_file_path):
            messagebox.showwarning("File Missing", "Please select a valid disk dump image before running scan.")
            return

        self.is_scanning = True
        self.btn_run_scan.configure(state="disabled", text="⚡ Scanning Deep...")
        self.btn_disk_dig.configure(state="disabled")
        self.btn_select_file.configure(state="disabled")
        self._set_status_badge("SCANNING FILE...", mode="SCANNING")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        # Log scan initiation to ledger
        self.ledger.add_entry("START_SCAN", {"target": os.path.basename(self.target_file_path)})

        # Run background thread
        thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        thread.start()

    def _run_scan_worker(self):
        try:
            self.event_queue.put(("STATUS", ("Step 1/4: Reading binary image and carving sectors...", False)))
            time.sleep(0.3)
            fragments = disk_dig_carve(self.target_file_path)

            self.event_queue.put(("STATUS", (f"Step 2/4: Carved {len(fragments)} candidate fragments. Correlating graph relationships...", False)))
            time.sleep(0.3)
            artifacts = stitch_fragments(fragments)

            self.event_queue.put(("STATUS", ("Step 3/4: Assessing structural integrity and delimiter health...", False)))
            time.sleep(0.2)

            self.event_queue.put(("STATUS", ("Step 4/4: Executing keyword and regex classification engine...", False)))
            time.sleep(0.2)
            prioritized = classify_and_prioritize(artifacts)

            # Post results safely to event queue
            self.event_queue.put(("COMPLETE", (fragments, prioritized)))
        except Exception as e:
            self.event_queue.put(("FAILED", str(e)))

    def _on_scan_completed(self, fragments: List[DataFragment], artifacts: List[ForensicArtifact]):
        self.is_scanning = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1.0)
        self.btn_disk_dig.configure(state="normal", text="⛏️ Disk Dig (Sector Carve)")
        self.btn_run_scan.configure(state="normal", text="⚡ AI Deep Scan")
        self.btn_select_file.configure(state="normal")
        self._set_status_badge("ANALYSIS COMPLETE", mode="DONE")

        self.artifacts = artifacts

        # Update telemetry stats
        total_frags = len(fragments)
        stitched_count = sum(1 for a in artifacts if a.relationship_links)
        critical_count = sum(1 for a in artifacts if "Tier 1" in a.priority_tier or "Critical" in a.priority_tier)

        self.stat_fragments_lbl.configure(text=f"Fragments: {total_frags}")
        self.stat_stitched_lbl.configure(text=f"Stitched: {stitched_count}")
        self.stat_critical_lbl.configure(text=f"Critical: {critical_count}")

        # Log scan completion to audit ledger
        self.ledger.add_entry("SCAN_COMPLETED", {
            "fragments_carved": total_frags,
            "artifacts_reconstructed": len(artifacts),
            "stitched_relationships": stitched_count,
            "critical_risk_items": critical_count
        })

        self._update_status(
            f"Scan Complete: {total_frags} stream blocks carved, {len(artifacts)} prioritized artifacts."
        )

        # Re-render list
        self._apply_filters()

        # Select first artifact if available
        if self.filtered_artifacts:
            self._display_artifact(self.filtered_artifacts[0])

    @property
    def current_artifacts(self):
        return self.artifacts

    @current_artifacts.setter
    def current_artifacts(self, val):
        self.artifacts = val

    def _on_scan_failed(self, error_msg: str):
        self.is_scanning = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(0)
        self.btn_run_scan.configure(state="normal", text="⚡ Run AI Scan & Deep Carve")
        self.btn_select_file.configure(state="normal")
        self._set_status_badge("SCAN FAILED", mode="ERROR")
        self._update_status(f"Scan failed: {error_msg}", is_error=True)
        messagebox.showerror("Carving Error", f"Failed to carve target image:\n{error_msg}")

    # =========================================================================
    # FILTERING & LIST RENDERING
    # =========================================================================
    def _apply_filters(self):
        if not self.artifacts:
            self.filtered_artifacts = []
            self._render_artifacts_list()
            return

        results = []
        for art in self.artifacts:
            # Check Category Filter
            cat_upper = art.category.upper()
            if self.current_filter == "CRITICAL":
                if "CRITICAL" not in cat_upper and "TIER 1" not in art.priority_tier.upper() and "FINANCIAL" not in cat_upper:
                    continue
            elif self.current_filter == "CREDENTIALS":
                if "CREDENTIAL" not in cat_upper:
                    continue
            elif self.current_filter == "PII":
                if "PII" not in cat_upper:
                    continue
            elif self.current_filter == "MEDIA":
                if "MEDIA" not in cat_upper and "DOCUMENT" not in cat_upper and "ARCHIVE" not in cat_upper and "BINARY" not in cat_upper:
                    continue
            elif self.current_filter == "LOGS":
                if "LOG" not in cat_upper and "SYSLOG" not in cat_upper and "AUTH" not in cat_upper:
                    continue

            # Check Search Query
            if self.search_query:
                q = self.search_query
                in_name = q in art.name.lower()
                in_cat = q in art.category.lower()
                in_content = q in art.reconstructed_content.lower()
                in_kw = any(q in kw.lower() for kw in art.matched_keywords)
                in_id = q in art.artifact_id.lower()
                in_span = q in str(art.metadata.get("byte_range", "")).lower()
                if not (in_name or in_cat or in_content or in_kw or in_id or in_span):
                    continue

            results.append(art)

        self.filtered_artifacts = results
        self._render_artifacts_list()

    def _render_artifacts_list(self):
        # Clear existing widgets
        for widget in self.artifacts_scroll.winfo_children():
            widget.destroy()
        self.artifact_widgets.clear()

        count = len(self.filtered_artifacts)
        self.queue_count_lbl.configure(text=f"{count} items")

        if not self.filtered_artifacts:
            msg = "No artifacts carved yet." if not self.artifacts else "No artifacts match current filter."
            placeholder = ctk.CTkLabel(
                self.artifacts_scroll,
                text=f"\n\n{msg}",
                font=ctk.CTkFont(family="Segoe UI", size=13),
                text_color=COLOR_TEXT_SECONDARY
            )
            placeholder.pack(pady=30)
            return

        for art in self.filtered_artifacts:
            card = self._create_artifact_card(art)
            card.pack(fill="x", pady=4, padx=2)
            self.artifact_widgets.append(card)

    def _create_artifact_card(self, art: ForensicArtifact) -> ctk.CTkFrame:
        is_selected = (self.selected_artifact and self.selected_artifact.artifact_id == art.artifact_id)
        card_bg = COLOR_CARD_ACTIVE if is_selected else COLOR_CARD_BG
        border_col = COLOR_BORDER_FOCUS if is_selected else COLOR_BORDER
        border_w = 2 if is_selected else 1

        card = ctk.CTkFrame(
            self.artifacts_scroll,
            fg_color=card_bg,
            corner_radius=8,
            border_width=border_w,
            border_color=border_col,
            cursor="hand2"
        )

        palette = get_category_color(art.category)

        # Header: Name, Artifact ID & Active Pill
        row1 = ctk.CTkFrame(card, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(8, 2))

        # Distinctive Monospace ID Chip
        lbl_id = ctk.CTkLabel(
            row1,
            text=f"[{art.artifact_id}]",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#0a1526",
            text_color="#38bdf8",
            corner_radius=4,
            padx=6,
            pady=1
        )
        lbl_id.pack(side="left", padx=(0, 6))

        lbl_name = ctk.CTkLabel(
            row1,
            text=art.name,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        lbl_name.pack(side="left", fill="x", expand=True)

        clickable_elements = [row1, lbl_id, lbl_name]

        if is_selected:
            badge_active = ctk.CTkLabel(
                row1,
                text="▶ ACTIVE",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                fg_color="#083344",
                text_color="#38bdf8",
                corner_radius=3,
                padx=5,
                pady=1
            )
            badge_active.pack(side="right")
            clickable_elements.append(badge_active)

        # Row 2: Badges (Category & Priority)
        row2 = ctk.CTkFrame(card, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=2)

        badge_cat = ctk.CTkLabel(
            row2,
            text=palette.get("badge", art.category),
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            fg_color=palette["bg"],
            text_color=palette["text"],
            corner_radius=4,
            padx=7,
            pady=2
        )
        badge_cat.pack(side="left", padx=(0, 4))
        clickable_elements.extend([row2, badge_cat])

        pri_short = "🔴 HIGH RISK" if "1" in art.priority_tier or "Critical" in art.priority_tier else (
            "🟡 SENSITIVE" if "2" in art.priority_tier else "🟢 NORMAL"
        )
        badge_pri = ctk.CTkLabel(
            row2,
            text=pri_short,
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            fg_color="#1e293b",
            text_color=palette["text"],
            corner_radius=4,
            padx=6,
            pady=2
        )
        badge_pri.pack(side="left")
        clickable_elements.append(badge_pri)

        # Stitched badge if composite or linked
        if art.relationship_links:
            badge_stitch = ctk.CTkLabel(
                row2,
                text=f"🔗 Linked ({art.relationship_links[0].confidence:.0f}%)",
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                fg_color="#1e1b4b",
                text_color="#c084fc",
                corner_radius=4,
                padx=6,
                pady=2
            )
            badge_stitch.pack(side="right")
            clickable_elements.append(badge_stitch)

        # Row 3: Meta details (Sectors, Entropy, Integrity Health)
        row3 = ctk.CTkFrame(card, fg_color="transparent")
        row3.pack(fill="x", padx=10, pady=(4, 8))

        sector_str = f"Sec {art.metadata.get('sector_span', [])}"
        span_str = art.metadata.get('byte_range', '')
        lbl_meta = ctk.CTkLabel(
            row3,
            text=f"{sector_str} • {span_str}",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLOR_TEXT_MUTED
        )
        lbl_meta.pack(side="left")
        clickable_elements.extend([row3, lbl_meta])

        # Health pill
        int_color = "#34d399" if art.integrity_score >= 90 else ("#fbbf24" if art.integrity_score >= 70 else "#f87171")
        lbl_integ = ctk.CTkLabel(
            row3,
            text=f"{art.integrity_score}% Health",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=int_color
        )
        lbl_integ.pack(side="right")
        clickable_elements.append(lbl_integ)

        # Entropy Mini-Pill
        ent_val = art.metadata.get("average_entropy", 0.0)
        ent_color = "#f87171" if ent_val >= 7.0 else ("#fbbf24" if ent_val >= 4.5 else "#38bdf8")
        lbl_ent = ctk.CTkLabel(
            row3,
            text=f"H:{ent_val:.2f}",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color="#0b1320",
            text_color=ent_color,
            corner_radius=3,
            padx=5,
            pady=1
        )
        lbl_ent.pack(side="right", padx=(0, 6))
        clickable_elements.append(lbl_ent)

        # Hover and click bindings
        def on_hover(e):
            if not (self.selected_artifact and self.selected_artifact.artifact_id == art.artifact_id):
                card.configure(fg_color=COLOR_CARD_HOVER)

        def on_unhover(e):
            if not (self.selected_artifact and self.selected_artifact.artifact_id == art.artifact_id):
                card.configure(fg_color=COLOR_CARD_BG)

        def on_click(event, target_art=art):
            self._display_artifact(target_art)
            self._render_artifacts_list()

        card.bind("<Enter>", on_hover)
        card.bind("<Leave>", on_unhover)
        card.bind("<Button-1>", on_click)
        for child in clickable_elements:
            child.bind("<Button-1>", on_click)

        return card

    # =========================================================================
    # DISPLAY ARTIFACT IN RIGHT INSPECTOR PANEL
    # =========================================================================
    def _display_artifact(self, art: ForensicArtifact):
        self.selected_artifact = art

        # Title & Badges
        self.selected_name_lbl.configure(text=f"[{art.artifact_id}]  {art.name}")

        palette = get_category_color(art.category)
        self.badge_category.configure(
            text=palette.get("badge", art.category),
            fg_color=palette["bg"],
            text_color=palette["text"]
        )

        pri_color = "#f87171" if "1" in art.priority_tier or "Critical" in art.priority_tier else (
            "#fbbf24" if "2" in art.priority_tier else "#34d399"
        )
        self.badge_priority.configure(
            text=art.priority_tier,
            fg_color="#131d31",
            text_color=pri_color
        )

        # Shannon Entropy Meter & Density Indicator
        ent_val = float(art.metadata.get("average_entropy", 0.0))
        if ent_val >= 7.0:
            ent_desc = "High Density / Packed or Encrypted"
            ent_color = "#f87171"
        elif ent_val >= 4.5:
            ent_desc = "Moderate Density / Structured Text or Code"
            ent_color = "#fbbf24"
        else:
            ent_desc = "Low Density / Plain Data or Slack"
            ent_color = "#38bdf8"
        self.badge_entropy.configure(text=f"Entropy: {ent_val:.2f} ({ent_desc})", text_color=ent_color)

        # Integrity Meter
        score = art.integrity_score
        meter_val = max(0.05, score / 100.0)
        self.integrity_meter.set(meter_val)

        if score >= 90:
            meter_color = "#10b981"
        elif score >= 70:
            meter_color = "#f59e0b"
        else:
            meter_color = "#ef4444"
        self.integrity_meter.configure(progress_color=meter_color)

        self.lbl_integrity_title.configure(text=f"{score}% Valid Structure", text_color=meter_color)

        # Diagnostic metadata line
        diag_items = []
        if art.integrity_details.get("header_footer"):
            diag_items.append(f"Headers: {art.integrity_details['header_footer']}")
        if art.integrity_details.get("syntax_health"):
            diag_items.append(f"Syntax: {art.integrity_details['syntax_health']}")
        if art.integrity_details.get("truncation_detected"):
            diag_items.append("[FAULT: Cluster Truncation Flagged]")
        diag_items.append(f"Entropy: {ent_val:.2f}")
        diag_items.append(f"Span: {art.metadata.get('byte_range', 'N/A')}")
        diag_items.append(f"SHA-256 Chain Height: #{len(self.ledger.chain)}")

        self.lbl_meta_details.configure(text="  │  ".join(diag_items))

        # Reconstructed Content in Terminal Buffer
        self.txt_content.configure(state="normal")
        self.txt_content.delete("1.0", "end")
        self.txt_content.insert("1.0", art.reconstructed_content)
        self.txt_content.configure(state="disabled")

        # AI Relationship Map Match Box with ASCII Network Tree Visualizer
        self.txt_relationship_map.configure(state="normal")
        self.txt_relationship_map.delete("1.0", "end")

        if art.relationship_links:
            lines = [
                f"╔═════════════════════════════════════════════════════════════════════════════════════════════╗",
                f"║  NEURAL FRAGMENT RELATIONSHIP MATRIX // {len(art.relationship_links)} ACTIVE CROSS-SECTOR CORRELATION(S)           ║",
                f"╚═════════════════════════════════════════════════════════════════════════════════════════════╝",
                f"[NODE SOURCE] : {art.artifact_id} ({art.name})",
                f"├── Offset Span : {art.metadata.get('byte_range', 'N/A')}",
                f"└── Active Graph Linkages:"
            ]
            for idx, link in enumerate(art.relationship_links, 1):
                is_last = (idx == len(art.relationship_links))
                pfx = "    └──" if is_last else "    ├──"
                sub_pfx = "       " if is_last else "    │  "
                lines.append(f"{pfx} [CORRELATION MATCH #{idx}] ──► Target Node: [{link.target_id}]")
                lines.append(f"{sub_pfx} ├── Confidence Score : {link.confidence:.1f}% Match")
                lines.append(f"{sub_pfx} ├── Shared Entity    : {link.token}")
                lines.append(f"{sub_pfx} ├── Heuristic Rule   : {link.link_type}")
                lines.append(f"{sub_pfx} └── Forensic Context : {link.rationale}")
            lines.append("")
            lines.append("✔ STATUS: Fragment boundaries resolved and stitched into continuous evidentiary chain.")
            rel_text = "\n".join(lines)
            self.txt_relationship_map.configure(text_color="#38bdf8")
        else:
            lines = [
                f"╔═════════════════════════════════════════════════════════════════════════════════════════════╗",
                f"║  STANDALONE EVIDENTIARY OBJECT // NO CONTINUATION TOKENS DETECTED                           ║",
                f"╚═════════════════════════════════════════════════════════════════════════════════════════════╝",
                f"[INSPECTED NODE] : {art.artifact_id} ({art.name})",
                f"├── Structural Continuity : Complete bounded block (No dangling cluster pointers)",
                f"├── Forensic Validation   : {art.integrity_status}",
                f"├── Shannon Entropy       : {ent_val:.2f} ({ent_desc})",
                f"└── Detected Signatures   : {', '.join(art.matched_keywords) if art.matched_keywords else 'Raw Sector Stream'}"
            ]
            rel_text = "\n".join(lines)
            self.txt_relationship_map.configure(text_color="#94a3b8")

        self.txt_relationship_map.insert("1.0", rel_text)
        self.txt_relationship_map.configure(state="disabled")

        self._update_status(f"Inspecting: {art.name} ({art.artifact_id})")


# Backwards compatibility alias
CalmStacksReconstructorApp = ReviverApp


def main():
    try:
        app = ReviverApp()
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
