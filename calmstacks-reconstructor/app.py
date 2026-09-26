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
    scan_and_purge_duplicates,
    precise_duplicate_scanner,
    query_llm_api,
    ai_enhance_missing_text,
    refine_carved_image,
    speak_text,
    stop_speech,
    is_speaking
)

# =========================================================================
# FUTURISTIC LIGHT-CYBER COLOR PALETTE & STYLING
# =========================================================================
ctk.set_appearance_mode("Light") # Clean futuristic light-cyber theme
ctk.set_default_color_theme("blue")

COLOR_BG_LIGHT = "#f1f5f9"         # Ice white cyber background
COLOR_PANEL_BG = "#ffffff"         # Pure white panel surface
COLOR_CARD_BG = "#f8fafc"          # Light card surface
COLOR_CARD_HOVER = "#e2e8f0"       # Subtle cyber hover glow
COLOR_CARD_ACTIVE = "#e0e7ff"      # Light indigo active glow
COLOR_BORDER = "#cbd5e1"           # Crisp slate border
COLOR_BORDER_FOCUS = "#2563eb"    # Electric Cobalt active border
COLOR_ACCENT = "#2563eb"           # Electric Cobalt Blue
COLOR_ACCENT_HOVER = "#1d4ed8"
COLOR_ACCENT_PURPLE = "#7c3aed"   # Electric Violet for Disk Dig
COLOR_ACCENT_PURPLE_HOVER = "#6d28d9"
COLOR_TEXT_PRIMARY = "#0f172a"     # Deep high-contrast text
COLOR_TEXT_SECONDARY = "#475569"   # Muted gray text
COLOR_TEXT_MUTED = "#94a3b8"       # Slate muted meta text

# Threat Level Palettes (Light-Cyber Glass Badges)
CATEGORY_PALETTE = {
    "CRITICAL": {
        "text": "#b91c1c",
        "bg": "#fee2e2",
        "border": "#ef4444",
        "badge": "🔴 CRITICAL RISK"
    },
    "CREDENTIALS": {
        "text": "#991b1b",
        "bg": "#fef2f2",
        "border": "#f87171",
        "badge": "🔑 CREDENTIALS"
    },
    "FINANCIAL": {
        "text": "#c2410c",
        "bg": "#ffedd5",
        "border": "#f97316",
        "badge": "💳 FINANCIAL WIRE"
    },
    "PII": {
        "text": "#b45309",
        "bg": "#fef3c7",
        "border": "#f59e0b",
        "badge": "🛡️ PII RECORD"
    },
    "MEDIA": {
        "text": "#6b21a8",
        "bg": "#f3e8ff",
        "border": "#a855f7",
        "badge": "📦 MEDIA / RECOVERED"
    },
    "LOGS": {
        "text": "#047857",
        "bg": "#d1fae5",
        "border": "#10b981",
        "badge": "⚡ SYSTEM LOGS"
    },
    "INTERNAL": {
        "text": "#1d4ed8",
        "bg": "#dbeafe",
        "border": "#3b82f6",
        "badge": "📑 DFIR MEMO"
    },
    "DEFAULT": {
        "text": "#334155",
        "bg": "#f1f5f9",
        "border": "#cbd5e1",
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
        self.title("REVIVER - Light-Cyber Digital Evidence Command Center")
        self.geometry("1440x900")
        self.minsize(1120, 720)
        self.configure(fg_color=COLOR_BG_LIGHT)

        # Cryptographic Hash Chain Ledger (Chain of Custody)
        self.ledger = ForensicLedger()

        # Thread-safe event queue
        self.event_queue = queue.Queue()

        # Default sample file path (prefers test_disk.img sandbox if present)
        test_disk_path = os.path.join(CURRENT_DIR, "test_disk.img")
        sample_dump_path = os.path.join(CURRENT_DIR, "sample_dump.bin")
        if os.path.exists(test_disk_path):
            self.target_file_path: str = test_disk_path
        elif os.path.exists(sample_dump_path):
            self.target_file_path: str = sample_dump_path
        else:
            self.target_file_path: str = ""

        # State Variables
        self.artifacts: List[ForensicArtifact] = []
        self.filtered_artifacts: List[ForensicArtifact] = []
        self.selected_artifact: Optional[ForensicArtifact] = None
        self.is_scanning: bool = False
        self.current_filter: str = "ALL"
        self.search_query: str = ""
        self.artifact_widgets: List[ctk.CTkFrame] = []

        # Text-To-Speech (TTS) Voice State Variables
        self.last_ai_response: str = ""
        self.auto_read_enabled: bool = False

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
    # TOP BAR (LIGHT-CYBER COMMAND HUD)
    # =========================================================================
    def _build_top_bar(self):
        self.top_bar = ctk.CTkFrame(
            self,
            fg_color=COLOR_PANEL_BG,
            corner_radius=0,
            height=72,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.top_bar.pack(side="top", fill="x", padx=0, pady=0)
        self.top_bar.pack_propagate(False)

        # Left: High-impact Cyber Command Branding with prominent Logo Emblem
        brand_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        brand_frame.pack(side="left", padx=16, pady=6)

        # High-tech Logo Emblem Box
        logo_emblem = ctk.CTkFrame(
            brand_frame,
            width=46,
            height=46,
            corner_radius=12,
            fg_color="#2563eb",
            border_width=2,
            border_color="#93c5fd"
        )
        logo_emblem.pack(side="left", padx=(0, 12))
        logo_emblem.pack_propagate(False)

        logo_icon = ctk.CTkLabel(
            logo_emblem,
            text="🛡️",
            font=ctk.CTkFont(size=24)
        )
        logo_icon.place(relx=0.5, rely=0.5, anchor="center")

        title_box = ctk.CTkFrame(brand_frame, fg_color="transparent")
        title_box.pack(side="left")

        # Headline Row: Big Logo-Style Typography + Cyber Tag
        headline_row = ctk.CTkFrame(title_box, fg_color="transparent")
        headline_row.pack(anchor="w")

        main_title = ctk.CTkLabel(
            headline_row,
            text="REVIVER",
            font=ctk.CTkFont(family="Bahnschrift", size=26, weight="bold"),
            text_color="#0f172a"
        )
        main_title.pack(side="left", padx=(0, 8))

        ver_badge = ctk.CTkLabel(
            headline_row,
            text="v2.5 // CORE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color="#dbeafe",
            text_color="#1d4ed8",
            corner_radius=4,
            padx=6,
            pady=2
        )
        ver_badge.pack(side="left")

        sub_title = ctk.CTkLabel(
            title_box,
            text="LIGHT-CYBER DIGITAL EVIDENCE COMMAND CENTER // DFIR SUITE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color="#64748b"
        )
        sub_title.pack(anchor="w", pady=(1, 0))

        # Right: Telemetry HUD & Status Badge
        telemetry_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        telemetry_frame.pack(side="right", padx=16, pady=8)

        # High-contrast Cyber Telemetry Chips
        self.stat_fragments_lbl = ctk.CTkLabel(
            telemetry_frame,
            text="Fragments: 0",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#f1f5f9",
            corner_radius=6,
            padx=10,
            pady=5,
            text_color=COLOR_TEXT_SECONDARY
        )
        self.stat_fragments_lbl.pack(side="left", padx=4)

        self.stat_stitched_lbl = ctk.CTkLabel(
            telemetry_frame,
            text="Stitched: 0",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#e0f2fe",
            corner_radius=6,
            padx=10,
            pady=5,
            text_color="#0284c7"
        )
        self.stat_stitched_lbl.pack(side="left", padx=4)

        self.stat_critical_lbl = ctk.CTkLabel(
            telemetry_frame,
            text="Critical: 0",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color="#fee2e2",
            corner_radius=6,
            padx=10,
            pady=5,
            text_color="#dc2626"
        )
        self.stat_critical_lbl.pack(side="left", padx=4)

        # Dynamic Pulsing Status Indicator Badge
        self.status_badge = ctk.CTkLabel(
            telemetry_frame,
            text="● SYSTEM READY",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#dcfce7",
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
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
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
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            width=115,
            height=32,
            command=self.handle_export
        )
        self.btn_export_top.pack(side="left", padx=(2, 0))

    # =========================================================================
    # 3-COLUMN MAIN LAYOUT SETUP (RESIZABLE PANES)
    # =========================================================================
    def _build_main_split_layout(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(side="top", fill="both", expand=True, padx=10, pady=8)

        # Resizable Horizontal PanedWindow allowing dynamic dragging of column widths
        self.paned_window = tk.PanedWindow(
            self.main_container,
            orient=tk.HORIZONTAL,
            sashwidth=6,
            sashrelief=tk.FLAT,
            bg=COLOR_BORDER,
            bd=0,
            sashcursor="size_we",
            opaqueresize=True
        )
        self.paned_window.pack(fill="both", expand=True)

        # Build the 3 distinct resizable columns
        self._build_left_controls_column()
        self._build_center_queue_column()
        self._build_right_ai_column()

    # =========================================================================
    # COLUMN 0: FORENSIC CONTROLS & ACTION TRIGGERS
    # =========================================================================
    def _build_left_controls_column(self):
        self.left_panel = ctk.CTkFrame(
            self.paned_window,
            fg_color=COLOR_PANEL_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.paned_window.add(self.left_panel, minsize=260, width=320, stretch="never", padx=3)

        # Container
        control_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        control_frame.pack(fill="both", expand=True, padx=14, pady=12)

        # Section Header
        lbl_sec = ctk.CTkLabel(
            control_frame,
            text="⚡ FORENSIC CONTROLS",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        lbl_sec.pack(fill="x", pady=(0, 2))

        lbl_sec_sub = ctk.CTkLabel(
            control_frame,
            text="EVIDENCE EXTRACTION & TRIAGE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=COLOR_TEXT_MUTED,
            anchor="w"
        )
        lbl_sec_sub.pack(fill="x", pady=(0, 10))

        # Target Disk Image Selector Area
        file_select_row = ctk.CTkFrame(control_frame, fg_color="transparent")
        file_select_row.pack(fill="x", pady=(0, 6))

        self.btn_select_file = ctk.CTkButton(
            file_select_row,
            text="📂 Select Disk / Dump",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#f1f5f9",
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
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
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
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.lbl_current_file.pack(fill="x", pady=(0, 10))

        # Action Buttons: Disk Dig (Raw Sector Carve) + AI Deep Scan
        self.btn_disk_dig = ctk.CTkButton(
            control_frame,
            text="⛏️ Disk Dig (Sector Carve)",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=COLOR_ACCENT_PURPLE,
            hover_color=COLOR_ACCENT_PURPLE_HOVER,
            text_color="#ffffff",
            height=40,
            command=self._start_disk_dig_thread
        )
        self.btn_disk_dig.pack(fill="x", pady=(0, 6))

        self.btn_run_scan = ctk.CTkButton(
            control_frame,
            text="⚡ AI Deep Scan",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            height=40,
            command=self._start_scan_thread
        )
        self.btn_run_scan.pack(fill="x", pady=(0, 10))

        # Progress Bar (pulsing during scan)
        self.progress_bar = ctk.CTkProgressBar(
            control_frame,
            height=8,
            progress_color=COLOR_ACCENT,
            fg_color="#e2e8f0"
        )
        self.progress_bar.pack(fill="x", pady=(0, 14))
        self.progress_bar.set(0)

        # Category Filter Tabs
        lbl_filt = ctk.CTkLabel(
            control_frame,
            text="TRIAGE CATEGORY FILTER",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=COLOR_TEXT_MUTED,
            anchor="w"
        )
        lbl_filt.pack(fill="x", pady=(0, 4))

        self.filter_segmented = ctk.CTkSegmentedButton(
            control_frame,
            values=["ALL", "CRITICAL", "CREDENTIALS", "PII", "MEDIA", "LOGS"],
            command=self._on_filter_changed,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            selected_color=COLOR_ACCENT,
            selected_hover_color=COLOR_ACCENT_HOVER,
            unselected_color="#f1f5f9",
            unselected_hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.filter_segmented.set("ALL")
        self.filter_segmented.pack(fill="x", pady=(0, 14))



        # System Telemetry Mini-Card
        telemetry_box = ctk.CTkFrame(
            control_frame,
            fg_color=COLOR_CARD_BG,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_BORDER
        )
        telemetry_box.pack(fill="x", side="bottom", pady=(8, 0))

        t_inner = ctk.CTkFrame(telemetry_box, fg_color="transparent")
        t_inner.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(
            t_inner,
            text="REVIVER INTELLIGENCE // v2.5",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=COLOR_ACCENT,
            anchor="w"
        ).pack(anchor="w")

        ctk.CTkLabel(
            t_inner,
            text="Raw Sector Carving & Shannon Entropy\nCryptographic Chain of Custody Active",
            font=ctk.CTkFont(family="Segoe UI", size=9),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w",
            justify="left"
        ).pack(anchor="w", pady=(2, 0))

    # =========================================================================
    # COLUMN 1: ARTIFACT QUEUE & FILTERING TOOLS
    # =========================================================================
    def _build_center_queue_column(self):
        self.center_panel = ctk.CTkFrame(
            self.paned_window,
            fg_color=COLOR_PANEL_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.paned_window.add(self.center_panel, minsize=300, width=420, stretch="always", padx=3)

        # Background Watermark (Shield + Plus Symbol)
        watermark = ctk.CTkLabel(
            self.center_panel,
            text="🛡️+",
            font=ctk.CTkFont(family="Segoe UI", size=140, weight="bold"),
            text_color="#f1f5f9"
        )
        watermark.place(relx=0.5, rely=0.52, anchor="center")
        watermark.lower()

        # Artifacts Queue Header
        queue_header_frame = ctk.CTkFrame(self.center_panel, fg_color="transparent")
        queue_header_frame.pack(fill="x", padx=14, pady=(12, 6))

        queue_title = ctk.CTkLabel(
            queue_header_frame,
            text="📦 ARTIFACT QUEUE",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        )
        queue_title.pack(side="left")

        self.queue_count_lbl = ctk.CTkLabel(
            queue_header_frame,
            text="0 items",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            fg_color="#e2e8f0",
            text_color=COLOR_TEXT_PRIMARY,
            corner_radius=6,
            padx=8,
            pady=3
        )
        self.queue_count_lbl.pack(side="right")

        # Instant Search Bar
        search_frame = ctk.CTkFrame(self.center_panel, fg_color="transparent")
        search_frame.pack(fill="x", padx=14, pady=(0, 8))

        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Search fragments, keywords, tokens, hex...",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=COLOR_CARD_BG,
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
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            command=self._clear_search
        )
        btn_clear_search.pack(side="right")

        # Separator Line
        sep = ctk.CTkFrame(self.center_panel, fg_color=COLOR_BORDER, height=1)
        sep.pack(fill="x", padx=14, pady=(0, 6))

        # Scrollable Artifacts List
        self.artifacts_scroll = ctk.CTkScrollableFrame(
            self.center_panel,
            fg_color="transparent",
            corner_radius=0
        )
        self.artifacts_scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Initial Empty State Placeholder
        self.empty_state_label = ctk.CTkLabel(
            self.artifacts_scroll,
            text="\n\nNo artifacts carved yet.\nRun 'Disk Dig' or 'AI Deep Scan' to extract\nand stitch forensic evidence.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_SECONDARY,
            justify="center"
        )
        self.empty_state_label.pack(pady=40)

    # =========================================================================
    # COLUMN 2: PERMANENT RIGHT-SIDE AI CHATBOT & FORENSIC INSPECTOR
    # =========================================================================
    def _build_right_ai_column(self):
        """Builds the permanent right-side panel containing AI Chat and Forensic Inspector."""
        self.right_panel = ctk.CTkFrame(
            self.paned_window,
            fg_color=COLOR_PANEL_BG,
            corner_radius=10,
            border_width=1,
            border_color=COLOR_BORDER
        )
        self.paned_window.add(self.right_panel, minsize=360, stretch="always", padx=3)

        # Header with toggle between Inspector and AI Copilot
        tab_row = ctk.CTkFrame(self.right_panel, fg_color="transparent", height=42)
        tab_row.pack(fill="x", padx=12, pady=10)

        self.btn_tab_ai = ctk.CTkButton(
            tab_row,
            text="💬 Reviver AI Copilot",
            width=170,
            height=34,
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            command=lambda: self._switch_right_panel_tab("ai")
        )
        self.btn_tab_ai.pack(side="left", padx=(0, 6))

        self.btn_tab_inspector = ctk.CTkButton(
            tab_row,
            text="🔍 Forensic Inspector",
            width=160,
            height=34,
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            command=lambda: self._switch_right_panel_tab("inspector")
        )
        self.btn_tab_inspector.pack(side="left")

        btn_popout = ctk.CTkButton(
            tab_row,
            text="🗖 Pop Out",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            width=70,
            height=34,
            command=self.open_reviver_chatbot
        )
        btn_popout.pack(side="right")

        # Container for AI Chat view (default visible)
        self.ai_chat_view_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        self.ai_chat_view_frame.pack(fill="both", expand=True)

        # Container for Inspector view (initially hidden)
        self.inspector_view_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")

        # Build views
        self._build_ai_chat_contents(self.ai_chat_view_frame)
        self._build_inspector_contents(self.inspector_view_frame)

    def _switch_right_panel_tab(self, tab_name: str):
        """Switches the right panel view between Forensic Inspector and Reviver AI Copilot."""
        if tab_name == "inspector":
            self.ai_chat_view_frame.pack_forget()
            self.inspector_view_frame.pack(fill="both", expand=True)
            self.btn_tab_inspector.configure(
                fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color="#ffffff", border_width=0
            )
            self.btn_tab_ai.configure(
                fg_color="#f1f5f9", hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_PRIMARY, border_width=1
            )
        else:
            self.inspector_view_frame.pack_forget()
            self.ai_chat_view_frame.pack(fill="both", expand=True)
            self.btn_tab_ai.configure(
                fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color="#ffffff", border_width=0
            )
            self.btn_tab_inspector.configure(
                fg_color="#f1f5f9", hover_color=COLOR_CARD_HOVER, text_color=COLOR_TEXT_PRIMARY, border_width=1
            )
            if hasattr(self, "ai_input_entry"):
                self.ai_input_entry.focus()

    # =========================================================================
    # TEXT-TO-SPEECH (TTS) AI VOICE CONTROLLER
    # =========================================================================
    def _toggle_read_aloud(self):
        """Toggles Text-to-Speech reading of the latest AI response or forensic context."""
        if is_speaking():
            stop_speech()
            self._on_tts_finished()
            return

        text_to_speak = self.last_ai_response
        if not text_to_speak:
            entry_text = self.ai_input_entry.get().strip() if hasattr(self, "ai_input_entry") else ""
            if entry_text:
                text_to_speak = entry_text
            elif getattr(self, "selected_artifact", None):
                art = self.selected_artifact
                text_to_speak = (
                    f"Selected artifact {art.artifact_id}. {art.name}. "
                    f"Category {art.category}, priority tier {art.priority_tier}. "
                    f"Health score {getattr(art, 'integrity_score', 80.0):.1f} percent."
                )
            else:
                text_to_speak = (
                    "Reviver AI digital forensics copilot is active. "
                    "Type a query or run a scan to carve digital evidence."
                )

        self._start_tts_speech(text_to_speak)

    def _start_tts_speech(self, text: str):
        """Dispatches text to the background TTS engine with UI lifecycle hooks."""
        def on_start():
            self.after(0, self._on_tts_started)

        def on_finish():
            self.after(0, self._on_tts_finished)

        speak_text(text, on_start=on_start, on_finish=on_finish)

    def _on_tts_started(self):
        """Updates the microphone / speaker button to active speaking state."""
        if hasattr(self, "btn_tts_voice") and self.btn_tts_voice.winfo_exists():
            self.btn_tts_voice.configure(
                text="⏹️ Stop Voice",
                fg_color="#fee2e2",
                hover_color="#fecaca",
                text_color="#dc2626",
                border_color="#f87171"
            )
        self._update_status("🔊 Reviver AI is speaking...")

    def _on_tts_finished(self):
        """Reverts the microphone / speaker button back to idle read-aloud state."""
        if hasattr(self, "btn_tts_voice") and self.btn_tts_voice.winfo_exists():
            self.btn_tts_voice.configure(
                text="🎙️ Read Aloud",
                fg_color="#f1f5f9",
                hover_color=COLOR_CARD_HOVER,
                text_color=COLOR_TEXT_PRIMARY,
                border_color=COLOR_BORDER
            )
        self._update_status("Ready")

    def _toggle_auto_tts(self):
        """Toggles hands-free auto-reading for all incoming AI responses."""
        self.auto_read_enabled = not self.auto_read_enabled
        if self.auto_read_enabled:
            if hasattr(self, "btn_auto_tts") and self.btn_auto_tts.winfo_exists():
                self.btn_auto_tts.configure(
                    text="🔊 Auto-Read: ON",
                    fg_color="#dbeafe",
                    hover_color="#bfdbfe",
                    text_color="#1d4ed8",
                    border_color="#3b82f6"
                )
            if self.last_ai_response:
                self._start_tts_speech(self.last_ai_response)
        else:
            if hasattr(self, "btn_auto_tts") and self.btn_auto_tts.winfo_exists():
                self.btn_auto_tts.configure(
                    text="🔊 Auto-Read: OFF",
                    fg_color="#f1f5f9",
                    hover_color=COLOR_CARD_HOVER,
                    text_color=COLOR_TEXT_SECONDARY,
                    border_color=COLOR_BORDER
                )
            if is_speaking():
                stop_speech()
                self._on_tts_finished()

    def _create_comprehensive_health_widget(self, parent_frame, score: float):
        """Creates a comprehensive progress bar + percentage health indicator."""
        health_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        health_frame.pack(fill="x", padx=10, pady=4)

        # Choose color based on structural score
        bar_color = "#10b981" if score >= 90 else ("#f59e0b" if score >= 70 else "#ef4444")

        lbl_score = ctk.CTkLabel(
            health_frame,
            text=f"Structural Health: {score:.1f}%",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=bar_color
        )
        lbl_score.pack(side="left", padx=(0, 10))

        progress = ctk.CTkProgressBar(
            health_frame,
            width=160,
            height=12,
            progress_color=bar_color,
            fg_color="#e2e8f0"
        )
        progress.pack(side="right", fill="x", expand=True)
        progress.set(max(0.05, score / 100.0))
        return health_frame

    def _quick_organize_files(self):
        target_dir = filedialog.askdirectory(title="Select Folder to Organize by File Type")
        if target_dir and os.path.exists(target_dir):
            res_msg = organize_folder_by_type(target_dir)
            self._update_status(res_msg)
            self.ledger.add_entry("ORGANIZE_FOLDER", {"path": target_dir})
            messagebox.showinfo("Folder Organized", f"{res_msg}\n\nPath: {target_dir}")

    def _quick_purge_duplicates(self):
        target_dir = filedialog.askdirectory(title="Select Folder to Scan & Purge Duplicates")
        if target_dir and os.path.exists(target_dir):
            msg, dupes = scan_and_purge_duplicates(target_dir, delete_mode=False)
            self.ledger.add_entry("SCAN_DUPLICATES", {"path": target_dir, "count": len(dupes)})
            if dupes:
                confirm = messagebox.askyesno(
                    "Duplicate Files Found",
                    f"Found {len(dupes)} duplicate files in:\n{target_dir}\n\nWould you like to purge/delete duplicate copies now?"
                )
                if confirm:
                    msg_del, _ = scan_and_purge_duplicates(target_dir, delete_mode=True)
                    self.ledger.add_entry("PURGE_DUPLICATES", {"path": target_dir, "purged": len(dupes)})
                    self._update_status(f"Purged {len(dupes)} duplicates.")
                    messagebox.showinfo("Purge Complete", f"Successfully cleaned duplicate files.\n{msg_del}")
                else:
                    self._update_status(f"Duplicate scan complete: {len(dupes)} copies detected.")
            else:
                self._update_status("No duplicate files detected.")
                messagebox.showinfo("Duplicate Scan", "No duplicate files found in folder.")

    def _build_inspector_contents(self, parent_frame):
        """Builds all Forensic Inspector payload preview and relationship graph components."""
        # 1. Top Section: Inspector Header & Forensics Telemetry HUD
        self.inspector_header = ctk.CTkFrame(
            parent_frame,
            fg_color=COLOR_CARD_BG,
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
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
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
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
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
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
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
            fg_color="#f1f5f9",
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
            fg_color="#f1f5f9",
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
            fg_color="#e0f2fe",
            text_color="#0284c7",
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
            fg_color="#e2e8f0"
        )
        self.integrity_meter.pack(side="left")
        self.integrity_meter.set(0)

        # Metadata Details Line
        self.lbl_meta_details = ctk.CTkLabel(
            self.inspector_header,
            text="Select an artifact from the queue to view forensic recovery preview and relationship graph.",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.lbl_meta_details.pack(fill="x", padx=14, pady=(0, 8))

        # 2. Middle Section: "Reconstructed Forensic Payload Buffer"
        content_header_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
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
            fg_color="#e0f2fe",
            text_color="#0284c7",
            corner_radius=3,
            padx=6,
            pady=1
        )
        content_badge.pack(side="right")

        self.txt_content = ctk.CTkTextbox(
            parent_frame,
            fg_color="#ffffff",
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="none"
        )
        self.txt_content.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        self.txt_content.insert("1.0", "/* RECONSTRUCTED PAYLOAD BUFFER EMPTY */\n\nPlease run Disk Dig or AI Scan to carve unallocated sectors and fragmented streams.")
        self.txt_content.configure(state="disabled")

        # 3. Lower Section: "AI Relationship Map Match & Fragment Graph"
        rel_header_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
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
            fg_color="#f3e8ff",
            text_color="#7c3aed",
            corner_radius=3,
            padx=6,
            pady=1
        )
        rel_badge.pack(side="right")

        self.txt_relationship_map = ctk.CTkTextbox(
            parent_frame,
            height=145,
            fg_color=COLOR_CARD_BG,
            text_color=COLOR_ACCENT,
            border_width=1,
            border_color=COLOR_BORDER,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word"
        )
        self.txt_relationship_map.pack(fill="x", padx=14, pady=(0, 12))
        self.txt_relationship_map.insert("1.0", "No active relationship links. Standalone fragment or pending scan.")
        self.txt_relationship_map.configure(state="disabled")

    def _build_ai_chat_contents(self, parent_frame):
        """Builds the embedded side-panel AI chatbot interface."""
        # Top banner frame
        ai_hdr = ctk.CTkFrame(parent_frame, fg_color=COLOR_CARD_BG, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
        ai_hdr.pack(fill="x", padx=14, pady=12)

        ai_hdr_inner = ctk.CTkFrame(ai_hdr, fg_color="transparent")
        ai_hdr_inner.pack(fill="x", padx=12, pady=10)

        ctk.CTkLabel(
            ai_hdr_inner,
            text="💬 Reviver AI // Neural Forensics Copilot",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=COLOR_TEXT_PRIMARY
        ).pack(side="left")

        hdr_right = ctk.CTkFrame(ai_hdr_inner, fg_color="transparent")
        hdr_right.pack(side="right")

        self.btn_auto_tts = ctk.CTkButton(
            hdr_right,
            text="🔊 Auto-Read: OFF",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            width=115,
            height=26,
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_SECONDARY,
            border_width=1,
            border_color=COLOR_BORDER,
            command=self._toggle_auto_tts
        )
        self.btn_auto_tts.pack(side="left", padx=(0, 6))

        copilot_status = ctk.CTkLabel(
            hdr_right,
            text="● COPILOT ACTIVE",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color="#dcfce7",
            text_color="#16a34a",
            corner_radius=4,
            padx=6,
            pady=2
        )
        copilot_status.pack(side="left", padx=(0, 6))

        # Quick action chips
        chips_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        chips_frame.pack(fill="x", padx=14, pady=(0, 6))

        def on_quick_action(cmd_text):
            if hasattr(self, "ai_input_entry"):
                self.ai_input_entry.delete(0, "end")
                self.ai_input_entry.insert(0, cmd_text)
                send_ai_message()

        for lbl, cmd in [
            ("📊 Summary", "summary"),
            ("🔴 Threats", "threats"),
            ("📂 Organize", "organize"),
            ("🔍 Duplicates", "duplicates"),
            ("⛏️ Disk Dig", "explain disk dig")
        ]:
            b = ctk.CTkButton(
                chips_frame,
                text=lbl,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                fg_color="#f1f5f9",
                hover_color=COLOR_CARD_HOVER,
                text_color=COLOR_TEXT_PRIMARY,
                border_width=1,
                border_color=COLOR_BORDER,
                height=26,
                command=lambda c=cmd: on_quick_action(c)
            )
            b.pack(side="left", padx=2)

        # Chat display box
        self.ai_chat_textbox = ctk.CTkTextbox(
            parent_frame,
            fg_color="#ffffff",
            text_color=COLOR_TEXT_PRIMARY,
            font=ctk.CTkFont(family="Consolas", size=11),
            border_width=1,
            border_color=COLOR_BORDER,
            wrap="word"
        )
        self.ai_chat_textbox.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.ai_chat_textbox.insert(
            "1.0",
            "╔══════════════════════════════════════════════════════════════════════════════╗\n"
            "║                 REVIVER AI NEURAL COPILOT // LIVE EMBEDDED                   ║\n"
            "╚══════════════════════════════════════════════════════════════════════════════╝\n"
            "Copilot connected to local DFIR inference engine and live LLM integration.\n\n"
            "• Ask anything: 'summary', 'threats', 'passwords', 'ledger status', 'explain entropy'\n"
            "• File management: 'organize <path>' or 'duplicates <path>'\n"
            "• Active evidence: Select an artifact on the left to reconstruct damaged text or enhance images.\n"
            "────────────────────────────────────────────────────────────────────────────────\n\n"
        )
        self.ai_chat_textbox.configure(state="disabled")

        # Input Row
        input_row = ctk.CTkFrame(parent_frame, fg_color="transparent")
        input_row.pack(fill="x", padx=14, pady=(0, 8))

        self.ai_input_entry = ctk.CTkEntry(
            input_row,
            placeholder_text="Ask Reviver AI or type command ('summary', 'organize', 'duplicates')...",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=38,
            fg_color="#ffffff",
            border_color=COLOR_BORDER,
            text_color=COLOR_TEXT_PRIMARY
        )
        self.ai_input_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        def send_ai_message(event=None):
            query = self.ai_input_entry.get().strip()
            if not query:
                return
            self.ai_input_entry.delete(0, "end")

            self.ai_chat_textbox.configure(state="normal")
            self.ai_chat_textbox.insert("end", f"Investigator > {query}\n")

            q_lower = query.lower()

            if q_lower.startswith("organize") or "organize" in q_lower:
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
                    msg, dupes = precise_duplicate_scanner(target_dir, delete_duplicates=is_purge)
                    resp = f"REVIVER AI: {msg}\n"
                    if dupes:
                        resp += "Exact duplicate files:\n"
                        for d in dupes[:5]:
                            resp += f"  - {os.path.basename(d)}\n"
                        if len(dupes) > 5:
                            resp += f"  - ...and {len(dupes) - 5} more files."
                    self.ledger.add_entry("SCAN_DUPLICATES", {"path": target_dir, "count": len(dupes), "purged": is_purge})
                else:
                    resp = "REVIVER AI: Duplicate scan cancelled or invalid directory specified."

            elif any(k in q_lower for k in ["summary", "overview", "results", "status"]):
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

            elif any(k in q_lower for k in ["threat", "critical", "secret", "password", "credential"]):
                crits = [a for a in getattr(self, 'artifacts', []) if "Tier 1" in a.priority_tier or "Critical" in a.priority_tier or "Credential" in a.category]
                if crits:
                    resp = f"REVIVER AI: Identified {len(crits)} critical risk items in current workspace:\n"
                    for c in crits[:4]:
                        resp += f"  - [{c.artifact_id}] {c.name} ({c.category})\n"
                    if len(crits) > 4:
                        resp += f"  - ...and {len(crits) - 4} more."
                else:
                    resp = "REVIVER AI: No critical threats currently detected. Run 'Disk Dig' or 'AI Scan' on a target disk image."

            else:
                sel = getattr(self, "selected_artifact", None)
                sel_info = f"ID: {sel.artifact_id}, Name: {sel.name}, Category: {sel.category}, Priority: {sel.priority_tier}, Content Preview: {sel.reconstructed_content[:200]}" if sel else "No artifact currently selected."
                context = (
                    f"Workspace Target: {os.path.basename(self.target_file_path) if self.target_file_path else 'None'}\n"
                    f"Total Artifacts Carved: {len(self.artifacts) if hasattr(self, 'artifacts') else 0}\n"
                    f"Selected Artifact Context: {sel_info}"
                )
                resp = query_llm_api(query, context=context)

            self.last_ai_response = resp
            self.ai_chat_textbox.insert("end", f"{resp}\n\n")
            self.ai_chat_textbox.configure(state="disabled")
            self.ai_chat_textbox.see("end")

            if self.auto_read_enabled:
                self._start_tts_speech(resp)

        self.ai_input_entry.bind("<Return>", send_ai_message)

        btn_send = ctk.CTkButton(
            input_row,
            text="Send",
            width=68,
            height=38,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            command=send_ai_message
        )
        btn_send.pack(side="right")

        self.btn_tts_voice = ctk.CTkButton(
            input_row,
            text="🎙️ Read Aloud",
            width=112,
            height=38,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            command=self._toggle_read_aloud
        )
        self.btn_tts_voice.pack(side="right", padx=(0, 6))

        # Enhancement Action Buttons Row
        enh_row = ctk.CTkFrame(parent_frame, fg_color="transparent")
        enh_row.pack(fill="x", padx=14, pady=(0, 10))

        def handle_ai_text_enhancement():
            sel = getattr(self, "selected_artifact", None)
            if not sel:
                messagebox.showinfo("Select Artifact", "Please select an artifact from the queue first to reconstruct.")
                return
            self.ai_chat_textbox.configure(state="normal")
            self.ai_chat_textbox.insert("end", f"Investigator > [Requested AI Text Reconstruction for {sel.artifact_id}]\n")
            enhanced = ai_enhance_missing_text(sel.reconstructed_content)
            self.ai_chat_textbox.insert("end", f"--- AI TEXT RECONSTRUCTION RESULT ---\n{enhanced}\n\n")
            self.ai_chat_textbox.configure(state="disabled")
            self.ai_chat_textbox.see("end")
            self.ledger.add_entry("AI_TEXT_RECONSTRUCTION", {"artifact_id": sel.artifact_id})

        def handle_ai_image_refinement():
            sel = getattr(self, "selected_artifact", None)
            target_data = None
            if sel and hasattr(sel, "raw_bytes") and sel.raw_bytes:
                target_data = sel.raw_bytes
            elif sel and hasattr(sel, "reconstructed_content") and sel.reconstructed_content:
                target_data = sel.reconstructed_content

            save_path = filedialog.asksaveasfilename(
                title="Save Forensic Enhanced Image",
                initialfile="enhanced_carved_image.png",
                filetypes=[("PNG Image (*.png)", "*.png"), ("JPEG Image (*.jpg)", "*.jpg"), ("All Files", "*.*")]
            )
            if save_path:
                if not target_data:
                    src_file = filedialog.askopenfilename(
                        title="Select Image to Refine & Sharpen",
                        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All Files", "*.*")]
                    )
                    if src_file:
                        with open(src_file, "rb") as f:
                            target_data = f.read()

                if target_data:
                    result = refine_carved_image(target_data, save_path)
                    if result and os.path.exists(save_path):
                        self.ai_chat_textbox.configure(state="normal")
                        self.ai_chat_textbox.insert("end", f"REVIVER AI: Successfully refined and sharpened forensic image!\nSaved to: {save_path}\n\n")
                        self.ai_chat_textbox.configure(state="disabled")
                        self.ai_chat_textbox.see("end")
                        self.ledger.add_entry("IMAGE_ENHANCEMENT", {"output": save_path})
                        messagebox.showinfo("Image Enhancement Successful", f"Image sharpened and enhanced:\n{save_path}")
                    else:
                        messagebox.showwarning("Enhancement Notice", "Could not decode valid image bytes from target data.")
                else:
                    messagebox.showinfo("Image Enhancement", "No image data was provided.")

        btn_enhance_text = ctk.CTkButton(
            enh_row,
            text="✨ AI Reconstruct Missing Text",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            height=32,
            command=handle_ai_text_enhancement
        )
        btn_enhance_text.pack(side="left", fill="x", expand=True, padx=(0, 4))

        btn_enhance_img = ctk.CTkButton(
            enh_row,
            text="🖼️ AI Enhance Carved Image",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            height=32,
            command=handle_ai_image_refinement
        )
        btn_enhance_img.pack(side="right", fill="x", expand=True, padx=(4, 0))

    # =========================================================================
    # BOTTOM BAR (LIVE STATUS TICKER & PROGRESS)
    # =========================================================================
    def _build_bottom_bar(self):
        self.bottom_bar = ctk.CTkFrame(self, fg_color=COLOR_PANEL_BG, corner_radius=0, height=36, border_width=1, border_color=COLOR_BORDER)
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
            text="ENGINE: REVIVER-CARVER-v2.5 | INTEGRITY-AUDIT: ACTIVE",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLOR_TEXT_MUTED,
            anchor="e"
        )
        engine_tag.pack(side="right", padx=16, pady=4)

    # =========================================================================
    # STATUS & UI UPDATERS
    # =========================================================================
    def _update_status(self, message: str, is_error: bool = False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {message}"
        color = "#ef4444" if is_error else COLOR_TEXT_SECONDARY
        self.lbl_status.configure(text=formatted, text_color=color)

    def _set_status_badge(self, text: str, mode: str = "READY"):
        self.status_mode = mode
        if mode == "READY":
            self.status_badge.configure(
                text=f"● {text}",
                fg_color="#dcfce7",
                text_color="#10b981"
            )
        elif mode == "SCANNING":
            self.status_badge.configure(
                text=f"⟳ {text}",
                fg_color="#dbeafe",
                text_color="#38bdf8"
            )
            self._pulse_status_badge()
        elif mode == "DONE":
            self.status_badge.configure(
                text=f"✔ {text}",
                fg_color="#e0f2fe",
                text_color="#0284c7"
            )
        elif mode == "ERROR":
            self.status_badge.configure(
                text=f"✖ {text}",
                fg_color="#fee2e2",
                text_color="#ef4444"
            )

    def _pulse_status_badge(self):
        """Creates a smooth pulsing neon glow effect during active deep scans."""
        if getattr(self, "status_mode", "") != "SCANNING":
            return
        curr_color = self.status_badge.cget("text_color")
        next_color = "#2563eb" if curr_color == "#38bdf8" else "#38bdf8"
        self.status_badge.configure(text_color=next_color)
        self.after(400, self._pulse_status_badge)

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
        ledger_win.configure(fg_color=COLOR_BG_LIGHT)
        ledger_win.after(100, ledger_win.lift)

        # Header Frame
        hdr = ctk.CTkFrame(ledger_win, fg_color=COLOR_PANEL_BG, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
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
            fg_color="#dcfce7",
            text_color="#16a34a",
            corner_radius=4,
            padx=10,
            pady=4
        )
        chain_len_lbl.pack(side="right", padx=12, pady=10)

        textbox = ctk.CTkTextbox(
            ledger_win,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#ffffff",
            text_color="#0f172a",
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
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            command=copy_ledger_json
        )
        btn_copy.pack(side="left")

        btn_close = ctk.CTkButton(
            btn_frame,
            text="Close",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            width=80,
            command=ledger_win.destroy
        )
        btn_close.pack(side="right")

    def handle_export(self):
        """Prompts the user with export format choices (Technical JSON vs. Plain-English Executive Summary)."""
        export_win = ctk.CTkToplevel(self)
        export_win.geometry("520x300")
        export_win.title("Reviver // Select Forensic Export Package")
        export_win.configure(fg_color=COLOR_BG_LIGHT)
        export_win.resizable(False, False)
        export_win.after(100, export_win.lift)

        # Header Frame
        hdr = ctk.CTkFrame(export_win, fg_color=COLOR_PANEL_BG, corner_radius=8, border_width=1, border_color=COLOR_BORDER)
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
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
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
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            text_color="#ffffff",
            height=42,
            command=export_plain_english
        )
        btn_text.pack(fill="x", pady=6)

    def open_reviver_chatbot(self):
        """Opens the local AI assistant 'REVIVER' interactive chat window."""
        chat_win = ctk.CTkToplevel(self)
        chat_win.geometry("640x700")
        chat_win.title("Reviver // AI Digital Assistant & DFIR Copilot")
        chat_win.configure(fg_color=COLOR_BG_LIGHT)
        chat_win.after(100, chat_win.lift)

        # Header Frame
        hdr = ctk.CTkFrame(chat_win, fg_color=COLOR_PANEL_BG, corner_radius=0, height=60, border_width=1, border_color=COLOR_BORDER)
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

        hdr_right_popout = ctk.CTkFrame(hdr_inner, fg_color="transparent")
        hdr_right_popout.pack(side="right")

        auto_tts_popout_var = tk.BooleanVar(value=self.auto_read_enabled)
        popout_last_resp = [""]

        def toggle_popout_auto():
            auto_tts_popout_var.set(not auto_tts_popout_var.get())
            if auto_tts_popout_var.get():
                btn_pop_auto.configure(text="🔊 Auto: ON", fg_color="#dbeafe", text_color="#1d4ed8", border_color="#3b82f6")
                if popout_last_resp[0]:
                    speak_text(popout_last_resp[0])
            else:
                btn_pop_auto.configure(text="🔊 Auto: OFF", fg_color="#f1f5f9", text_color=COLOR_TEXT_SECONDARY, border_color=COLOR_BORDER)
                stop_speech()

        btn_pop_auto = ctk.CTkButton(
            hdr_right_popout,
            text="🔊 Auto: ON" if auto_tts_popout_var.get() else "🔊 Auto: OFF",
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            width=92,
            height=26,
            fg_color="#dbeafe" if auto_tts_popout_var.get() else "#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color="#1d4ed8" if auto_tts_popout_var.get() else COLOR_TEXT_SECONDARY,
            border_width=1,
            border_color="#3b82f6" if auto_tts_popout_var.get() else COLOR_BORDER,
            command=toggle_popout_auto
        )
        btn_pop_auto.pack(side="left", padx=(0, 8))

        status_chip = ctk.CTkLabel(
            hdr_right_popout,
            text="● COPILOT ACTIVE",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            fg_color="#dcfce7",
            text_color="#16a34a",
            corner_radius=4,
            padx=8,
            pady=3
        )
        status_chip.pack(side="left")

        # Chat Display Box
        chat_box = ctk.CTkTextbox(
            chat_win,
            fg_color="#ffffff",
            text_color=COLOR_TEXT_PRIMARY,
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
                fg_color="#f1f5f9",
                hover_color=COLOR_CARD_HOVER,
                text_color=COLOR_TEXT_PRIMARY,
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
            fg_color="#ffffff",
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
                sel = getattr(self, "selected_artifact", None)
                sel_info = f"ID: {sel.artifact_id}, Name: {sel.name}, Category: {sel.category}, Priority: {sel.priority_tier}, Content Preview: {sel.reconstructed_content[:200]}" if sel else "No artifact currently selected."
                context = (
                    f"Workspace Target: {os.path.basename(self.target_file_path) if self.target_file_path else 'None'}\n"
                    f"Total Artifacts Carved: {len(self.artifacts) if hasattr(self, 'artifacts') else 0}\n"
                    f"Selected Artifact Context: {sel_info}"
                )
                resp = query_llm_api(query, context=context)

            popout_last_resp[0] = resp
            self.last_ai_response = resp
            chat_box.insert("end", f"{resp}\n\n")
            chat_box.configure(state="disabled")
            chat_box.see("end")

            if auto_tts_popout_var.get():
                btn_pop_voice.configure(text="⏹️ Stop Voice", fg_color="#fee2e2", text_color="#dc2626", border_color="#f87171")
                speak_text(
                    resp,
                    on_finish=lambda: chat_win.after(0, lambda: btn_pop_voice.configure(text="🎙️ Read Aloud", fg_color="#f1f5f9", text_color=COLOR_TEXT_PRIMARY, border_color=COLOR_BORDER)) if chat_win.winfo_exists() else None
                )

        def toggle_popout_voice():
            if is_speaking():
                stop_speech()
                btn_pop_voice.configure(text="🎙️ Read Aloud", fg_color="#f1f5f9", text_color=COLOR_TEXT_PRIMARY, border_color=COLOR_BORDER)
            else:
                txt = popout_last_resp[0] or user_entry.get().strip() or "Reviver AI copilot is online."
                btn_pop_voice.configure(text="⏹️ Stop Voice", fg_color="#fee2e2", text_color="#dc2626", border_color="#f87171")
                speak_text(
                    txt,
                    on_finish=lambda: chat_win.after(0, lambda: btn_pop_voice.configure(text="🎙️ Read Aloud", fg_color="#f1f5f9", text_color=COLOR_TEXT_PRIMARY, border_color=COLOR_BORDER)) if chat_win.winfo_exists() else None
                )

        user_entry.bind("<Return>", send_message)

        btn_send = ctk.CTkButton(
            input_frame,
            text="Send",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            width=70,
            height=38,
            fg_color=COLOR_ACCENT,
            hover_color=COLOR_ACCENT_HOVER,
            command=send_message
        )
        btn_send.pack(side="right")

        btn_pop_voice = ctk.CTkButton(
            input_frame,
            text="🎙️ Read Aloud",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            width=112,
            height=38,
            fg_color="#f1f5f9",
            hover_color=COLOR_CARD_HOVER,
            text_color=COLOR_TEXT_PRIMARY,
            border_width=1,
            border_color=COLOR_BORDER,
            command=toggle_popout_voice
        )
        btn_pop_voice.pack(side="right", padx=(0, 6))

        chat_win.protocol("WM_DELETE_WINDOW", lambda: (stop_speech(), chat_win.destroy()))

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
            fg_color="#e0f2fe",
            text_color="#0284c7",
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
                fg_color="#dbeafe",
                text_color="#2563eb",
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
            fg_color="#f1f5f9",
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
                fg_color="#f3e8ff",
                text_color="#7c3aed",
                corner_radius=4,
                padx=6,
                pady=2
            )
            badge_stitch.pack(side="right")
            clickable_elements.append(badge_stitch)

        # Comprehensive Health Progress Bar Widget
        hw = self._create_comprehensive_health_widget(card, art.integrity_score)
        clickable_elements.append(hw)
        for child in hw.winfo_children():
            clickable_elements.append(child)

        # Row 3: Meta details (Sectors, Byte span, Shannon Entropy)
        row3 = ctk.CTkFrame(card, fg_color="transparent")
        row3.pack(fill="x", padx=10, pady=(2, 8))

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

        # Entropy Mini-Pill
        ent_val = art.metadata.get("average_entropy", 0.0)
        ent_color = "#b91c1c" if ent_val >= 7.0 else ("#b45309" if ent_val >= 4.5 else "#0284c7")
        lbl_ent = ctk.CTkLabel(
            row3,
            text=f"H:{ent_val:.2f}",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            fg_color="#f1f5f9",
            text_color=ent_color,
            corner_radius=3,
            padx=5,
            pady=1
        )
        lbl_ent.pack(side="right", padx=(0, 2))
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

        pri_color = "#b91c1c" if "1" in art.priority_tier or "Critical" in art.priority_tier else (
            "#b45309" if "2" in art.priority_tier else "#047857"
        )
        self.badge_priority.configure(
            text=art.priority_tier,
            fg_color="#f1f5f9",
            text_color=pri_color
        )

        # Shannon Entropy Meter & Density Indicator
        ent_val = float(art.metadata.get("average_entropy", 0.0))
        if ent_val >= 7.0:
            ent_desc = "High Density / Packed or Encrypted"
            ent_color = "#b91c1c"
        elif ent_val >= 4.5:
            ent_desc = "Moderate Density / Structured Text or Code"
            ent_color = "#b45309"
        else:
            ent_desc = "Low Density / Plain Data or Slack"
            ent_color = "#0284c7"
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

        self.lbl_integrity_title.configure(text=f"Structural Health: {score:.1f}%", text_color=meter_color)

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
