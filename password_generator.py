#!/usr/bin/env python3
"""
Cryptographically Secure Random Password Generator (Tkinter Desktop App)
========================================================================
Tech Stack: Python 3, secrets, string, hashlib, tkinter, pyperclip

Features:
1. Enforced minimum password length of 8 via synchronized Spinbox & Slider.
2. Checkboxes for Uppercase, Lowercase, Numbers, and Symbols (minimum 2 required).
3. Uses Python's `secrets` module (CSPRNG) exclusively—never `random`.
4. Guarantees at least one character from each selected character category,
   then shuffles securely using `secrets.SystemRandom().shuffle()`.
5. Real-time password strength indicator (Weak / Medium / Strong) with visual bar.
6. Automatic clipboard copy on generation via `pyperclip.copy()` + manual "Copy" button.
7. Option to exclude ambiguous characters ('0', 'O', 'l', '1', 'I').
8. Optional "Hash Password (SHA-256)" toggle using `hashlib.sha256` to display
   the hex digest alongside the plaintext password.
9. Displays the last 5 generated passwords in session memory by default, with an
   opt-in, decoupled `HistoryExporter` for manual JSON/CSV file export.
10. Clear inline GUI validation messages for invalid length or < 2 character types.
"""

from collections import deque
import csv
from datetime import datetime
import hashlib
import json
import secrets
import string
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Deque, Dict, List, Tuple

import pyperclip


class HistoryExporter:
    """
    Standalone, decoupled export utility for exporting in-memory session history
    to a local JSON or CSV file upon explicit user action, leaving core
    password generation and volatile session storage logic untouched.
    """

    @staticmethod
    def export_to_json(
        parent: tk.Misc,
        history: Deque[str],
        strength_fn: Callable[[str], str],
    ) -> str:
        """Export the current session password history to a user-selected JSON file."""
        if not history:
            raise ValueError("No passwords in session history to export.")

        filepath = filedialog.asksaveasfilename(
            parent=parent,
            title="Export Session Password History (JSON)",
            defaultextension=".json",
            initialfile="session_password_history.json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not filepath:
            return ""

        exported_at = datetime.now().isoformat(timespec="seconds")
        payload = {
            "exported_at": exported_at,
            "count": len(history),
            "items": [
                {
                    "rank": idx,
                    "password": pw,
                    "sha256": hashlib.sha256(pw.encode("utf-8")).hexdigest(),
                    "length": len(pw),
                    "strength": strength_fn(pw),
                }
                for idx, pw in enumerate(history, start=1)
            ],
        }

        with open(filepath, mode="w", encoding="utf-8") as json_file:
            json.dump(payload, json_file, indent=2)

        return filepath

    @staticmethod
    def export_to_csv(
        parent: tk.Misc,
        history: Deque[str],
        strength_fn: Callable[[str], str],
    ) -> str:
        """Export the current session password history to a user-selected CSV file."""
        if not history:
            raise ValueError("No passwords in session history to export.")

        filepath = filedialog.asksaveasfilename(
            parent=parent,
            title="Export Session Password History (CSV)",
            defaultextension=".csv",
            initialfile="session_password_history.csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not filepath:
            return ""

        exported_at = datetime.now().isoformat(timespec="seconds")
        with open(filepath, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(
                ["rank", "password", "sha256", "length", "strength", "exported_at"]
            )
            for idx, pw in enumerate(history, start=1):
                digest = hashlib.sha256(pw.encode("utf-8")).hexdigest()
                writer.writerow([idx, pw, digest, len(pw), strength_fn(pw), exported_at])

        return filepath


class PasswordGeneratorApp:
    """Main application class for the Tkinter Random Password Generator."""

    # Ambiguous characters to strip when exclusion option is enabled
    AMBIGUOUS_CHARS = set("0Ol1I")
    MIN_LENGTH = 8
    MAX_LENGTH = 64
    MAX_HISTORY = 5

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SecurePass — Cryptographic Password Generator")
        self.root.geometry("560x760")
        self.root.minsize(520, 720)
        self.root.configure(bg="#F8FAFC")

        # Cryptographically secure random number generator instance for shuffling
        self.csprng = secrets.SystemRandom()

        # Session-only password history (bounded to 5 items, never auto-saved to file)
        self.session_history: deque[str] = deque(maxlen=self.MAX_HISTORY)

        # Tkinter state variables
        self.length_var = tk.StringVar(value="16")
        self.length_scale_var = tk.IntVar(value=16)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        self.show_hash = tk.BooleanVar(value=False)

        self.password_var = tk.StringVar(value="")
        self.hash_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")
        self.error_var = tk.StringVar(value="")
        self.strength_label_var = tk.StringVar(value="Strength: —")

        self._configure_styles()
        self._build_ui()

        # Generate an initial password on startup
        self.generate_password()

    def _configure_styles(self) -> None:
        """Configure ttk widget styles for a clean desktop interface."""
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("TFrame", background="#F8FAFC")
        style.configure("Card.TFrame", background="#FFFFFF")
        style.configure(
            "Header.TLabel",
            background="#F8FAFC",
            foreground="#0F172A",
            font=("Helvetica", 15, "bold"),
        )
        style.configure(
            "Subheader.TLabel",
            background="#F8FAFC",
            foreground="#475569",
            font=("Helvetica", 10),
        )
        style.configure(
            "Section.TLabel",
            background="#FFFFFF",
            foreground="#0F172A",
            font=("Helvetica", 10, "bold"),
        )
        style.configure(
            "TCheckbutton",
            background="#FFFFFF",
            foreground="#1E293B",
            font=("Helvetica", 10),
        )

    def _build_ui(self) -> None:
        """Construct and arrange all GUI widgets."""
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 1. Header
        header_lbl = ttk.Label(
            main_frame,
            text="Cryptographic Password Generator",
            style="Header.TLabel",
        )
        header_lbl.pack(anchor=tk.W)

        sub_lbl = ttk.Label(
            main_frame,
            text="Powered by Python's secrets & hashlib modules · Session-only memory",
            style="Subheader.TLabel",
        )
        sub_lbl.pack(anchor=tk.W, pady=(2, 14))

        # 2. Password Output & Copy Controls
        output_card = tk.Frame(
            main_frame, bg="#FFFFFF", bd=1, relief=tk.SOLID, padx=14, pady=14
        )
        output_card.pack(fill=tk.X, pady=(0, 12))

        entry_row = tk.Frame(output_card, bg="#FFFFFF")
        entry_row.pack(fill=tk.X)

        self.password_entry = tk.Entry(
            entry_row,
            textvariable=self.password_var,
            font=("Courier", 14, "bold"),
            fg="#0F172A",
            bg="#F1F5F9",
            readonlybackground="#F1F5F9",
            relief=tk.FLAT,
            state="readonly",
            justify=tk.LEFT,
        )
        self.password_entry.pack(
            side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(0, 8)
        )

        self.copy_btn = tk.Button(
            entry_row,
            text="Copy",
            command=self.copy_to_clipboard,
            bg="#E2E8F0",
            fg="#0F172A",
            activebackground="#CBD5E1",
            font=("Helvetica", 10, "bold"),
            relief=tk.FLAT,
            padx=14,
            pady=7,
            cursor="hand2",
        )
        self.copy_btn.pack(side=tk.RIGHT)

        # Optional SHA-256 Hash Row (Managed by _update_hash_display)
        self.hash_row = tk.Frame(output_card, bg="#FFFFFF")

        tk.Label(
            self.hash_row,
            text="SHA-256 (hashlib):",
            bg="#FFFFFF",
            fg="#475569",
            font=("Helvetica", 8, "bold"),
        ).pack(anchor=tk.W, pady=(8, 2))

        hash_entry_container = tk.Frame(self.hash_row, bg="#FFFFFF")
        hash_entry_container.pack(fill=tk.X)

        self.hash_entry = tk.Entry(
            hash_entry_container,
            textvariable=self.hash_var,
            font=("Courier", 9),
            fg="#334155",
            bg="#F8FAFC",
            readonlybackground="#F8FAFC",
            relief=tk.FLAT,
            state="readonly",
        )
        self.hash_entry.pack(
            side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 8)
        )

        self.copy_hash_btn = tk.Button(
            hash_entry_container,
            text="Copy Hash",
            command=self.copy_hash_to_clipboard,
            bg="#F1F5F9",
            fg="#0F172A",
            activebackground="#E2E8F0",
            font=("Helvetica", 8, "bold"),
            relief=tk.FLAT,
            padx=10,
            pady=5,
            cursor="hand2",
        )
        self.copy_hash_btn.pack(side=tk.RIGHT)

        # Strength Indicator Row (Label + Visual Canvas Bar)
        self.strength_row = tk.Frame(output_card, bg="#FFFFFF")
        self.strength_row.pack(fill=tk.X, pady=(10, 4))

        self.strength_label = tk.Label(
            self.strength_row,
            textvariable=self.strength_label_var,
            bg="#FFFFFF",
            fg="#334155",
            font=("Helvetica", 9, "bold"),
        )
        self.strength_label.pack(side=tk.LEFT)

        self.status_label = tk.Label(
            self.strength_row,
            textvariable=self.status_var,
            bg="#FFFFFF",
            fg="#15803D",
            font=("Helvetica", 9),
        )
        self.status_label.pack(side=tk.RIGHT)

        self.strength_canvas = tk.Canvas(
            output_card, height=8, bg="#E2E8F0", highlightthickness=0
        )
        self.strength_canvas.pack(fill=tk.X, pady=(4, 0))
        self.strength_canvas.bind("<Configure>", lambda _e: self._redraw_strength_bar())
        self._current_strength_state: Tuple[str, float, str] = ("Weak", 0.33, "#DC2626")

        # 3. Inline Error Banner (Hidden when valid)
        self.error_banner = tk.Label(
            main_frame,
            textvariable=self.error_var,
            bg="#FEF2F2",
            fg="#B91C1C",
            font=("Helvetica", 9, "bold"),
            padx=10,
            pady=8,
            justify=tk.LEFT,
            anchor="w",
            wraplength=490,
        )

        # 4. Configuration Controls (Length & Character Sets)
        config_card = tk.Frame(
            main_frame, bg="#FFFFFF", bd=1, relief=tk.SOLID, padx=14, pady=14
        )
        config_card.pack(fill=tk.X, pady=(0, 12))

        # Length Spinbox + Slider
        length_header = tk.Frame(config_card, bg="#FFFFFF")
        length_header.pack(fill=tk.X)

        tk.Label(
            length_header,
            text="Password Length (min 8):",
            bg="#FFFFFF",
            fg="#0F172A",
            font=("Helvetica", 10, "bold"),
        ).pack(side=tk.LEFT)

        self.length_spinbox = tk.Spinbox(
            length_header,
            from_=self.MIN_LENGTH,
            to=self.MAX_LENGTH,
            textvariable=self.length_var,
            width=6,
            font=("Courier", 11, "bold"),
            command=self._on_spinbox_change,
        )
        self.length_spinbox.pack(side=tk.RIGHT)
        self.length_spinbox.bind("<Return>", lambda _e: self._on_spinbox_change())
        self.length_spinbox.bind("<FocusOut>", lambda _e: self._on_spinbox_change())

        self.length_slider = tk.Scale(
            config_card,
            from_=self.MIN_LENGTH,
            to=self.MAX_LENGTH,
            orient=tk.HORIZONTAL,
            variable=self.length_scale_var,
            showvalue=False,
            bg="#FFFFFF",
            highlightthickness=0,
            troughcolor="#E2E8F0",
            command=self._on_slider_change,
        )
        self.length_slider.pack(fill=tk.X, pady=(6, 12))

        # Character Set Checkboxes (At least 2 required)
        tk.Label(
            config_card,
            text="Character Types (select at least 2):",
            bg="#FFFFFF",
            fg="#0F172A",
            font=("Helvetica", 10, "bold"),
        ).pack(anchor=tk.W, pady=(0, 6))

        checks_grid = tk.Frame(config_card, bg="#FFFFFF")
        checks_grid.pack(fill=tk.X, pady=(0, 8))

        ttk.Checkbutton(
            checks_grid,
            text="Uppercase (A–Z)",
            variable=self.use_upper,
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 20), pady=3)

        ttk.Checkbutton(
            checks_grid,
            text="Lowercase (a–z)",
            variable=self.use_lower,
        ).grid(row=0, column=1, sticky=tk.W, pady=3)

        ttk.Checkbutton(
            checks_grid,
            text="Numbers (0–9)",
            variable=self.use_digits,
        ).grid(row=1, column=0, sticky=tk.W, padx=(0, 20), pady=3)

        ttk.Checkbutton(
            checks_grid,
            text="Symbols (!@#$...)",
            variable=self.use_symbols,
        ).grid(row=1, column=1, sticky=tk.W, pady=3)

        # Ambiguous Characters & Hash Password Toggles
        ttk.Separator(config_card, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)
        ttk.Checkbutton(
            config_card,
            text="Exclude ambiguous characters (0, O, l, 1, I)",
            variable=self.exclude_ambiguous,
        ).pack(anchor=tk.W, pady=(0, 4))

        ttk.Checkbutton(
            config_card,
            text="Hash Password (SHA-256 via hashlib)",
            variable=self.show_hash,
            command=self._update_hash_display,
        ).pack(anchor=tk.W)

        # 5. Primary Action Button ("Generate Another")
        self.generate_btn = tk.Button(
            main_frame,
            text="Generate Another",
            command=self.generate_password,
            bg="#0F172A",
            fg="#FFFFFF",
            activebackground="#1E293B",
            activeforeground="#FFFFFF",
            font=("Helvetica", 11, "bold"),
            relief=tk.FLAT,
            pady=10,
            cursor="hand2",
        )
        self.generate_btn.pack(fill=tk.X, pady=(0, 12))

        # 6. Session History (Last 5 Passwords — Memory Only by default + Optional Export)
        history_card = tk.Frame(
            main_frame, bg="#FFFFFF", bd=1, relief=tk.SOLID, padx=14, pady=12
        )
        history_card.pack(fill=tk.BOTH, expand=True)

        history_header = tk.Frame(history_card, bg="#FFFFFF")
        history_header.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            history_header,
            text="Last 5 Generated Passwords (Session Memory)",
            bg="#FFFFFF",
            fg="#0F172A",
            font=("Helvetica", 9, "bold"),
        ).pack(side=tk.LEFT)

        export_btn_frame = tk.Frame(history_header, bg="#FFFFFF")
        export_btn_frame.pack(side=tk.RIGHT)

        self.export_json_btn = tk.Button(
            export_btn_frame,
            text="Export JSON",
            command=lambda: self.export_session_history("json"),
            bg="#F1F5F9",
            fg="#0F172A",
            activebackground="#E2E8F0",
            font=("Helvetica", 8, "bold"),
            relief=tk.FLAT,
            padx=8,
            pady=3,
            cursor="hand2",
        )
        self.export_json_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.export_csv_btn = tk.Button(
            export_btn_frame,
            text="Export CSV",
            command=lambda: self.export_session_history("csv"),
            bg="#F1F5F9",
            fg="#0F172A",
            activebackground="#E2E8F0",
            font=("Helvetica", 8, "bold"),
            relief=tk.FLAT,
            padx=8,
            pady=3,
            cursor="hand2",
        )
        self.export_csv_btn.pack(side=tk.LEFT)

        self.history_listbox = tk.Listbox(
            history_card,
            height=5,
            font=("Courier", 10),
            bg="#F8FAFC",
            fg="#1E293B",
            selectbackground="#CBD5E1",
            selectforeground="#0F172A",
            relief=tk.FLAT,
            activestyle="none",
        )
        self.history_listbox.pack(fill=tk.BOTH, expand=True)

    # -------------------------------------------------------------------------
    # Event Handlers & Synchronization
    # -------------------------------------------------------------------------

    def _on_slider_change(self, value: str) -> None:
        """Keep the Spinbox text synchronized when the Scale slider moves."""
        self.length_var.set(str(int(float(value))))

    def _on_spinbox_change(self) -> None:
        """Sync slider if spinbox holds a valid integer within range."""
        try:
            val = int(self.length_var.get().strip())
            if self.MIN_LENGTH <= val <= self.MAX_LENGTH:
                self.length_scale_var.set(val)
        except ValueError:
            pass

    def _show_error(self, message: str) -> None:
        """Display an inline validation error message inside the GUI."""
        self.error_var.set(f"Validation Error: {message}")
        self.error_banner.pack(
            fill=tk.X, pady=(0, 12), before=self.generate_btn
        )

    def _clear_error(self) -> None:
        """Hide the inline validation error banner."""
        self.error_var.set("")
        self.error_banner.pack_forget()

    def _compute_sha256(self, password: str) -> str:
        """Return the hexadecimal SHA-256 digest of a password using hashlib."""
        if not password:
            return ""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _refresh_history_listbox(self) -> None:
        """Render the session history listbox, optionally including SHA-256 hashes."""
        self.history_listbox.delete(0, tk.END)
        show_digest = self.show_hash.get()
        for idx, item in enumerate(self.session_history, start=1):
            if show_digest:
                digest_short = self._compute_sha256(item)[:16]
                self.history_listbox.insert(
                    tk.END, f"#{idx}  {item}   [SHA-256: {digest_short}...]"
                )
            else:
                self.history_listbox.insert(tk.END, f"#{idx}  {item}")

    def _update_hash_display(self) -> None:
        """Compute SHA-256 hash and show or hide the hash row based on toggle state."""
        current_pw = self.password_var.get()
        self.hash_var.set(self._compute_sha256(current_pw))
        if self.show_hash.get():
            self.hash_row.pack(fill=tk.X, before=self.strength_row)
        else:
            self.hash_row.pack_forget()
        if hasattr(self, "history_listbox"):
            self._refresh_history_listbox()

    # -------------------------------------------------------------------------
    # Core Validation, Generation & Strength Calculation
    # -------------------------------------------------------------------------

    def _get_character_pools(self) -> Dict[str, str]:
        """Build active character pools and strip ambiguous characters if requested."""
        pools: Dict[str, str] = {}
        if self.use_upper.get():
            pools["upper"] = string.ascii_uppercase
        if self.use_lower.get():
            pools["lower"] = string.ascii_lowercase
        if self.use_digits.get():
            pools["digits"] = string.digits
        if self.use_symbols.get():
            pools["symbols"] = string.punctuation

        if self.exclude_ambiguous.get():
            pools = {
                key: "".join(ch for ch in chars if ch not in self.AMBIGUOUS_CHARS)
                for key, chars in pools.items()
            }
        return pools

    def _validate_inputs(self) -> Tuple[bool, int, Dict[str, str], str]:
        """
        Validate password length (min 8) and character type count (min 2).
        Returns (is_valid, length, pools, error_message).
        """
        raw_length = self.length_var.get().strip()
        try:
            length = int(raw_length)
        except ValueError:
            return (
                False,
                0,
                {},
                "Password length must be a whole number (minimum 8).",
            )

        if length < self.MIN_LENGTH:
            return (
                False,
                length,
                {},
                f"Password length must be at least {self.MIN_LENGTH} characters (entered {length}).",
            )

        if length > self.MAX_LENGTH:
            return (
                False,
                length,
                {},
                f"Password length cannot exceed {self.MAX_LENGTH} characters.",
            )

        pools = self._get_character_pools()
        if len(pools) < 2:
            return (
                False,
                length,
                pools,
                "Please select at least 2 character types (Uppercase, Lowercase, Numbers, or Symbols).",
            )

        return True, length, pools, ""

    def _calculate_strength(
        self, length: int, active_type_count: int
    ) -> Tuple[str, float, str]:
        """
        Evaluate password strength based on length and character diversity.
        Returns (label, fill_ratio, hex_color).
        """
        if length >= 14 and active_type_count >= 3:
            return ("Strong", 1.0, "#16A34A")
        if length >= 16 and active_type_count >= 2:
            return ("Strong", 1.0, "#16A34A")
        if length >= 10 and active_type_count >= 2:
            return ("Medium", 0.66, "#D97706")
        return ("Weak", 0.33, "#DC2626")

    def _infer_password_strength_label(self, pw: str) -> str:
        """Infer the strength label of an existing password string for export metadata."""
        types_present = sum(
            [
                any(c in string.ascii_uppercase for c in pw),
                any(c in string.ascii_lowercase for c in pw),
                any(c in string.digits for c in pw),
                any(c in string.punctuation for c in pw),
            ]
        )
        label, _ratio, _color = self._calculate_strength(len(pw), types_present)
        return label

    def _redraw_strength_bar(self) -> None:
        """Render the visual strength indicator bar on the canvas."""
        self.strength_canvas.delete("all")
        width = self.strength_canvas.winfo_width()
        if width <= 1:
            width = 480
        _label, ratio, color = self._current_strength_state
        fill_width = int(width * ratio)
        self.strength_canvas.create_rectangle(
            0, 0, fill_width, 8, fill=color, outline=""
        )

    def generate_password(self) -> None:
        """
        Validate settings, generate a password using `secrets`, guarantee
        character inclusion from each selected category, shuffle securely,
        update strength, optional SHA-256 hash & session history, and copy to clipboard.
        """
        is_valid, length, pools, error_msg = self._validate_inputs()
        if not is_valid:
            self._show_error(error_msg)
            self.status_var.set("")
            return

        self._clear_error()
        self.length_scale_var.set(length)

        # 1. Guarantee at least one character from each selected category
        password_chars: List[str] = [
            secrets.choice(pool_chars) for pool_chars in pools.values()
        ]

        # 2. Fill remaining length from the combined pool using secrets.choice
        combined_pool = "".join(pools.values())
        remaining_count = length - len(password_chars)
        password_chars.extend(
            secrets.choice(combined_pool) for _ in range(remaining_count)
        )

        # 3. Shuffle securely using secrets.SystemRandom().shuffle()
        self.csprng.shuffle(password_chars)
        new_password = "".join(password_chars)

        # 4. Update Session-Only History (max 5 items, newest first)
        self.session_history.appendleft(new_password)

        # 5. Update GUI Output, SHA-256 Hash & Strength Indicator
        self.password_var.set(new_password)
        self._update_hash_display()

        label, ratio, color = self._calculate_strength(length, len(pools))
        self._current_strength_state = (label, ratio, color)
        self.strength_label_var.set(
            f"Strength: {label} ({length} chars, {len(pools)} types)"
        )
        self.strength_label.configure(fg=color)
        self._redraw_strength_bar()

        # 6. Automatically copy to clipboard via pyperclip
        self.copy_to_clipboard(auto=True)

    def copy_to_clipboard(self, auto: bool = False) -> None:
        """Copy the current password to the system clipboard using pyperclip."""
        current_pw = self.password_var.get()
        if not current_pw:
            return

        try:
            pyperclip.copy(current_pw)
            self.status_var.set(
                "Auto-copied via pyperclip" if auto else "Copied to clipboard!"
            )
        except pyperclip.PyperclipException:
            # Fallback to Tkinter's built-in clipboard if OS clipboard utility is missing
            self.root.clipboard_clear()
            self.root.clipboard_append(current_pw)
            self.root.update_idletasks()
            self.status_var.set(
                "Auto-copied to clipboard" if auto else "Copied to clipboard!"
            )

    def copy_hash_to_clipboard(self) -> None:
        """Copy the SHA-256 hex digest to the system clipboard using pyperclip."""
        current_hash = self.hash_var.get()
        if not current_hash:
            return

        try:
            pyperclip.copy(current_hash)
            self.status_var.set("SHA-256 hash copied!")
        except pyperclip.PyperclipException:
            self.root.clipboard_clear()
            self.root.clipboard_append(current_hash)
            self.root.update_idletasks()
            self.status_var.set("SHA-256 hash copied!")

    def export_session_history(self, fmt: str) -> None:
        """
        Delegate exporting the in-memory session history to `HistoryExporter`
        after an explicit plaintext security confirmation.
        """
        if not self.session_history:
            self._show_error("No generated passwords in session history to export.")
            return

        confirm = messagebox.askyesno(
            title="Plaintext Password Export Warning",
            message=(
                "Exporting will write the current session's passwords in plaintext "
                f"to a local {fmt.upper()} file.\n\n"
                "Do you want to proceed?"
            ),
            parent=self.root,
        )
        if not confirm:
            return

        try:
            if fmt.lower() == "json":
                saved_path = HistoryExporter.export_to_json(
                    self.root,
                    self.session_history,
                    self._infer_password_strength_label,
                )
            else:
                saved_path = HistoryExporter.export_to_csv(
                    self.root,
                    self.session_history,
                    self._infer_password_strength_label,
                )

            if saved_path:
                self._clear_error()
                self.status_var.set(f"Exported {fmt.upper()} file")
        except OSError as exc:
            self._show_error(f"Failed to write export file: {exc}")


def main() -> None:
    """Entry point for the Tkinter Password Generator application."""
    root = tk.Tk()
    PasswordGeneratorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
