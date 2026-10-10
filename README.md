# SecurePass Studio — Cryptographic Password Generator

A cryptographically secure random password generator available as both a **Python Tkinter Desktop GUI** and an **Interactive Web Workbench (React + D3 + QR)**. It uses OS-level CSPRNG (`secrets` / Web Crypto API), guarantees character diversity, computes SHA-256 hashes (`hashlib`), renders client-side QR codes for mobile transfer, and visualizes brute-force resistance with D3.

---

## Key Features

- **CSPRNG Security**: Uses Python's `secrets` module (`secrets.choice` & `secrets.SystemRandom().shuffle`) and Web Crypto (`crypto.getRandomValues`)—never pseudo-random `random`.
- **Enforced Rules & Inline Validation**: Enforces a minimum password length of 8 and at least 2 character categories (Uppercase, Lowercase, Numbers, Symbols) with guaranteed inclusion from each selected category.
- **Ambiguous Character Filter**: Optional toggle to exclude look-alike characters (`0`, `O`, `l`, `1`, `I`).
- **Visibility & Color-Coding**: Eye-icon toggle (`Show` / `Hide`) to mask or reveal password characters, plus optional color-coding by character type.
- **SHA-256 Hashing (`hashlib`)**: Optional **Hash Password (SHA-256)** toggle displaying the 256-bit hex digest alongside the plaintext password.
- **Mobile QR Code Transfer**: Client-side SVG QR code generator (`qrcode.react`) with privacy blur masking, error-correction controls (`L`, `M`, `Q`, `H`), and SVG download.
- **D3 Entropy & Attack Vector Analytics**: Radial entropy gauge and $\log_{10}$ survival bar chart comparing crack times against Online API, Slow KDF (`Argon2id`/`bcrypt`), Multi-GPU `SHA-256`, and ASIC Supercluster threat models.
- **Session-Only History & Opt-In Export**: Retains the last 5 generated passwords in volatile session memory (`collections.deque(maxlen=5)`), with decoupled JSON and CSV export gated by a plaintext confirmation dialog.

---

## Quick Start

### 1. Run the Web Workbench (React + Vite)
```bash
npm install
npm run dev
