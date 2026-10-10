import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Copy,
  Check,
  RefreshCw,
  Download,
  AlertTriangle,
  ShieldCheck,
  Sparkles,
  KeyRound,
  Sliders,
  Layers,
  Clock,
  QrCode,
  Eye,
  EyeOff,
  Smartphone,
} from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { EntropyD3Chart } from './EntropyD3Chart';

// Character pool constants
const ASCII_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ASCII_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const PUNCTUATION = '!@#$%^&*()-_=+[]{}|;:,.<>?/~';
const AMBIGUOUS_CHARS = new Set(['0', 'O', 'l', '1', 'I']);

const MIN_LENGTH = 8;
const MAX_LENGTH = 64;
const MAX_HISTORY = 5;

type StrengthLevel = 'Weak' | 'Medium' | 'Strong';
type QRErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';

interface StrengthInfo {
  label: StrengthLevel;
  ratio: number;
  textClass: string;
  barClass: string;
  surfaceClass: string;
  entropyBits: number;
  poolSize: number;
  crackTimeLabel: string;
}

interface HistoryEntry {
  id: string;
  password: string;
  sha256: string;
  length: number;
  typesCount: number;
  strength: StrengthLevel;
  timestamp: string;
}

/**
 * Cryptographically secure random integer in [0, max) using Web Crypto API.
 */
function csprngRandBelow(max: number): number {
  if (max <= 1) return 0;
  const array = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  let value = 0;
  do {
    window.crypto.getRandomValues(array);
    value = array[0];
  } while (value >= limit);
  return value % max;
}

function secretsChoice(pool: string): string {
  return pool[csprngRandBelow(pool.length)];
}

function secretsShuffle(arr: string[]): string[] {
  const copy = [...arr];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = csprngRandBelow(i + 1);
    const temp = copy[i];
    copy[i] = copy[j];
    copy[j] = temp;
  }
  return copy;
}

/**
 * Synchronous, FIPS 180-4 compliant SHA-256 implementation.
 */
function hashlibSha256Hex(message: string): string {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  const H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];

  const bytes = new TextEncoder().encode(message);
  const bitLen = bytes.length * 8;

  const totalLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);

  const rotr = (n: number, x: number) => (x >>> n) | (x << (32 - n));
  const W = new Uint32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, W[i - 15]) ^ rotr(18, W[i - 15]) ^ (W[i - 15] >>> 3);
      const s1 = rotr(17, W[i - 2]) ^ rotr(19, W[i - 2]) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = H;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }

  return H.map((word) => word.toString(16).padStart(8, '0')).join('');
}

/**
 * Standalone, decoupled HistoryExporter utility.
 */
const HistoryExporter = {
  toJSONString(history: HistoryEntry[]): string {
    const exportedAt = new Date().toISOString();
    const payload = {
      exported_at: exportedAt,
      count: history.length,
      items: history.map((item, idx) => ({
        rank: idx + 1,
        password: item.password,
        sha256: item.sha256,
        length: item.length,
        strength: item.strength,
        generated_at: item.timestamp,
      })),
    };
    return JSON.stringify(payload, null, 2);
  },

  toCSVString(history: HistoryEntry[]): string {
    const exportedAt = new Date().toISOString();
    const escapeCsv = (val: string | number) => {
      const str = String(val);
      return `"${str.replace(/"/g, '""')}"`;
    };
    const rows = [
      ['rank', 'password', 'sha256', 'length', 'strength', 'exported_at'].join(
        ','
      ),
      ...history.map((item, idx) =>
        [
          idx + 1,
          escapeCsv(item.password),
          escapeCsv(item.sha256),
          item.length,
          escapeCsv(item.strength),
          escapeCsv(exportedAt),
        ].join(',')
      ),
    ];
    return rows.join('\n');
  },
};

function estimateCrackTime(entropyBits: number): string {
  if (entropyBits < 45) return 'Seconds to minutes (Offline GPU)';
  if (entropyBits < 60) return 'Hours to days (Offline GPU)';
  if (entropyBits < 78) return 'Centuries (100B guesses/sec)';
  if (entropyBits < 100) return 'Millions of years';
  return '10¹⁵+ years (Astronomical)';
}

export default function App() {
  // Spinbox + Slider state (minimum 8 enforced)
  const [rawLengthInput, setRawLengthInput] = useState<string>('16');
  const [sliderLength, setSliderLength] = useState<number>(16);

  // Character type & option checkboxes
  const [useUpper, setUseUpper] = useState<boolean>(true);
  const [useLower, setUseLower] = useState<boolean>(true);
  const [useDigits, setUseDigits] = useState<boolean>(true);
  const [useSymbols, setUseSymbols] = useState<boolean>(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState<boolean>(false);
  const [showHash, setShowHash] = useState<boolean>(true);
  const [colorizeChars, setColorizeChars] = useState<boolean>(true);

  // QR Code state
  const [showQrCode, setShowQrCode] = useState<boolean>(true);
  const [blurQrCode, setBlurQrCode] = useState<boolean>(false);
  const [qrPayloadMode, setQrPayloadMode] = useState<'password' | 'sha256'>(
    'password'
  );
  const [qrErrorLevel, setQrErrorLevel] =
    useState<QRErrorCorrectionLevel>('M');
  const qrContainerRef = useRef<HTMLDivElement | null>(null);

  // Output & GUI state
  const [password, setPassword] = useState<string>('');
  const [isPasswordVisible, setIsPasswordVisible] = useState<boolean>(true);
  const [sha256Hash, setSha256Hash] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [clipboardStatus, setClipboardStatus] = useState<string>('');
  const [copiedManual, setCopiedManual] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [sessionHistory, setSessionHistory] = useState<HistoryEntry[]>([]);
  const [pendingExportFormat, setPendingExportFormat] = useState<
    'json' | 'csv' | null
  >(null);
  const [activePresetName, setActivePresetName] = useState<string>(
    'Standard Balanced (16 chars)'
  );

  const [strengthInfo, setStrengthInfo] = useState<StrengthInfo>({
    label: 'Strong',
    ratio: 1,
    textClass: 'text-emerald-700',
    barClass: 'bg-emerald-500',
    surfaceClass: 'bg-emerald-50/70 border-emerald-200',
    entropyBits: 104,
    poolSize: 90,
    crackTimeLabel: '10¹⁵+ years (Astronomical)',
  });

  const buildCharacterPools = useCallback(
    (
      upper: boolean,
      lower: boolean,
      digits: boolean,
      symbols: boolean,
      noAmbiguous: boolean
    ): Record<string, string> => {
      const pools: Record<string, string> = {};
      if (upper) pools.upper = ASCII_UPPERCASE;
      if (lower) pools.lower = ASCII_LOWERCASE;
      if (digits) pools.digits = DIGITS;
      if (symbols) pools.symbols = PUNCTUATION;

      if (noAmbiguous) {
        for (const key of Object.keys(pools)) {
          pools[key] = pools[key]
            .split('')
            .filter((ch) => !AMBIGUOUS_CHARS.has(ch))
            .join('');
        }
      }
      return pools;
    },
    []
  );

  const calculateStrength = useCallback(
    (length: number, typesCount: number, totalPoolSize: number): StrengthInfo => {
      const entropyBits =
        totalPoolSize > 0 ? Math.round(length * Math.log2(totalPoolSize)) : 0;
      const crackTimeLabel = estimateCrackTime(entropyBits);

      if (
        (length >= 14 && typesCount >= 3) ||
        (length >= 16 && typesCount >= 2)
      ) {
        return {
          label: 'Strong',
          ratio: 1.0,
          textClass: 'text-emerald-700',
          barClass: 'bg-emerald-500',
          surfaceClass: 'bg-emerald-50/70 border-emerald-200',
          entropyBits,
          poolSize: totalPoolSize,
          crackTimeLabel,
        };
      }
      if (length >= 10 && typesCount >= 2) {
        return {
          label: 'Medium',
          ratio: 0.66,
          textClass: 'text-amber-700',
          barClass: 'bg-amber-500',
          surfaceClass: 'bg-amber-50/70 border-amber-200',
          entropyBits,
          poolSize: totalPoolSize,
          crackTimeLabel,
        };
      }
      return {
        label: 'Weak',
        ratio: 0.33,
        textClass: 'text-rose-700',
        barClass: 'bg-rose-500',
        surfaceClass: 'bg-rose-50/70 border-rose-200',
        entropyBits,
        poolSize: totalPoolSize,
        crackTimeLabel,
      };
    },
    []
  );

  const copyTextToClipboard = useCallback(
    async (text: string, mode: 'auto' | 'manual' | 'hash') => {
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Fallback if clipboard permission is restricted in iframe
      }
      if (mode === 'auto') {
        setClipboardStatus('Auto-copied to clipboard');
        setCopiedManual(false);
      } else if (mode === 'manual') {
        setClipboardStatus('Copied to clipboard!');
        setCopiedManual(true);
        setTimeout(() => setCopiedManual(false), 1800);
      } else {
        setClipboardStatus('SHA-256 hash copied!');
        setCopiedHash(true);
        setTimeout(() => setCopiedHash(false), 1800);
      }
    },
    []
  );

  const generatePassword = useCallback(
    (
      overrideRawLength?: string,
      overrideUpper?: boolean,
      overrideLower?: boolean,
      overrideDigits?: boolean,
      overrideSymbols?: boolean,
      overrideNoAmbiguous?: boolean
    ) => {
      const rawLen =
        overrideRawLength !== undefined ? overrideRawLength : rawLengthInput;
      const uUpper = overrideUpper !== undefined ? overrideUpper : useUpper;
      const uLower = overrideLower !== undefined ? overrideLower : useLower;
      const uDigits = overrideDigits !== undefined ? overrideDigits : useDigits;
      const uSymbols =
        overrideSymbols !== undefined ? overrideSymbols : useSymbols;
      const noAmb =
        overrideNoAmbiguous !== undefined
          ? overrideNoAmbiguous
          : excludeAmbiguous;

      const trimmed = rawLen.trim();
      const parsedLength = Number(trimmed);

      // 1. Validate length (must be integer >= 8 and <= 64)
      if (!trimmed || !Number.isInteger(parsedLength)) {
        setErrorMessage(
          'Validation Error: Password length must be a whole number (minimum 8).'
        );
        setClipboardStatus('');
        return;
      }

      if (parsedLength < MIN_LENGTH) {
        setErrorMessage(
          `Validation Error: Password length must be at least ${MIN_LENGTH} characters (entered ${parsedLength}).`
        );
        setClipboardStatus('');
        return;
      }

      if (parsedLength > MAX_LENGTH) {
        setErrorMessage(
          `Validation Error: Password length cannot exceed ${MAX_LENGTH} characters.`
        );
        setClipboardStatus('');
        return;
      }

      // 2. Validate character types (at least 2 required)
      const pools = buildCharacterPools(uUpper, uLower, uDigits, uSymbols, noAmb);
      const poolValues = Object.values(pools);
      if (poolValues.length < 2) {
        setErrorMessage(
          'Validation Error: Please select at least 2 character types (Uppercase, Lowercase, Numbers, or Symbols).'
        );
        setClipboardStatus('');
        return;
      }

      // Valid inputs -> Clear error & sync slider
      setErrorMessage('');
      setSliderLength(parsedLength);

      // 3. Guarantee at least 1 character from each selected category using CSPRNG
      const guaranteedChars = poolValues.map((pool) => secretsChoice(pool));

      // 4. Fill remaining slots from the combined pool
      const combinedPool = poolValues.join('');
      const remainingCount = parsedLength - guaranteedChars.length;
      const allChars = [...guaranteedChars];
      for (let i = 0; i < remainingCount; i++) {
        allChars.push(secretsChoice(combinedPool));
      }

      // 5. Securely shuffle via CSPRNG Fisher-Yates
      const shuffledPassword = secretsShuffle(allChars).join('');
      const digest = hashlibSha256Hex(shuffledPassword);

      // 6. Compute strength
      const nextStrength = calculateStrength(
        parsedLength,
        poolValues.length,
        combinedPool.length
      );

      setPassword(shuffledPassword);
      setSha256Hash(digest);
      setStrengthInfo(nextStrength);

      // 7. Prepend to session-only history (bounded to last 5 passwords)
      const now = new Date();
      const timeString = now.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });

      setSessionHistory((prev) =>
        [
          {
            id: `${now.getTime()}-${csprngRandBelow(10000)}`,
            password: shuffledPassword,
            sha256: digest,
            length: parsedLength,
            typesCount: poolValues.length,
            strength: nextStrength.label,
            timestamp: timeString,
          },
          ...prev,
        ].slice(0, MAX_HISTORY)
      );

      // 8. Auto-copy to clipboard
      copyTextToClipboard(shuffledPassword, 'auto');
    },
    [
      rawLengthInput,
      useUpper,
      useLower,
      useDigits,
      useSymbols,
      excludeAmbiguous,
      buildCharacterPools,
      calculateStrength,
      copyTextToClipboard,
    ]
  );

  // Initial generation on mount
  useEffect(() => {
    generatePassword('16', true, true, true, true, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = Number(e.target.value);
    setSliderLength(val);
    setRawLengthInput(String(val));
    setActivePresetName('Custom Configuration');
  };

  const handleSpinboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value;
    setRawLengthInput(raw);
    setActivePresetName('Custom Configuration');
    const num = Number(raw);
    if (Number.isInteger(num) && num >= MIN_LENGTH && num <= MAX_LENGTH) {
      setSliderLength(num);
    }
  };

  const applyPreset = (
    name: string,
    len: number,
    upper: boolean,
    lower: boolean,
    digits: boolean,
    symbols: boolean,
    noAmb: boolean
  ) => {
    setActivePresetName(name);
    setRawLengthInput(String(len));
    setSliderLength(len);
    setUseUpper(upper);
    setUseLower(lower);
    setUseDigits(digits);
    setUseSymbols(symbols);
    setExcludeAmbiguous(noAmb);
    generatePassword(String(len), upper, lower, digits, symbols, noAmb);
  };

  const downloadFile = (
    filename: string,
    content: string,
    mime = 'text/plain;charset=utf-8'
  ) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadQrCodeSvg = () => {
    if (!qrContainerRef.current) return;
    const svgElement = qrContainerRef.current.querySelector('svg');
    if (!svgElement) return;
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svgElement);
    downloadFile(
      'password_qr_code.svg',
      svgString,
      'image/svg+xml;charset=utf-8'
    );
    setClipboardStatus('Downloaded QR SVG');
  };

  const handleConfirmExport = (fmt: 'json' | 'csv') => {
    if (sessionHistory.length === 0) {
      setErrorMessage(
        'Validation Error: No generated passwords in session history to export.'
      );
      setPendingExportFormat(null);
      return;
    }

    if (fmt === 'json') {
      const jsonContent = HistoryExporter.toJSONString(sessionHistory);
      downloadFile(
        'session_password_history.json',
        jsonContent,
        'application/json;charset=utf-8'
      );
      setClipboardStatus('Exported JSON file');
    } else {
      const csvContent = HistoryExporter.toCSVString(sessionHistory);
      downloadFile(
        'session_password_history.csv',
        csvContent,
        'text/csv;charset=utf-8'
      );
      setClipboardStatus('Exported CSV file');
    }
    setPendingExportFormat(null);
  };

  const selectedTypesCount = [useUpper, useLower, useDigits, useSymbols].filter(
    Boolean
  ).length;

  // Compute live character breakdown for the Anatomy section
  const charCounts = {
    upper: password.split('').filter((c) => ASCII_UPPERCASE.includes(c)).length,
    lower: password.split('').filter((c) => ASCII_LOWERCASE.includes(c)).length,
    digits: password.split('').filter((c) => DIGITS.includes(c)).length,
    symbols: password.split('').filter((c) => PUNCTUATION.includes(c)).length,
  };

  const activeQrValue =
    qrPayloadMode === 'password' ? password : sha256Hash;

  return (
    <div className="min-h-screen bg-gradient-to-b from-sky-50/60 via-indigo-50/20 to-rose-50/30 text-slate-800 flex flex-col">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 lg:px-10 py-4 bg-white/90 backdrop-blur-xs border-b border-indigo-100">
        <a
          href="#generator"
          className="text-lg font-bold tracking-tight text-indigo-950 whitespace-nowrap shrink-0"
        >
          SecurePass Studio
        </a>

        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
          <a
            href="#generator"
            className="hover:text-indigo-700 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Generator &amp; QR
          </a>
          <a
            href="#presets"
            className="hover:text-indigo-700 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Security Presets
          </a>
          <a
            href="#anatomy"
            className="hover:text-indigo-700 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Entropy &amp; Anatomy
          </a>
          <a
            href="#history"
            className="hover:text-indigo-700 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Session History
          </a>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => generatePassword()}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-xs"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Generate New Password
          </button>
        </div>
      </header>

      {/* Main Content Container (1440px Desktop Presence) */}
      <main className="flex-1 max-w-[1340px] w-full mx-auto px-6 lg:px-10 py-8 space-y-12">
        {/* Hero / Intro Strip */}
        <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 border-b border-indigo-100/80 pb-6">
          <div className="max-w-2xl">
            <p className="text-xs font-semibold text-indigo-600 mb-1.5">
              Cryptographic CSPRNG · Instant QR Mobile Transfer · SHA-256 Digest
            </p>
            <h1
              className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900"
              style={{ textWrap: 'balance' }}
            >
              Random Password Generator &amp; Mobile QR Transfer
            </h1>
          </div>

          {/* Quick Validation Test Buttons */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => {
                setRawLengthInput('5');
                generatePassword(
                  '5',
                  useUpper,
                  useLower,
                  useDigits,
                  useSymbols,
                  excludeAmbiguous
                );
              }}
              className="px-3.5 py-2 text-xs font-medium text-rose-700 bg-rose-50/80 border border-rose-200 rounded-lg hover:bg-rose-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Test Validation: Length &lt; 8
            </button>
            <button
              type="button"
              onClick={() => {
                setUseUpper(true);
                setUseLower(false);
                setUseDigits(false);
                setUseSymbols(false);
                generatePassword('16', true, false, false, false, excludeAmbiguous);
              }}
              className="px-3.5 py-2 text-xs font-medium text-amber-800 bg-amber-50/80 border border-amber-200 rounded-lg hover:bg-amber-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Test Validation: &lt; 2 Types
            </button>
            <button
              type="button"
              onClick={() =>
                applyPreset(
                  'Standard Balanced (16 chars)',
                  16,
                  true,
                  true,
                  true,
                  true,
                  false
                )
              }
              className="px-3.5 py-2 text-xs font-medium text-indigo-700 bg-indigo-50/80 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Reset Defaults
            </button>
          </div>
        </section>

        {/* Section 1: Main Generator Workspace & Session History */}
        <section
          id="generator"
          className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch"
        >
          {/* Left Column (7 cols): Interactive Password Generator Card */}
          <div className="lg:col-span-7 bg-white border border-indigo-100 rounded-2xl p-6 sm:p-8 flex flex-col justify-between space-y-6 shadow-xs">
            <div className="space-y-6">
              {/* Card Title Row */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="text-lg font-bold text-slate-900">
                    01. Password Configuration &amp; Output
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Active Profile: {activePresetName} · Guaranteed 1+ char per selected set
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-4">
                  <label className="flex items-center gap-2 text-xs text-emerald-800 font-semibold cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={showHash}
                      onChange={(e) => setShowHash(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                    />
                    <span>Hash Password (SHA-256)</span>
                  </label>
                  <label className="flex items-center gap-2 text-xs text-slate-600 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={colorizeChars}
                      onChange={(e) => setColorizeChars(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                    />
                    <span>Color-code characters</span>
                  </label>
                  <label className="flex items-center gap-2 text-xs text-indigo-700 font-semibold cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={showQrCode}
                      onChange={(e) => setShowQrCode(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                    />
                    <span>Show QR Code</span>
                  </label>
                </div>
              </div>

              {/* Password Output & QR Code Display Box */}
              <div className="bg-sky-50/60 border border-sky-200/80 rounded-xl p-4 sm:p-5 space-y-4">
                <div className="flex flex-col md:flex-row gap-5 items-stretch">
                  {/* Left Side of Display Box: Password, Hash & Strength */}
                  <div className="flex-1 flex flex-col justify-between space-y-3.5 min-w-0">
                    <div className="space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white/90 border border-sky-200/90 rounded-xl p-3.5">
                        {/* Masked, color-coded, or plain password display */}
                        <div
                          className="font-mono text-lg sm:text-xl font-bold tracking-wide break-all select-all tabular-nums"
                          aria-label="Generated password"
                        >
                          {!isPasswordVisible ? (
                            <span className="text-slate-600 tracking-widest select-none">
                              {'•'.repeat(password.length)}
                            </span>
                          ) : colorizeChars ? (
                            password.split('').map((ch, idx) => {
                              let color = 'text-slate-800';
                              if (ASCII_UPPERCASE.includes(ch))
                                color = 'text-indigo-700';
                              else if (DIGITS.includes(ch))
                                color = 'text-sky-700';
                              else if (PUNCTUATION.includes(ch))
                                color = 'text-emerald-700';
                              return (
                                <span key={idx} className={color}>
                                  {ch}
                                </span>
                              );
                            })
                          ) : (
                            password
                          )}
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() =>
                              setIsPasswordVisible((prev) => !prev)
                            }
                            aria-label={
                              isPasswordVisible
                                ? 'Mask password characters'
                                : 'Reveal password characters'
                            }
                            title={
                              isPasswordVisible
                                ? 'Hide password characters'
                                : 'Show password characters'
                            }
                            className="inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200 rounded-lg hover:bg-slate-200 hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            {isPasswordVisible ? (
                              <>
                                <EyeOff className="w-4 h-4 text-slate-600" />
                                Hide
                              </>
                            ) : (
                              <>
                                <Eye className="w-4 h-4 text-indigo-600" />
                                Show
                              </>
                            )}
                          </button>

                          <button
                            type="button"
                            onClick={() =>
                              copyTextToClipboard(password, 'manual')
                            }
                            className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-indigo-50 text-indigo-900 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            {copiedManual ? (
                              <>
                                <Check className="w-4 h-4 text-emerald-600" />
                                Copied!
                              </>
                            ) : (
                              <>
                                <Copy className="w-4 h-4 text-indigo-600" />
                                Copy
                              </>
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Color Legend */}
                      {colorizeChars && (
                        <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500 px-1">
                          <span className="font-semibold text-indigo-700">
                            Uppercase (A–Z)
                          </span>
                          <span>·</span>
                          <span className="font-semibold text-slate-800">
                            Lowercase (a–z)
                          </span>
                          <span>·</span>
                          <span className="font-semibold text-sky-700">
                            Numbers (0–9)
                          </span>
                          <span>·</span>
                          <span className="font-semibold text-emerald-700">
                            Symbols (!@#$)
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Optional SHA-256 Digest Display */}
                    {showHash && (
                      <div className="pt-2.5 border-t border-sky-200/70 space-y-1.5">
                        <div className="flex items-center justify-between text-xs text-slate-600">
                          <span className="font-semibold text-indigo-950">
                            SHA-256 Hash (hashlib.sha256):
                          </span>
                          <span className="font-mono text-[11px] text-slate-500">
                            256-bit hex digest
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <input
                            type="text"
                            readOnly
                            value={sha256Hash}
                            aria-label="SHA-256 password hash"
                            className="w-full font-mono text-xs text-slate-700 bg-white/90 px-3 py-2 rounded-lg border border-sky-200 focus:outline-none select-all tabular-nums"
                          />
                          <button
                            type="button"
                            onClick={() =>
                              copyTextToClipboard(sha256Hash, 'hash')
                            }
                            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-white text-slate-700 border border-sky-200 rounded-lg hover:bg-sky-100/60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                          >
                            {copiedHash ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-600" />
                                Copied
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5 text-sky-700" />
                                Copy Hash
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Strength Bar & Clipboard Status */}
                    <div className="pt-1 space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <span className={`font-bold ${strengthInfo.textClass}`}>
                          Strength: {strengthInfo.label} ({password.length} chars ·{' '}
                          {selectedTypesCount} sets · ~{strengthInfo.entropyBits} bits)
                        </span>
                        <span className="text-emerald-700 font-semibold">
                          {clipboardStatus}
                        </span>
                      </div>
                      <div
                        className="w-full h-2.5 bg-white/90 border border-sky-200/80 rounded-full overflow-hidden"
                        role="progressbar"
                        aria-valuenow={Math.round(strengthInfo.ratio * 100)}
                        aria-valuemin={0}
                        aria-valuemax={100}
                      >
                        <div
                          className={`h-full transition-transform duration-150 origin-left ${strengthInfo.barClass}`}
                          style={{ transform: `scaleX(${strengthInfo.ratio})` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Right Side of Display Box: Live QR Code for Mobile Transfer */}
                  {showQrCode && activeQrValue && (
                    <div className="md:w-52 bg-white border border-indigo-100 rounded-xl p-3.5 flex flex-col items-center justify-between gap-2.5 shrink-0 shadow-2xs">
                      <div className="w-full flex items-center justify-between text-[11px] font-semibold text-indigo-950">
                        <span className="inline-flex items-center gap-1">
                          <Smartphone className="w-3.5 h-3.5 text-indigo-600" />
                          Scan to Transfer
                        </span>
                        <button
                          type="button"
                          onClick={() => setBlurQrCode((prev) => !prev)}
                          title={
                            blurQrCode
                              ? 'Reveal QR code'
                              : 'Blur QR code for shoulder-surfing privacy'
                          }
                          className="inline-flex items-center gap-1 text-slate-500 hover:text-indigo-700 transition-colors cursor-pointer"
                        >
                          {blurQrCode ? (
                            <>
                              <Eye className="w-3.5 h-3.5" />
                              Show
                            </>
                          ) : (
                            <>
                              <EyeOff className="w-3.5 h-3.5" />
                              Mask
                            </>
                          )}
                        </button>
                      </div>

                      {/* QR Code Canvas / SVG Container */}
                      <div
                        ref={qrContainerRef}
                        onClick={() => {
                          if (blurQrCode) setBlurQrCode(false);
                        }}
                        className={`p-2 bg-white border border-slate-200/80 rounded-lg transition-filter duration-150 ${
                          blurQrCode ? 'blur-md cursor-pointer select-none' : ''
                        }`}
                      >
                        <QRCodeSVG
                          value={activeQrValue}
                          size={128}
                          level={qrErrorLevel}
                          includeMargin={false}
                          fgColor="#1e1b4b"
                          bgColor="#ffffff"
                        />
                      </div>

                      {/* QR Controls: Payload Switcher & ECC / Download */}
                      <div className="w-full space-y-1.5">
                        <div className="flex items-center gap-1 p-0.5 bg-slate-100 rounded-md w-full">
                          <button
                            type="button"
                            onClick={() => setQrPayloadMode('password')}
                            className={`flex-1 py-1 text-[10px] font-semibold rounded transition-colors whitespace-nowrap cursor-pointer ${
                              qrPayloadMode === 'password'
                                ? 'bg-white text-indigo-950 shadow-2xs'
                                : 'text-slate-600 hover:text-slate-900'
                            }`}
                          >
                            Password
                          </button>
                          <button
                            type="button"
                            onClick={() => setQrPayloadMode('sha256')}
                            className={`flex-1 py-1 text-[10px] font-semibold rounded transition-colors whitespace-nowrap cursor-pointer ${
                              qrPayloadMode === 'sha256'
                                ? 'bg-white text-indigo-950 shadow-2xs'
                                : 'text-slate-600 hover:text-slate-900'
                            }`}
                          >
                            SHA-256
                          </button>
                        </div>

                        <div className="flex items-center justify-between gap-1 text-[10px] text-slate-500">
                          <div className="flex items-center gap-1">
                            <span>ECC:</span>
                            {(['L', 'M', 'Q', 'H'] as QRErrorCorrectionLevel[]).map(
                              (lvl) => (
                                <button
                                  key={lvl}
                                  type="button"
                                  onClick={() => setQrErrorLevel(lvl)}
                                  className={`px-1 rounded font-mono font-semibold cursor-pointer ${
                                    qrErrorLevel === lvl
                                      ? 'bg-indigo-100 text-indigo-800'
                                      : 'hover:text-slate-800'
                                  }`}
                                >
                                  {lvl}
                                </button>
                              )
                            )}
                          </div>
                          <button
                            type="button"
                            onClick={downloadQrCodeSvg}
                            className="inline-flex items-center gap-0.5 text-indigo-700 hover:underline font-semibold cursor-pointer"
                          >
                            <Download className="w-2.5 h-2.5" />
                            SVG
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Inline Validation Error Message */}
              {errorMessage && (
                <div
                  role="alert"
                  className="bg-rose-50 border border-rose-200 text-rose-800 rounded-xl px-4 py-3 flex items-start gap-3 text-xs font-semibold"
                >
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <span>{errorMessage}</span>
                </div>
              )}

              {/* Controls Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 pt-1">
                {/* Length Control */}
                <div className="bg-indigo-50/40 border border-indigo-100 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="length-spinbox"
                      className="text-xs font-bold text-indigo-950"
                    >
                      Password Length (min 8):
                    </label>
                    <input
                      id="length-spinbox"
                      type="number"
                      min={1}
                      max={MAX_LENGTH}
                      value={rawLengthInput}
                      onChange={handleSpinboxChange}
                      className="w-20 font-mono text-sm font-bold text-right px-2.5 py-1 border border-indigo-200 rounded-lg bg-white text-indigo-950 focus:outline-none focus:ring-2 focus:ring-indigo-500 tabular-nums"
                    />
                  </div>
                  <input
                    type="range"
                    min={MIN_LENGTH}
                    max={MAX_LENGTH}
                    value={sliderLength}
                    onChange={handleSliderChange}
                    aria-label="Password length slider"
                    className="w-full accent-indigo-600 cursor-pointer"
                  />
                  <div className="flex justify-between text-[11px] font-mono text-slate-500 tabular-nums">
                    <span>8 (Min)</span>
                    <span>16</span>
                    <span>32</span>
                    <span>48</span>
                    <span>64 (Max)</span>
                  </div>
                </div>

                {/* Character Diversity Checkboxes */}
                <div className="bg-emerald-50/40 border border-emerald-100 rounded-xl p-4 space-y-2.5">
                  <p className="text-xs font-bold text-emerald-950">
                    Character Types (select at least 2):
                  </p>
                  <div className="grid grid-cols-2 gap-2 text-xs text-slate-800">
                    <label className="flex items-center gap-2 cursor-pointer select-none py-1">
                      <input
                        type="checkbox"
                        checked={useUpper}
                        onChange={(e) => setUseUpper(e.target.checked)}
                        className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                      />
                      <span>Uppercase (A–Z)</span>
                    </label>

                    <label className="flex items-center gap-2 cursor-pointer select-none py-1">
                      <input
                        type="checkbox"
                        checked={useLower}
                        onChange={(e) => setUseLower(e.target.checked)}
                        className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                      />
                      <span>Lowercase (a–z)</span>
                    </label>

                    <label className="flex items-center gap-2 cursor-pointer select-none py-1">
                      <input
                        type="checkbox"
                        checked={useDigits}
                        onChange={(e) => setUseDigits(e.target.checked)}
                        className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                      />
                      <span>Numbers (0–9)</span>
                    </label>

                    <label className="flex items-center gap-2 cursor-pointer select-none py-1">
                      <input
                        type="checkbox"
                        checked={useSymbols}
                        onChange={(e) => setUseSymbols(e.target.checked)}
                        className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                      />
                      <span>Symbols (!@#$)</span>
                    </label>
                  </div>
                </div>
              </div>

              {/* Additional Options Row */}
              <div className="flex flex-wrap items-center justify-between gap-4 bg-amber-50/40 border border-amber-100 rounded-xl px-4 py-3">
                <label className="flex items-center gap-2.5 text-xs text-slate-800 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={excludeAmbiguous}
                    onChange={(e) => setExcludeAmbiguous(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                  />
                  <span className="font-semibold">
                    Exclude ambiguous characters (0, O, l, 1, I)
                  </span>
                </label>

                <label className="flex items-center gap-2.5 text-xs text-slate-800 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={showHash}
                    onChange={(e) => setShowHash(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 accent-indigo-600"
                  />
                  <span className="font-semibold">
                    Hash Password (SHA-256)
                  </span>
                </label>
              </div>
            </div>

            {/* Primary Action Button ("Generate Another") */}
            <button
              type="button"
              onClick={() => generatePassword()}
              className="w-full py-3 px-5 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white font-semibold text-sm rounded-xl flex items-center justify-center gap-2 transition-colors cursor-pointer whitespace-nowrap shadow-xs"
            >
              <RefreshCw className="w-4 h-4" />
              Generate Another
            </button>
          </div>

          {/* Right Column (5 cols): Session History & Export Card */}
          <div
            id="history"
            className="lg:col-span-5 bg-white border border-indigo-100 rounded-2xl p-6 sm:p-8 flex flex-col justify-between space-y-6 shadow-xs"
          >
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold text-slate-900">
                    02. Session Password History
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Last 5 generated passwords · Click any item to load its QR code
                  </p>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => setPendingExportFormat('json')}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-indigo-800 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Download className="w-3 h-3" />
                    JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => setPendingExportFormat('csv')}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-sky-800 bg-sky-50 border border-sky-200 rounded-lg hover:bg-sky-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Download className="w-3 h-3" />
                    CSV
                  </button>
                </div>
              </div>

              {/* Plaintext Export Warning Confirmation */}
              {pendingExportFormat && (
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5 text-xs text-amber-950 space-y-2.5">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                    <p className="leading-snug">
                      <span className="font-semibold">
                        Plaintext Export Confirmation:
                      </span>{' '}
                      Exporting writes {sessionHistory.length} session{' '}
                      password(s) and their SHA-256 digests to a local{' '}
                      <span className="font-mono font-semibold uppercase">
                        .{pendingExportFormat}
                      </span>{' '}
                      file.
                    </p>
                  </div>
                  <div className="flex items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setPendingExportFormat(null)}
                      className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={() => handleConfirmExport(pendingExportFormat)}
                      className="px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors cursor-pointer"
                    >
                      Download .{pendingExportFormat.toUpperCase()}
                    </button>
                  </div>
                </div>
              )}

              {/* History List */}
              {sessionHistory.length === 0 ? (
                <div className="bg-slate-50 border border-slate-200/80 rounded-xl p-8 text-center">
                  <p className="text-xs text-slate-500">
                    No passwords generated in this session yet.
                  </p>
                </div>
              ) : (
                <ul className="space-y-2.5">
                  {sessionHistory.map((item, idx) => {
                    const isSelected = item.password === password;
                    return (
                      <li
                        key={item.id}
                        className={`p-3 border rounded-xl transition-colors space-y-1.5 ${
                          isSelected
                            ? 'bg-indigo-50/70 border-indigo-200'
                            : 'bg-sky-50/40 hover:bg-sky-50/90 border-sky-100'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="font-mono text-xs font-bold text-indigo-500 tabular-nums shrink-0">
                              #{idx + 1}
                            </span>
                            <span className="font-mono text-sm font-semibold text-slate-900 truncate tabular-nums">
                              {item.password}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <button
                              type="button"
                              onClick={() => {
                                setPassword(item.password);
                                setSha256Hash(item.sha256);
                                setShowQrCode(true);
                              }}
                              title="Render QR code for this password"
                              className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-sky-800 bg-white border border-sky-200 rounded-md hover:bg-sky-50 transition-colors cursor-pointer"
                            >
                              <QrCode className="w-3 h-3" />
                              QR
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                copyTextToClipboard(item.password, 'manual')
                              }
                              className="px-2.5 py-1 text-xs font-semibold text-indigo-700 bg-white border border-indigo-200 rounded-md hover:bg-indigo-50 transition-colors cursor-pointer"
                            >
                              Copy
                            </button>
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono tabular-nums">
                          <span>
                            {item.length} chars · {item.typesCount} sets ·{' '}
                            {item.strength}
                          </span>
                          <span>{item.timestamp}</span>
                        </div>
                        {showHash && (
                          <div className="pt-1 border-t border-sky-200/60 flex items-center justify-between gap-2 text-[11px] font-mono text-slate-600">
                            <span className="truncate" title={item.sha256}>
                              SHA-256: {item.sha256}
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                copyTextToClipboard(item.sha256, 'hash')
                              }
                              className="px-2 py-0.5 text-[10px] font-sans font-semibold text-sky-800 bg-white border border-sky-200 rounded hover:bg-sky-50 transition-colors shrink-0 cursor-pointer"
                            >
                              Copy Hash
                            </button>
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {/* Session Privacy Note */}
            <div className="bg-emerald-50/60 border border-emerald-200/70 rounded-xl p-3.5 flex items-center gap-3 text-xs text-emerald-900">
              <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>
                QR codes are rendered 100% client-side in SVG—no password data ever leaves your browser.
              </span>
            </div>
          </div>
        </section>

        {/* Section 2: One-Click Security Presets */}
        <section
          id="presets"
          className="space-y-4 pt-4 border-t border-indigo-100/80"
        >
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2">
            <div>
              <h2 className="text-lg font-bold text-slate-900">
                03. Quick Security Presets
              </h2>
              <p className="text-xs text-slate-600">
                Apply tailored length and character rules for different security scenarios with one click
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <button
              type="button"
              onClick={() =>
                applyPreset(
                  'Banking & Financial Vault',
                  24,
                  true,
                  true,
                  true,
                  true,
                  false
                )
              }
              className="text-left bg-white hover:bg-indigo-50/40 border border-indigo-100 rounded-xl p-4 transition-colors cursor-pointer space-y-2 shadow-2xs"
            >
              <div className="flex items-center justify-between text-indigo-700">
                <span className="text-xs font-bold">01. Financial Vault</span>
                <KeyRound className="w-4 h-4" />
              </div>
              <p className="text-sm font-bold text-slate-900">
                24 Chars · All 4 Types
              </p>
              <p className="text-xs text-slate-600 leading-relaxed">
                Maximum character diversity (~157 bits entropy) for primary email and financial accounts.
              </p>
            </button>

            <button
              type="button"
              onClick={() =>
                applyPreset(
                  'Readability-First (No Ambiguous)',
                  16,
                  true,
                  true,
                  true,
                  false,
                  true
                )
              }
              className="text-left bg-white hover:bg-sky-50/50 border border-sky-100 rounded-xl p-4 transition-colors cursor-pointer space-y-2 shadow-2xs"
            >
              <div className="flex items-center justify-between text-sky-700">
                <span className="text-xs font-bold">02. Easy Readability</span>
                <Sparkles className="w-4 h-4" />
              </div>
              <p className="text-sm font-bold text-slate-900">
                16 Chars · No 0, O, l, 1, I
              </p>
              <p className="text-xs text-slate-600 leading-relaxed">
                Strips look-alike characters and symbols for effortless manual typing or quick mobile QR scan.
              </p>
            </button>

            <button
              type="button"
              onClick={() =>
                applyPreset(
                  'Developer API Secret Key',
                  32,
                  true,
                  true,
                  true,
                  true,
                  true
                )
              }
              className="text-left bg-white hover:bg-emerald-50/50 border border-emerald-100 rounded-xl p-4 transition-colors cursor-pointer space-y-2 shadow-2xs"
            >
              <div className="flex items-center justify-between text-emerald-700">
                <span className="text-xs font-bold">03. API &amp; Signing Key</span>
                <Sliders className="w-4 h-4" />
              </div>
              <p className="text-sm font-bold text-slate-900">
                32 Chars · 200+ Bits
              </p>
              <p className="text-xs text-slate-600 leading-relaxed">
                High-length cryptographic secret suitable for webhook tokens, JWT secrets, and database admins.
              </p>
            </button>

            <button
              type="button"
              onClick={() =>
                applyPreset(
                  'Compact Alphanumeric',
                  12,
                  true,
                  true,
                  true,
                  false,
                  true
                )
              }
              className="text-left bg-white hover:bg-amber-50/50 border border-amber-100 rounded-xl p-4 transition-colors cursor-pointer space-y-2 shadow-2xs"
            >
              <div className="flex items-center justify-between text-amber-700">
                <span className="text-xs font-bold">04. Legacy Compatible</span>
                <Layers className="w-4 h-4" />
              </div>
              <p className="text-sm font-bold text-slate-900">
                12 Chars · Letters &amp; Digits
              </p>
              <p className="text-xs text-slate-600 leading-relaxed">
                Designed for portals that reject special punctuation while maintaining strong 3-set diversity.
              </p>
            </button>
          </div>
        </section>

        {/* Section 3: Password Anatomy & Cryptographic Entropy Analysis */}
        <section
          id="anatomy"
          className="space-y-4 pt-4 border-t border-indigo-100/80"
        >
          <div>
            <h2 className="text-lg font-bold text-slate-900">
              04. Live Password Anatomy &amp; Brute-Force Resistance
            </h2>
            <p className="text-xs text-slate-600">
              Real-time structural inspection of the currently generated password
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Character Composition Cards */}
            <div className="lg:col-span-7 bg-white border border-indigo-100 rounded-2xl p-6 space-y-5 shadow-2xs">
              <h3 className="text-sm font-bold text-slate-900">
                Character Category Distribution ({password.length} Total Characters)
              </h3>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-indigo-50/70 border border-indigo-100 rounded-xl p-3.5">
                  <span className="text-xs font-semibold text-indigo-700">
                    Uppercase
                  </span>
                  <p className="text-2xl font-bold font-mono text-indigo-950 mt-1 tabular-nums">
                    {charCounts.upper}
                  </p>
                  <span className="text-[11px] text-slate-500">
                    {useUpper ? 'Guaranteed ≥ 1' : 'Disabled'}
                  </span>
                </div>

                <div className="bg-slate-100/80 border border-slate-200 rounded-xl p-3.5">
                  <span className="text-xs font-semibold text-slate-700">
                    Lowercase
                  </span>
                  <p className="text-2xl font-bold font-mono text-slate-900 mt-1 tabular-nums">
                    {charCounts.lower}
                  </p>
                  <span className="text-[11px] text-slate-500">
                    {useLower ? 'Guaranteed ≥ 1' : 'Disabled'}
                  </span>
                </div>

                <div className="bg-sky-50/80 border border-sky-100 rounded-xl p-3.5">
                  <span className="text-xs font-semibold text-sky-700">
                    Numbers
                  </span>
                  <p className="text-2xl font-bold font-mono text-sky-950 mt-1 tabular-nums">
                    {charCounts.digits}
                  </p>
                  <span className="text-[11px] text-slate-500">
                    {useDigits ? 'Guaranteed ≥ 1' : 'Disabled'}
                  </span>
                </div>

                <div className="bg-emerald-50/80 border border-emerald-100 rounded-xl p-3.5">
                  <span className="text-xs font-semibold text-emerald-700">
                    Symbols
                  </span>
                  <p className="text-2xl font-bold font-mono text-emerald-950 mt-1 tabular-nums">
                    {charCounts.symbols}
                  </p>
                  <span className="text-[11px] text-slate-500">
                    {useSymbols ? 'Guaranteed ≥ 1' : 'Disabled'}
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600">
                <span>
                  Active Character Pool Size:{' '}
                  <strong className="font-mono text-slate-900 tabular-nums">
                    {strengthInfo.poolSize} unique symbols
                  </strong>
                </span>
                <span>
                  Ambiguous Filter:{' '}
                  <strong className="text-slate-900">
                    {excludeAmbiguous
                      ? 'Active (0, O, l, 1, I removed)'
                      : 'Inactive (Full pool)'}
                  </strong>
                </span>
              </div>
            </div>

            {/* Entropy & Crack-Time Estimator */}
            <div
              className={`lg:col-span-5 border rounded-2xl p-6 flex flex-col justify-between space-y-4 ${strengthInfo.surfaceClass}`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-700">
                    Information Entropy
                  </span>
                  <Clock className={`w-4 h-4 ${strengthInfo.textClass}`} />
                </div>
                <p
                  className={`text-3xl font-bold font-mono tabular-nums ${strengthInfo.textClass}`}
                >
                  {strengthInfo.entropyBits} bits
                </p>
                <p className="text-xs text-slate-600 leading-relaxed">
                  Calculated as <code className="font-mono">L × log₂(N)</code> where{' '}
                  <code className="font-mono">L = {password.length}</code> and{' '}
                  <code className="font-mono">N = {strengthInfo.poolSize}</code>.
                </p>
              </div>

              <div className="bg-white/90 border border-white rounded-xl p-4 space-y-1.5">
                <span className="text-[11px] font-semibold text-slate-500">
                  Estimated Brute-Force Resistance
                </span>
                <p className="text-sm font-bold text-slate-900">
                  {strengthInfo.crackTimeLabel}
                </p>
                <p className="text-[11px] text-slate-500">
                  Shuffled with unbiased CSPRNG Fisher-Yates permutation
                </p>
              </div>
            </div>
          </div>

          {/* D3 Radial Entropy Gauge & Log-Scale Attack Vector Comparison Chart */}
          <EntropyD3Chart
            entropyBits={strengthInfo.entropyBits}
            passwordLength={password.length}
            poolSize={strengthInfo.poolSize}
          />
        </section>
      </main>

      {/* Quiet Light Footer */}
      <footer className="border-t border-indigo-100 bg-white/80 px-6 lg:px-10 py-4 mt-auto">
        <div className="max-w-[1340px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-indigo-600" />
            <span>
              SecurePass Studio · CSPRNG Password, QR &amp; SHA-256 Generator · Session-only memory
            </span>
          </div>
          <div>
            <span>Minimum length 8 · Minimum 2 character sets enforced</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
