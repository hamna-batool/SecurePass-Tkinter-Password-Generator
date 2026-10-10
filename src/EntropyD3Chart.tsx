import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

interface EntropyD3ChartProps {
  entropyBits: number;
  passwordLength: number;
  poolSize: number;
}

interface AttackVector {
  id: string;
  name: string;
  rateLabel: string;
  guessesPerSecond: number;
  description: string;
}

const ATTACK_VECTORS: AttackVector[] = [
  {
    id: 'online',
    name: 'Online Rate-Limited API',
    rateLabel: '10² guesses/s',
    guessesPerSecond: 1e2,
    description: 'Throttled web login or MFA-backed endpoint',
  },
  {
    id: 'slow_kdf',
    name: 'Offline Slow Hash (Argon2id / bcrypt)',
    rateLabel: '10⁵ guesses/s',
    guessesPerSecond: 1e5,
    description: 'Breached database with memory-hard key derivation',
  },
  {
    id: 'fast_gpu',
    name: 'Offline Fast Hash (Multi-GPU SHA-256)',
    rateLabel: '10¹⁰ guesses/s',
    guessesPerSecond: 1e10,
    description: 'Dedicated 8× flagship GPU cracking rig',
  },
  {
    id: 'asic_cluster',
    name: 'Distributed ASIC / Supercluster',
    rateLabel: '10¹⁴ guesses/s',
    guessesPerSecond: 1e14,
    description: 'Large-scale custom hardware array (100T H/s)',
  },
];

function formatDurationSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds > 3.154e23) {
    return '> 10¹⁶ years';
  }
  if (seconds < 1) return '< 1 second';
  if (seconds < 60) return `${seconds.toFixed(1)} secs`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${minutes.toFixed(1)} mins`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(1)} hours`;
  const days = hours / 24;
  if (days < 365.25) return `${days.toFixed(1)} days`;
  const years = days / 365.25;
  if (years < 1e3) return `${years.toFixed(1)} years`;
  if (years < 1e6) return `${(years / 1e3).toFixed(1)}k years`;
  if (years < 1e9) return `${(years / 1e6).toFixed(1)}M years`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)}B years`;
  return `${(years / 1e12).toFixed(1)}T years`;
}

export const EntropyD3Chart: React.FC<EntropyD3ChartProps> = ({
  entropyBits,
  passwordLength,
  poolSize,
}) => {
  const gaugeSvgRef = useRef<SVGSVGElement | null>(null);
  const barsSvgRef = useRef<SVGSVGElement | null>(null);

  // 1. Render D3 Radial Entropy Gauge
  useEffect(() => {
    if (!gaugeSvgRef.current) return;

    const svg = d3.select(gaugeSvgRef.current);
    svg.selectAll('*').remove();

    const width = 320;
    const height = 185;
    const centerX = width / 2;
    const centerY = height - 26;
    const outerRadius = 122;
    const innerRadius = 92;

    const maxGaugeBits = 200;
    const clampedBits = Math.max(0, Math.min(maxGaugeBits, entropyBits));

    // Angle scale: -90 deg (-PI/2) to +90 deg (+PI/2)
    const angleScale = d3
      .scaleLinear()
      .domain([0, maxGaugeBits])
      .range([-Math.PI / 2, Math.PI / 2]);

    const g = svg
      .attr('viewBox', `0 0 ${width} ${height}`)
      .append('g')
      .attr('transform', `translate(${centerX}, ${centerY})`);

    // Security threshold zones on the arc
    const zones = [
      { from: 0, to: 50, color: '#fda4af', label: 'Weak' }, // Rose
      { from: 50, to: 80, color: '#fcd34d', label: 'Fair' }, // Amber
      { from: 80, to: 128, color: '#818cf8', label: 'Strong' }, // Indigo
      { from: 128, to: maxGaugeBits, color: '#34d399', label: 'Vault' }, // Emerald
    ];

    const arcGenerator = d3
      .arc<{ from: number; to: number }>()
      .innerRadius(innerRadius)
      .outerRadius(outerRadius)
      .startAngle((d) => angleScale(d.from))
      .endAngle((d) => angleScale(d.to))
      .padAngle(0.02)
      .cornerRadius(4);

    // Draw background zone segments
    g.selectAll('.zone-arc')
      .data(zones)
      .enter()
      .append('path')
      .attr('class', 'zone-arc')
      .attr('d', (d) => arcGenerator(d) || '')
      .attr('fill', (d) => d.color)
      .attr('opacity', 0.35);

    // Active progress arc up to current entropyBits
    const activeColor =
      entropyBits < 50
        ? '#e11d48'
        : entropyBits < 80
        ? '#d97706'
        : entropyBits < 128
        ? '#4f46e5'
        : '#059669';

    const activeArc = d3
      .arc()
      .innerRadius(innerRadius)
      .outerRadius(outerRadius)
      .startAngle(-Math.PI / 2)
      .endAngle(angleScale(clampedBits))
      .cornerRadius(4);

    g.append('path')
      .attr(
        'd',
        activeArc({
          innerRadius,
          outerRadius,
          startAngle: -Math.PI / 2,
          endAngle: angleScale(clampedBits),
        }) || ''
      )
      .attr('fill', activeColor);

    // Tick marks at key entropy benchmarks (50, 80, 128, 200 bits)
    const ticks = [0, 50, 80, 128, 200];
    ticks.forEach((tickVal) => {
      const angle = angleScale(tickVal) - Math.PI / 2;
      const labelR = outerRadius + 15;
      const lx = Math.cos(angle) * labelR;
      const ly = Math.sin(angle) * labelR;

      g.append('text')
        .attr('x', lx)
        .attr('y', ly)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'middle')
        .attr('fill', '#64748b')
        .attr('font-size', '10px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-weight', '600')
        .text(`${tickVal}b`);
    });

    // Needle pointer
    const needleAngle = angleScale(clampedBits) - Math.PI / 2;
    const needleLength = innerRadius - 8;
    const nx = Math.cos(needleAngle) * needleLength;
    const ny = Math.sin(needleAngle) * needleLength;

    g.append('line')
      .attr('x1', 0)
      .attr('y1', 0)
      .attr('x2', nx)
      .attr('y2', ny)
      .attr('stroke', '#1e1b4b')
      .attr('stroke-width', 2.5)
      .attr('stroke-linecap', 'round');

    g.append('circle')
      .attr('cx', 0)
      .attr('cy', 0)
      .attr('r', 5)
      .attr('fill', '#1e1b4b');

    // Center readout text
    g.append('text')
      .attr('x', 0)
      .attr('y', -26)
      .attr('text-anchor', 'middle')
      .attr('fill', activeColor)
      .attr('font-size', '24px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('font-weight', '700')
      .text(`${entropyBits} bits`);

    g.append('text')
      .attr('x', 0)
      .attr('y', -8)
      .attr('text-anchor', 'middle')
      .attr('fill', '#475569')
      .attr('font-size', '11px')
      .attr('font-weight', '600')
      .text(
        `L=${passwordLength} · Pool=${poolSize} (${
          entropyBits >= 128
            ? 'NIST / Post-Quantum Ready'
            : entropyBits >= 80
            ? 'Resistant to Offline Rigs'
            : entropyBits >= 50
            ? 'Vulnerable to GPU Arrays'
            : 'Critical Brute-Force Risk'
        })`
      );
  }, [entropyBits, passwordLength, poolSize]);

  // 2. Render D3 Log10 Attack Vector Resistance Bar Chart
  useEffect(() => {
    if (!barsSvgRef.current) return;

    const svg = d3.select(barsSvgRef.current);
    svg.selectAll('*').remove();

    const width = 560;
    const height = 210;
    const margin = { top: 22, right: 110, bottom: 28, left: 10 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Average guesses required = 2^(entropyBits - 1)
    // Log10(seconds) = (entropyBits - 1) * log10(2) - log10(guessesPerSecond)
    const log10Two = Math.log10(2);
    const minLogSec = -2; // 0.01 sec
    const maxLogSec = 18; // ~31.7 billion years

    const xScale = d3
      .scaleLinear()
      .domain([minLogSec, maxLogSec])
      .range([0, innerWidth])
      .clamp(true);

    const yScale = d3
      .scaleBand()
      .domain(ATTACK_VECTORS.map((v) => v.id))
      .range([0, innerHeight])
      .padding(0.34);

    const g = svg
      .attr('viewBox', `0 0 ${width} ${height}`)
      .append('g')
      .attr('transform', `translate(${margin.left}, ${margin.top})`);

    // Vertical reference lines (1 Second, 1 Day, 1 Year, 1M Years)
    const milestones = [
      { logSec: 0, label: '1 sec' },
      { logSec: Math.log10(86400), label: '1 day' },
      { logSec: Math.log10(3.154e7), label: '1 year' },
      { logSec: Math.log10(3.154e10), label: '1k yrs' },
      { logSec: Math.log10(3.154e13), label: '1M yrs' },
    ];

    milestones.forEach((m) => {
      const xPos = xScale(m.logSec);
      g.append('line')
        .attr('x1', xPos)
        .attr('y1', -4)
        .attr('x2', xPos)
        .attr('y2', innerHeight)
        .attr('stroke', '#e2e8f0')
        .attr('stroke-dasharray', '3,3')
        .attr('stroke-width', 1);

      g.append('text')
        .attr('x', xPos)
        .attr('y', innerHeight + 16)
        .attr('text-anchor', 'middle')
        .attr('fill', '#64748b')
        .attr('font-size', '10px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .text(m.label);
    });

    // Plot sleek, thin bars for each attack vector
    ATTACK_VECTORS.forEach((vector) => {
      const bandTop = yScale(vector.id) ?? 0;
      const barH = 7;
      const yPos = bandTop + 14;

      const logSeconds =
        Math.max(0, entropyBits - 1) * log10Two -
        Math.log10(vector.guessesPerSecond);
      const seconds = Math.pow(10, Math.min(30, logSeconds));
      const barWidth = Math.max(6, xScale(logSeconds));

      // Color based on how long this attack takes
      const barColor =
        logSeconds < 3.5 // < ~1 hour
          ? '#f43f5e'
          : logSeconds < 7.5 // < ~1 year
          ? '#f59e0b'
          : logSeconds < 11 // < ~3,000 years
          ? '#6366f1'
          : '#10b981';

      // Label above bar
      g.append('text')
        .attr('x', 2)
        .attr('y', yPos - 6)
        .attr('fill', '#1e293b')
        .attr('font-size', '11px')
        .attr('font-weight', '600')
        .text(`${vector.name} (${vector.rateLabel})`);

      // Track background
      g.append('rect')
        .attr('x', 0)
        .attr('y', yPos)
        .attr('width', innerWidth)
        .attr('height', barH)
        .attr('rx', 3.5)
        .attr('fill', '#f1f5f9');

      // Filled log-scale resistance bar
      g.append('rect')
        .attr('x', 0)
        .attr('y', yPos)
        .attr('width', barWidth)
        .attr('height', barH)
        .attr('rx', 3.5)
        .attr('fill', barColor);

      // Duration text on the right
      g.append('text')
        .attr('x', innerWidth + 8)
        .attr('y', yPos + barH / 2 + 0.5)
        .attr('dominant-baseline', 'middle')
        .attr('fill', '#0f172a')
        .attr('font-size', '11px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-weight', '700')
        .text(formatDurationSeconds(seconds));
    });
  }, [entropyBits]);

  return (
    <div className="bg-white border border-indigo-100 rounded-2xl p-6 shadow-2xs space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-900">
            D3 Entropy Gauge &amp; Attack Vector Survival Chart
          </h3>
          <p className="text-xs text-slate-500">
            Log₁₀ time-to-crack across 50% keyspace (<code className="font-mono">2^(E−1)</code> guesses) against common threat models
          </p>
        </div>
        <div className="flex items-center gap-3 text-[11px] font-medium text-slate-600">
          <span className="text-rose-600 font-semibold">■ &lt;1 hr</span>
          <span>·</span>
          <span className="text-amber-600 font-semibold">■ &lt;1 yr</span>
          <span>·</span>
          <span className="text-indigo-600 font-semibold">■ Centuries</span>
          <span>·</span>
          <span className="text-emerald-600 font-semibold">■ Astronomical</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Left: D3 Radial Gauge */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center bg-indigo-50/30 border border-indigo-100/70 rounded-xl p-3">
          <svg
            ref={gaugeSvgRef}
            className="w-full max-w-[310px] h-auto overflow-visible"
            role="img"
            aria-label={`D3 entropy gauge showing ${entropyBits} bits`}
          />
        </div>

        {/* Right: D3 Horizontal Log-Scale Attack Vector Bars */}
        <div className="lg:col-span-7 flex flex-col justify-center">
          <svg
            ref={barsSvgRef}
            className="w-full h-auto overflow-visible"
            role="img"
            aria-label="D3 horizontal bar chart comparing time to crack across 4 attack vectors"
          />
        </div>
      </div>
    </div>
  );
};
