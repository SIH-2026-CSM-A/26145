import React from 'react';

export default function Sparkline({ data, color = '#5ee6ff', width = 160, height = 44 }) {
  if (data.length < 2) return <svg width={width} height={height} />;
  const max = Math.max(...data, 1), step = width / (data.length - 1);
  const pts = data.map((v, i) => [i * step, height - 3 - (v / max) * (height - 6)]);
  const line = pts.map((p) => p.join(',')).join(' ');
  return (
    <svg width={width} height={height} className="overflow-visible" aria-hidden>
      <defs><linearGradient id="spk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={color} stopOpacity="0.35" /><stop offset="1" stopColor={color} stopOpacity="0" /></linearGradient></defs>
      <polygon points={`0,${height} ${line} ${width},${height}`} fill="url(#spk)" />
      <polyline points={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
      <circle cx={pts.at(-1)[0]} cy={pts.at(-1)[1]} r="3" fill={color} />
    </svg>
  );
}
