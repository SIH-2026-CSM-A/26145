import React from 'react';
import { BookOpen } from 'lucide-react';

// The honest replay line is always on screen: what is being replayed, how fast, which loop.
export function replayLine(src, state) {
  if (!src) return state ? 'Live pipeline' : 'No capture attached';
  return `Replay of ${src.capture} at ${src.speed ? `${src.speed}× real time` : 'full speed'}${src.loop ? ` · loop ${src.loop}` : ''}`;
}

const Mark = () => (
  <svg viewBox="0 0 32 32" className="h-9 w-9" aria-hidden>
    <rect x="1" y="1" width="30" height="30" rx="9" fill="rgb(94 230 255 / 0.12)" stroke="rgb(94 230 255 / 0.5)" />
    <path d="M7 16h9M16 10l7 6-7 6z" fill="#5ee6ff" stroke="#5ee6ff" strokeWidth="1.6" strokeLinejoin="round" />
    <path d="M24 9v14" stroke="#5ee6ff" strokeWidth="2.2" strokeLinecap="round" />
  </svg>
);

export default function TopBar({ metrics, live, onModelCard }) {
  const state = metrics?.pipeline_state;
  return (
    <header className="flex items-center gap-5 px-6 py-3">
      <div className="flex items-center gap-3">
        <Mark />
        <div className="leading-tight">
          <div className="text-xl font-bold tracking-[0.18em] text-fg">SAAKSHI</div>
          <div className="text-xs text-dim">Passive threat sensor for one-way links · SIH26145</div>
        </div>
      </div>
      <div className="ml-4 flex items-center gap-2 rounded-full bg-deep/80 px-3.5 py-1.5 text-sm ring-1 ring-line/20" data-testid="replay-banner">
        <span className={`h-2 w-2 rounded-full ${live ? 'bg-safe animate-pulse' : 'bg-amber-400'}`} />
        <span className="text-fg">{replayLine(metrics?.source, state)}</span>
        <span className="text-faint">·</span>
        <span className={live ? 'text-safe' : 'text-amber-300'}>{live ? (state === 'running' ? 'live' : state || 'connected') : 'reconnecting'}</span>
      </div>
      <button onClick={onModelCard} data-testid="model-card-button"
              className="ml-auto inline-flex items-center gap-2 rounded-full bg-panel/70 px-4 py-1.5 text-sm text-fg ring-1 ring-line/25 hover:ring-brand/60">
        <BookOpen className="h-4 w-4 text-brand" /> Model card
      </button>
    </header>
  );
}
