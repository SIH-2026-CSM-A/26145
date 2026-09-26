import React from 'react';
import { X } from 'lucide-react';
import card from '../modelCard.json';

export default function ModelCard({ onClose }) {
  return (
    <div className="fixed inset-0 z-30 bg-slate-950/70 flex items-center justify-center p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-slate-900 ring-1 ring-slate-700 rounded-xl p-5" onClick={(e) => e.stopPropagation()} data-testid="model-card">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h2 className="text-lg font-bold text-slate-50">{card.title}</h2>
            <p className="text-xs text-slate-400">Every figure is quoted from {card.source}; a test fails if they drift.</p>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-slate-800 text-slate-400" aria-label="Close model card"><X className="w-5 h-5" /></button>
        </div>
        <dl className="divide-y divide-slate-800">
          {card.items.map((it) => (
            <div key={it.label} className="py-2.5 grid grid-cols-[140px_1fr] gap-3">
              <dt className="text-xs uppercase tracking-wider text-slate-400 pt-0.5">{it.label}</dt>
              <dd className="text-sm text-slate-100">{it.text}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}
