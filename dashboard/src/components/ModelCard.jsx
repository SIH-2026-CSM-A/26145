import React from 'react';
import { motion } from 'motion/react';
import { X, Database, FlaskConical, Gauge, BarChart3, EyeOff, ShieldCheck, TriangleAlert } from 'lucide-react';
import card from '../modelCard.json';

// Every figure is quoted from docs/MODELS.md; tests/training/test_model_card_facts.py fails on drift.
const ICON = { 'Trained on': Database, 'Validated by': FlaskConical, 'Alert budget': Gauge, 'Held-out result': BarChart3,
  'Cannot see': EyeOff, 'Guard rails': ShieldCheck, 'Known failure modes': TriangleAlert };
const WARN = new Set(['Held-out result', 'Cannot see', 'Known failure modes']);

export default function ModelCard({ onClose }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/80 p-6" onClick={onClose}>
      <motion.div initial={{ opacity: 0, y: 16, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={{ duration: 0.3 }}
                  className="glass max-h-[92vh] w-full max-w-5xl overflow-y-auto !bg-panel/95 p-7" onClick={(e) => e.stopPropagation()} data-testid="model-card">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <div className="eyebrow">Model card</div>
            <h2 className="mt-1 text-3xl font-semibold text-fg">{card.title}</h2>
            <p className="mt-1 text-sm text-dim">Every figure is quoted from {card.source}; a test fails if they drift.</p>
          </div>
          <button onClick={onClose} className="rounded-full p-1.5 text-dim hover:bg-deep hover:text-fg" aria-label="Close model card"><X className="h-6 w-6" /></button>
        </div>
        <div className="grid grid-cols-2 gap-3">
          {card.items.map((it, i) => {
            const Icon = ICON[it.label] || Database, warn = WARN.has(it.label);
            return (
              <motion.div key={it.label} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 * i }}
                          className={`flex gap-4 rounded-xl bg-deep/60 p-4 ring-1 ${warn ? 'ring-amber-400/25' : 'ring-line/15'} ${i === card.items.length - 1 && i % 2 === 0 ? 'col-span-2' : ''}`}>
                <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${warn ? 'bg-amber-400/10 text-amber-300' : 'bg-brand/10 text-brand'}`}><Icon className="h-5 w-5" /></div>
                <div>
                  <div className="eyebrow">{it.label}</div>
                  <div className="mt-1 text-[16px] leading-snug text-fg">{it.text}</div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </motion.div>
    </div>
  );
}
