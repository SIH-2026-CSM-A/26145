import React, { useEffect, useRef } from 'react';
import { animate } from 'animejs';
import { useReducedMotion } from 'motion/react';

// A number that counts to its new value (anime.js). null shows an em dash.
export default function Counter({ value, format = (v) => Math.round(v).toLocaleString('en-US'), className = '', ...rest }) {
  const el = useRef(null), cur = useRef({ v: 0 }), reduced = useReducedMotion();
  useEffect(() => {
    if (value === null || value === undefined || !Number.isFinite(value)) { el.current.textContent = '—'; return; }
    const show = () => { el.current.textContent = format(cur.current.v); };
    if (reduced) { cur.current.v = value; show(); return; }
    const a = animate(cur.current, { v: value, duration: 900, ease: 'outExpo', onUpdate: show, onComplete: show });
    return () => a.pause();
  }, [value, reduced]); // eslint-disable-line react-hooks/exhaustive-deps
  return <span ref={el} className={className} {...rest}>—</span>;
}
