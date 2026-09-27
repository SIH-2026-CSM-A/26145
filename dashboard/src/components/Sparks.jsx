import React, { forwardRef, useImperativeHandle, useState } from 'react';
import { motion } from 'motion/react';

// Page-level layer: a coloured spark flies from the enclave to its threat-class tile.
const Sparks = forwardRef(function Sparks(_, ref) {
  const [list, setList] = useState([]);
  useImperativeHandle(ref, () => ({
    fly(from, to, color, onLand) {
      const id = Math.random();
      setList((l) => [...l, { id, from, to, color, onLand }]);
    },
  }), []);
  return (
    <div className="pointer-events-none fixed inset-0 z-40">
      {list.map((s) => {
        const mid = { x: (s.from.x + s.to.x) / 2, y: Math.min(s.from.y, s.to.y) - 80 };
        return (
          <motion.div key={s.id} className="absolute h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full"
                      style={{ background: s.color, boxShadow: `0 0 18px 6px ${s.color}` }}
                      initial={{ left: s.from.x, top: s.from.y, scale: 1.3 }}
                      animate={{ left: [s.from.x, mid.x, s.to.x], top: [s.from.y, mid.y, s.to.y], scale: [1.3, 1, 0.6] }}
                      transition={{ duration: 0.9, ease: 'easeInOut' }}
                      onAnimationComplete={() => { s.onLand(); setList((l) => l.filter((x) => x.id !== s.id)); }} />
        );
      })}
    </div>
  );
});
export default Sparks;
