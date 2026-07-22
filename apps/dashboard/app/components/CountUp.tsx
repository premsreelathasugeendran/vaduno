"use client";

import { useEffect, useRef, useState } from "react";

const faint = { color: "var(--text-faint)" };

/** Animated count-up (easeOutExpo). Respects prefers-reduced-motion. */
export function CountUp({
  value,
  decimals = 0,
  prefix,
  suffix,
  faintFraction,
  duration = 850,
}: {
  value: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  faintFraction?: boolean;
  duration?: number;
}) {
  const [n, setN] = useState(0);
  const raf = useRef<number>(0);

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce || value === 0) {
      setN(value);
      return;
    }
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      setN(value);
    };
    const start = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / duration);
      if (p >= 1) {
        finish();
        return;
      }
      setN(value * (1 - Math.pow(2, -10 * p)));
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    // Guarantee the final value even if rAF never fires (hidden/backgrounded
    // tab, non-compositing surface) — setTimeout runs where rAF is paused.
    const fallback = setTimeout(finish, duration + 400);
    return () => {
      cancelAnimationFrame(raf.current);
      clearTimeout(fallback);
    };
  }, [value, duration]);

  const [whole, fraction] = n.toFixed(decimals).split(".");
  const grouped = Number(whole).toLocaleString("en-US");

  return (
    <span style={{ fontVariantNumeric: "tabular-nums lining-nums" }}>
      {prefix && <span style={faint}>{prefix}</span>}
      {grouped}
      {fraction && <span style={faintFraction ? faint : undefined}>.{fraction}</span>}
      {suffix && <span style={faint}>{suffix}</span>}
    </span>
  );
}
