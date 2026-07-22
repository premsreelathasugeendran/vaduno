"use client";

import { useEffect, useRef, useState } from "react";

const faint = { color: "var(--text-faint)" };

/** Animated count-up (easeOutExpo). Respects prefers-reduced-motion. */
export function CountUp({
  value,
  decimals = 0,
  prefix,
  faintFraction,
  duration = 850,
}: {
  value: number;
  decimals?: number;
  prefix?: string;
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
    const start = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / duration);
      const eased = 1 - Math.pow(2, -10 * p);
      setN(value * (p >= 1 ? 1 : eased));
      if (p < 1) raf.current = requestAnimationFrame(tick);
      else setN(value);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [value, duration]);

  const [whole, fraction] = n.toFixed(decimals).split(".");
  const grouped = Number(whole).toLocaleString("en-US");

  return (
    <span style={{ fontVariantNumeric: "tabular-nums lining-nums" }}>
      {prefix && <span style={faint}>{prefix}</span>}
      {grouped}
      {fraction && <span style={faintFraction ? faint : undefined}>.{fraction}</span>}
    </span>
  );
}
