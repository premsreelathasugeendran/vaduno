"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { NAV } from "./Sidebar";

const Ctx = createContext<() => void>(() => {});
export const useCommandPalette = () => useContext(Ctx);

const ITEMS = [
  ...NAV.map((n) => ({ label: n.label, href: n.href, hint: "Page" })),
  { label: "Settings", href: "/settings", hint: "Page" },
  { label: "Audit chain", href: "/audit", hint: "Verify integrity" },
];

export function CommandPaletteProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);

  const show = useCallback(() => setOpen(true), []);

  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return ITEMS;
    return ITEMS.filter((i) => i.label.toLowerCase().includes(t) || i.hint.toLowerCase().includes(t));
  }, [q]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (open) {
      setQ("");
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  const go = useCallback(
    (href: string) => {
      setOpen(false);
      router.push(href);
    },
    [router],
  );

  if (!open) return <Ctx.Provider value={show}>{children}</Ctx.Provider>;

  return (
    <Ctx.Provider value={show}>
      {children}
      <div className="cmdk-overlay" onClick={() => setOpen(false)}>
        <div className="cmdk" onClick={(e) => e.stopPropagation()}>
          <div className="cmdk-input-row">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="7" />
              <path d="M21 21l-4-4" strokeLinecap="round" />
            </svg>
            <input
              ref={inputRef}
              className="cmdk-input"
              placeholder="Jump to a page or action…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setIdx(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setIdx((i) => Math.min(i + 1, results.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setIdx((i) => Math.max(i - 1, 0));
                } else if (e.key === "Enter" && results[idx]) {
                  go(results[idx]!.href);
                }
              }}
            />
            <span className="kbd">esc</span>
          </div>
          <div className="cmdk-list">
            {results.length === 0 && <div className="cmdk-empty">No matches.</div>}
            {results.map((r, i) => (
              <button
                key={r.label}
                className={`cmdk-item${i === idx ? " active" : ""}`}
                onMouseEnter={() => setIdx(i)}
                onClick={() => go(r.href)}
              >
                <span>{r.label}</span>
                <span className="cmdk-hint">{r.hint}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </Ctx.Provider>
  );
}
