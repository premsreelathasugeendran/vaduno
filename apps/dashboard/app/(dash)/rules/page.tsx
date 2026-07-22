import { loadActivePolicy } from "../../../lib/data";

export const dynamic = "force-dynamic";

function ChipRow({ label, items, tone }: { label: string; items?: string[]; tone: "allow" | "block" }) {
  return (
    <div className="rule-block">
      <div className="rule-label">
        <span className="eyebrow">{label}</span>
        <span className="mono rule-count">{items?.length ?? 0}</span>
      </div>
      <div className="chip-wrap">
        {items && items.length > 0 ? (
          items.map((i) => (
            <span key={i} className={`chip ${tone}`}>
              {i}
            </span>
          ))
        ) : (
          <span className="chip-empty">none</span>
        )}
      </div>
    </div>
  );
}

export default async function RulesPage() {
  const policy = await loadActivePolicy();

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Rules</h1>
        <p className="lead-sub">Who and what your agents may pay — evaluated deterministically, before any money moves.</p>
      </div>

      <div className="panel reveal s2">
        <div className="panel-head"><h2>Merchants</h2><span className="meta">host &amp; payTo matching</span></div>
        <ChipRow label="Allowed" items={policy?.merchants?.allow} tone="allow" />
        <ChipRow label="Blocked" items={policy?.merchants?.block} tone="block" />
      </div>

      <div className="two-col reveal s3">
        <div className="panel">
          <div className="panel-head"><h2>Categories</h2></div>
          <ChipRow label="Allowed" items={policy?.categories?.allow} tone="allow" />
          <ChipRow label="Blocked" items={policy?.categories?.block} tone="block" />
        </div>
        <div className="panel">
          <div className="panel-head"><h2>Rails</h2></div>
          <ChipRow label="Allowed" items={policy?.rails?.allow} tone="allow" />
        </div>
      </div>
    </>
  );
}
