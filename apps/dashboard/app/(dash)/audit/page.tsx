import { loadRawLedger } from "../../../lib/data";
import { Seal } from "../../components/Seal";

export const dynamic = "force-dynamic";

const TYPE_LABEL: Record<string, string> = {
  intent_received: "intent received",
  policy_decision: "policy decision",
  approval_requested: "approval requested",
  approval_resolved: "approval resolved",
  mandate_issued: "mandate issued",
  mandate_consumed: "mandate consumed",
  execution_started: "execution started",
  execution_result: "execution result",
  policy_updated: "policy updated",
  guard_frozen: "guard frozen",
  guard_unfrozen: "guard unfrozen",
};

export default async function AuditPage() {
  const { entries, chain, head } = await loadRawLedger(40);

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Audit</h1>
        <p className="lead-sub">Every decision is written to a hash-chained, append-only ledger. Any edit is detectable.</p>
      </div>

      <div className={`audit-hero reveal s2 ${chain.ok ? "ok" : "bad"}`}>
        <div className="audit-seal">
          <Seal variant={chain.ok ? "verified" : "blocked"} size={52} />
        </div>
        <div>
          <div className="audit-status">{chain.ok ? "Chain verified" : `Tampering detected at seq ${chain.firstBadSeq}`}</div>
          <div className="audit-detail mono">
            {chain.entries} entries · head seq {head.seq} · head hash{" "}
            <span className="hash">{head.hash ? head.hash.slice(0, 16) : "—"}…</span>
          </div>
          <div className="audit-note">
            Re-derived every hash from genesis; {chain.ok ? "all links match — history is intact." : "a link failed — history was altered."}
          </div>
        </div>
      </div>

      <div className="panel reveal s3">
        <div className="panel-head"><h2>Hash chain</h2><span className="meta mono">latest {entries.length}</span></div>
        <div className="chain-list">
          {entries.map((e) => (
            <div className="chain-row" key={e.seq}>
              <span className="chain-seq mono">#{e.seq}</span>
              <span className="chain-type">{TYPE_LABEL[e.type] ?? e.type}</span>
              <span className="chain-hash mono">{typeof e.hash === "string" ? e.hash.slice(0, 12) + "…" : "—"}</span>
              <span className="chain-link" aria-hidden>⛓</span>
              <span className="chain-prev mono">
                {typeof e.prevHash !== "string"
                  ? "—"
                  : e.prevHash === "0".repeat(64)
                    ? "genesis"
                    : e.prevHash.slice(0, 12) + "…"}
              </span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
