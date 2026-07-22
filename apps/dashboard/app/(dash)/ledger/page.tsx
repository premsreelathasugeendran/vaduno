import { loadRawLedger } from "../../../lib/data";
import { LedgerExplorer } from "../../components/LedgerExplorer";

export const dynamic = "force-dynamic";

export default async function LedgerPage() {
  const { entries } = await loadRawLedger(200);
  const nowMs = Date.now();

  return (
    <>
      <div className="page-lead reveal s1">
        <h1 className="lead-title">Ledger</h1>
        <p className="lead-sub">The full flight recorder. Click any entry to trace its intent and export an evidence packet.</p>
      </div>
      <LedgerExplorer entries={entries} nowMs={nowMs} />
    </>
  );
}
