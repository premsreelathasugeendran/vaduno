import type { FreezeState, FreezeStore, UnfreezeResult } from "@vaduno/revocation";
import { toSafeInt, type PgPool } from "./pg.js";

interface FreezeRow {
  epoch: string | number;
  frozen: boolean;
  reason: string | null;
  frozen_by: string | null;
  frozen_at: string | null;
}

function toState(row: FreezeRow): FreezeState {
  return {
    epoch: toSafeInt(row.epoch, "epoch"),
    frozen: row.frozen,
    reason: row.reason,
    by: row.frozen_by,
    at: row.frozen_at,
  };
}

const UNFROZEN: FreezeState = { epoch: 0, frozen: false, reason: null, by: null, at: null };

/**
 * Postgres-backed FreezeStore — the kill switch that binds across INSTANCES.
 *
 * One global row (`vaduno_freeze`, id constrained to 1). No advisory lock and
 * no transaction, on purpose: every mutation is a SINGLE statement, and the
 * compare-and-set IS the `WHERE epoch = $expected` clause — Postgres evaluates
 * the compare and applies the update atomically, so a stale unfreeze racing a
 * fresh freeze simply matches zero rows and changes nothing. This store is far
 * simpler than `PostgresRevocationStore` because none of the registry's hard
 * parts apply: no index allocation, no MAX+1 under a lock, no bitstring.
 *
 * Fail-closed is the CALLER's contract to inherit, and it comes free: any
 * connection failure here throws, `createFreezeCheck` (and the guard's own
 * revocationCheck wrapper) turn the throw into a denial. Stated loudly, as the
 * store interface requires: an unreachable database DENIES EVERY PAYMENT on
 * every guard wired to this store — a total stop, in the recoverable
 * direction. See freeze-store.ts in @vaduno/revocation for the posture and the
 * epoch-fencing rationale.
 *
 * Honest evidence status: like every store in this package, its conformance
 * run is env-gated on `VADUNO_TEST_POSTGRES_URL` and SKIPS on any machine
 * without a live Postgres — including the machine it was written on. Check the
 * CI postgres job for the commit you install.
 */
export class PostgresFreezeStore implements FreezeStore {
  constructor(
    private readonly pool: PgPool,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async freeze(reason: string, by: string | null = null): Promise<FreezeState> {
    const at = this.now().toISOString();
    // Upsert so the very first freeze works on an empty table (a missing row
    // means "never frozen", epoch 0). The reason COALESCE preserves a live
    // reason through an empty overwrite — freeze('') from a sloppy monitor
    // must not blank "credentials leaked" out of the operational evidence —
    // and 'frozen' is the last-resort default, mirroring MemoryFreezeStore.
    const res = await this.pool.query<FreezeRow>(
      `INSERT INTO vaduno_freeze AS f (id, epoch, frozen, reason, frozen_by, frozen_at)
       VALUES (1, 1, TRUE, COALESCE(NULLIF(btrim($1), ''), 'frozen'), $2, $3)
       ON CONFLICT (id) DO UPDATE SET
         epoch     = f.epoch + 1,
         frozen    = TRUE,
         reason    = COALESCE(NULLIF(btrim($1), ''), f.reason, 'frozen'),
         frozen_by = $2,
         frozen_at = $3
       RETURNING epoch, frozen, reason, frozen_by, frozen_at`,
      [reason, by, at],
    );
    const row = res.rows[0];
    // A freeze that cannot report the state it wrote is an outage, not a
    // success. Throw (= the caller denies) rather than fabricate a snapshot.
    if (!row) {
      throw new Error("@vaduno/postgres: freeze() returned no row — freeze state unknown");
    }
    return toState(row);
  }

  async unfreeze(expectedEpoch: number): Promise<UnfreezeResult> {
    // THE compare-and-set: `WHERE epoch = $expected` matches either exactly
    // the state the operator looked at, or nothing. Zero rows = refused,
    // nothing changed.
    const updated = await this.pool.query(
      `UPDATE vaduno_freeze
       SET epoch = epoch + 1, frozen = FALSE, reason = NULL, frozen_by = NULL, frozen_at = NULL
       WHERE id = 1 AND epoch = $1`,
      [expectedEpoch],
    );
    if ((updated.rowCount ?? 0) === 1) return { ok: true };
    if (expectedEpoch === 0) {
      // No row yet is implicitly epoch 0 (never frozen); an unfreeze fenced
      // on 0 is still a valid CAS. The conditional insert keeps it atomic:
      // if a concurrent freeze created the row first, ON CONFLICT makes this
      // a no-op and the fence is honestly stale.
      const inserted = await this.pool.query(
        `INSERT INTO vaduno_freeze (id, epoch, frozen, reason, frozen_by, frozen_at)
         VALUES (1, 1, FALSE, NULL, NULL, NULL)
         ON CONFLICT (id) DO NOTHING`,
      );
      if ((inserted.rowCount ?? 0) === 1) return { ok: true };
    }
    return { ok: false, code: "STALE_EPOCH" };
  }

  async read(): Promise<FreezeState> {
    const res = await this.pool.query<FreezeRow>(
      "SELECT epoch, frozen, reason, frozen_by, frozen_at FROM vaduno_freeze WHERE id = 1",
    );
    const row = res.rows[0];
    // A missing ROW is the initial "never frozen" state — the table answered.
    // A missing TABLE or a dead connection throws, which the caller must turn
    // into a denial (unreachable is never "not frozen").
    if (!row) return { ...UNFROZEN };
    return toState(row);
  }
}
