/**
 * Minimal structural types for a `pg` Pool/Client.
 *
 * Declared here rather than importing from `pg` or `@types/pg` so this package
 * has no hard dependency on either: `pg` is an optional peer, you supply the
 * pool, and anything shaped like one works (pg.Pool, a pooled proxy, pgbouncer
 * client, a test double).
 */
export interface PgQueryResult<R = Record<string, unknown>> {
  rows: R[];
  rowCount: number | null;
}

export interface PgClient {
  query<R = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<R>>;
  release(err?: boolean): void;
}

export interface PgPool {
  connect(): Promise<PgClient>;
  query<R = Record<string, unknown>>(
    text: string,
    values?: unknown[],
  ): Promise<PgQueryResult<R>>;
}

/**
 * Run `fn` inside a transaction on a dedicated connection, rolling back on any
 * throw and always returning the connection to the pool.
 *
 * A dedicated connection is not optional here: `pg_advisory_xact_lock` is
 * scoped to a transaction on one backend, so running the lock and the work on
 * different pooled connections would take a lock that guards nothing.
 */
export async function inTransaction<T>(
  pool: PgPool,
  fn: (client: PgClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    failed = true;
    try {
      await client.query("ROLLBACK");
    } catch {
      /* connection is already unusable; releasing with an error discards it */
    }
    throw err;
  } finally {
    client.release(failed);
  }
}

/**
 * BIGINT columns come back as strings from node-postgres (a 64-bit integer
 * does not fit a JS number in general). Every amount in Vaduno is minor units
 * and must be a safe integer, so parse strictly and refuse anything else
 * rather than letting a silent NaN through a budget check.
 */
export function toSafeInt(value: unknown, field: string): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(n)) {
    throw new Error(
      `@vaduno/postgres: ${field} is not a safe integer (got ${String(value)})`,
    );
  }
  return n;
}
