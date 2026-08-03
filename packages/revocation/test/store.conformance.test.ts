/**
 * Runs the shared RevocationStore conformance suite against the stores that
 * ship here. PostgresRevocationStore is exercised from @vaduno/postgres, which
 * depends on this package — see packages/postgres/test.
 */
import { MemoryRevocationStore } from "../src/store.js";
import { runRevocationStoreConformance } from "./revocation-store-conformance.js";

// One handle: correct within a process, and the cross-process cases skip
// themselves rather than claiming a guarantee it never made.
runRevocationStoreConformance({
  name: "MemoryRevocationStore",
  async create() {
    return { stores: [new MemoryRevocationStore()] };
  },
});
