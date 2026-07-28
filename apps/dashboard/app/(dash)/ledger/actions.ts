"use server";

import { cookies } from "next/headers";
import type { LedgerEntry } from "@swale/guard";
import { loadIntentTrail } from "../../../lib/data";
import { SESSION_COOKIE, isValidSession } from "../../../lib/auth";

export async function fetchTrail(intentId: string): Promise<LedgerEntry[]> {
  const jar = await cookies();
  if (!(await isValidSession(jar.get(SESSION_COOKIE)?.value))) return [];
  if (typeof intentId !== "string" || intentId.length === 0 || intentId.length > 200) return [];
  return loadIntentTrail(intentId);
}
