"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { getApprovalStore } from "../lib/data";
import { SESSION_COOKIE, isValidSession } from "../lib/auth";

export async function resolveApproval(
  intentId: string,
  approved: boolean,
): Promise<{ ok: boolean }> {
  // Defense in depth: re-check the session inside the action, not just in
  // middleware. An unauthenticated caller can never resolve an approval.
  const jar = await cookies();
  const authed = await isValidSession(jar.get(SESSION_COOKIE)?.value);
  if (!authed) return { ok: false };

  if (typeof intentId !== "string" || intentId.length === 0 || intentId.length > 200) {
    return { ok: false };
  }

  // FileApprovalStore.resolve only acts on a CURRENTLY-pending id and never
  // overwrites an existing decision, so a crafted id cannot pre-approve.
  await getApprovalStore().resolve(intentId, {
    approved,
    approver: "operator",
    ...(approved ? {} : { note: "declined from dashboard" }),
  });
  revalidatePath("/");
  return { ok: true };
}
