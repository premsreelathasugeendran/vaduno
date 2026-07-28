"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { SESSION_COOKIE, mintSession } from "../../lib/auth";

export async function login(formData: FormData): Promise<void> {
  const passcode = String(formData.get("passcode") ?? "");
  const token = await mintSession(passcode);
  if (!token) {
    redirect("/login?error=1");
  }
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    // Secure everywhere except an explicit localhost demo (plain http).
    secure: !process.env.SWALE_ALLOW_DEFAULT_PASSCODE,
    path: "/",
    maxAge: 60 * 60 * 12,
  });
  redirect("/");
}
