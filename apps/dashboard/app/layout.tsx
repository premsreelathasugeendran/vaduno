import "./fonts.css";
import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Paygent — the vault terminal",
  description: "Spend firewall & tamper-evident flight recorder for AI-agent payments.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
