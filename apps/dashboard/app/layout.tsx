import "./fonts.css";
import "./globals.css";
import "./pages.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Vaduno — the vault terminal",
  description: "Spend firewall & tamper-evident flight recorder for AI-agent payments.",
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#0a0d14",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
