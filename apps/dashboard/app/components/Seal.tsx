/**
 * The signet seal — a fine-line guilloché rosette (banknote engraving) with a
 * verdict glyph pressed into its center. Gold = approved-clean / verified,
 * red = firewall-blocked. This is the "tamper-evident stamp" signature motif.
 */
export function Seal({
  variant = "verified",
  size = 14,
}: {
  variant?: "verified" | "blocked" | "pending";
  size?: number;
}) {
  const color =
    variant === "blocked"
      ? "var(--critical)"
      : variant === "pending"
        ? "var(--caution)"
        : "var(--positive)";

  const petals = Array.from({ length: 10 }, (_, i) => (
    <ellipse
      key={i}
      cx="12"
      cy="12"
      rx="3.6"
      ry="9"
      stroke={color}
      strokeOpacity="0.3"
      strokeWidth="0.4"
      fill="none"
      transform={`rotate(${i * 18} 12 12)`}
    />
  ));

  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="seal" aria-hidden>
      <circle cx="12" cy="12" r="11.2" stroke={color} strokeOpacity="0.55" strokeWidth="1" />
      <circle cx="12" cy="12" r="9" stroke={color} strokeOpacity="0.35" strokeWidth="0.5" />
      {petals}
      {variant === "blocked" ? (
        <path d="M9 9l6 6M15 9l-6 6" stroke={color} strokeWidth="1.5" strokeLinecap="round" />
      ) : variant === "pending" ? (
        <circle cx="12" cy="12" r="2" fill={color} />
      ) : (
        <path
          d="M8.4 12.3l2.5 2.5 4.7-5.2"
          stroke={color}
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
      )}
    </svg>
  );
}
