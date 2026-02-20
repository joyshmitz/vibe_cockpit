"use client";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#65a30d",
  ok: "#16a34a",
  online: "#16a34a",
  offline: "#6b7280",
};

interface StatusBadgeProps {
  status: string;
  label?: string;
}

export function StatusBadge({ status, label }: StatusBadgeProps) {
  const color = SEVERITY_COLORS[status.toLowerCase()] || "#6b7280";
  const text = label || status;
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: "4px",
        backgroundColor: color,
        color: "#fff",
        fontSize: "12px",
        fontWeight: 600,
        textTransform: "uppercase",
      }}
    >
      {text}
    </span>
  );
}
