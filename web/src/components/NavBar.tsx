"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Overview" },
  { href: "/machines", label: "Machines" },
  { href: "/alerts", label: "Alerts" },
  { href: "/guardian", label: "Guardian" },
  { href: "/oracle", label: "Oracle" },
  { href: "/accounts", label: "Accounts" },
  { href: "/sessions", label: "Sessions" },
  { href: "/settings", label: "Settings" },
];

export function NavBar() {
  const pathname = usePathname();
  return (
    <nav
      style={{
        display: "flex",
        gap: "4px",
        padding: "8px 16px",
        backgroundColor: "#111827",
        borderBottom: "1px solid #374151",
      }}
    >
      <span
        style={{
          fontWeight: 700,
          color: "#60a5fa",
          marginRight: "16px",
          fontSize: "14px",
          lineHeight: "32px",
        }}
      >
        vc
      </span>
      {NAV_ITEMS.map(({ href, label }) => {
        const active = pathname === href;
        return (
          <Link
            key={href}
            href={href}
            style={{
              padding: "4px 12px",
              borderRadius: "4px",
              fontSize: "13px",
              color: active ? "#fff" : "#9ca3af",
              backgroundColor: active ? "#1f2937" : "transparent",
              textDecoration: "none",
              lineHeight: "24px",
            }}
          >
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
