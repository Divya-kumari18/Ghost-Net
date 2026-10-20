import { useState } from "react";
import Icon from "./Icon.jsx";
import { severityConfig, statusConfig } from "../design-system.js";

// ── Badge ───────────────────────────────────────────────────────
export function Badge({ label, severity, status, size = "sm" }) {
  const cfg = severity
    ? severityConfig(severity)
    : status
    ? statusConfig(status)
    : { bg: "#1b2937", border: "#34434b", text: "#99aab2" };
  const pad = size === "xs" ? "2px 7px" : size === "lg" ? "5px 12px" : "3px 9px";
  const fs  = size === "xs" ? 10 : size === "lg" ? 13 : 11;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: pad, borderRadius: 99, fontSize: fs, fontWeight: 600,
      fontFamily: "var(--font-mono)", letterSpacing: "0.02em",
      background: cfg.bg, border: `1.5px solid ${cfg.border}`, color: cfg.text,
      whiteSpace: "nowrap",
    }}>
      {cfg.dot && (
        <span style={{
          width: 5, height: 5, borderRadius: "50%",
          background: cfg.dot, flexShrink: 0,
          animation: "pulseDot 2s ease-in-out infinite",
          display: "inline-block",
        }} />
      )}
      {label || severity || status}
    </span>
  );
}

// ── Button ──────────────────────────────────────────────────────
export function Btn({ children, onClick, variant = "ghost", size = "md", disabled, style = {} }) {
  const [hov, setHov] = useState(false);
  const base = {
    display: "inline-flex", alignItems: "center", gap: 6, cursor: disabled ? "not-allowed" : "pointer",
    fontFamily: "var(--font-body)", fontWeight: 600, borderRadius: "var(--r-md)",
    transition: "all 0.14s", border: "1.5px solid transparent", outline: "none",
    opacity: disabled ? 0.5 : 1, ...style,
  };
  const sizes = { xs:"6px 10px;font-size:11px", sm:"7px 12px;font-size:12px", md:"8px 16px;font-size:13px", lg:"10px 20px;font-size:14px" };
  const [p, fs] = (sizes[size] || sizes.md).split(";font-size:");
  const variants = {
    primary: { background: hov ? "#9afbd9" : "#73f5c5", color: "#09251b", borderColor: "#73f5c5" },
    danger:  { background: hov ? "#4c1d2b" : "#321927", color: "#fda4af", borderColor: "#713047" },
    success: { background: hov ? "#124e4a" : "#103b3b", color: "#6ee7d8", borderColor: "#1f6868" },
    ghost:   { background: hov ? "#183041" : "transparent", color: "#c3d4db", borderColor: "#34434b" },
    amber:   { background: hov ? "#4a3513" : "#302610", color: "#fcd34d", borderColor: "#70521d" },
    outline: { background: hov ? "#18372c" : "transparent", color: "#6ee7d8", borderColor: "#2a7776" },
  };
  return (
    <button
      style={{ ...base, padding: p, fontSize: fs, ...variants[variant] }}
      onClick={onClick} disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >{children}</button>
  );
}

// ── Card ────────────────────────────────────────────────────────
export function Card({ children, style = {}, padding = "20px", hover = false }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      style={{
        background: "var(--color-surface)", border: "1.5px solid var(--color-border)",
        borderRadius: "var(--r-lg)", padding,
        boxShadow: hov && hover ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "box-shadow 0.2s, border-color 0.2s",
        borderColor: hov && hover ? "#2a7776" : "var(--color-border)",
        ...style,
      }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >{children}</div>
  );
}

// ── StatCard ────────────────────────────────────────────────────
export function StatCard({ icon, label, value, sub, color = "#73f5c5", trend, onClick }) {
  return <div className="stat-card" onClick={onClick} style={{cursor:onClick?'pointer':undefined}}>
    <div className="stat-card-top"><span>{label}</span><span className="stat-icon" style={{color,background:color+'16'}}><Icon name={typeof icon==='string'&&['network','incidents','events','vuln','shield','malware','reports'].includes(icon)?icon:/packet|traffic|network/i.test(label)?'network':/alert|critical|incident/i.test(label)?'incidents':/event/i.test(label)?'events':/vulnerab|finding/i.test(label)?'vuln':'shield'} size={18}/></span></div>
    <div className="stat-value">{value}</div><div className="stat-bottom"><span>{sub}</span>{trend!=null&&<span style={{color}}> {trend>0?'↑':'↓'} {Math.abs(trend)}%</span>}</div>
  </div>;
}

export function ModuleHeader({ eyebrow = "GHOSTNET MODULE", title, subtitle, actions }) {
  return (
    <div className="module-header">
      <div>
        <div className="module-eyebrow"><span className="module-eyebrow-dot" />{eyebrow}</div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="module-header-actions">{actions}</div>}
    </div>
  );
}

// ── Panel ────────────────────────────────────────────────────────
export function Panel({ title, subtitle, actions, children, padding = "0", style = {} }) {
  return (
    <Card padding="0" style={style}>
      {(title || actions) && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "14px 18px", borderBottom: "1.5px solid var(--color-border)",
          background: "#121e24",
        }}>
          <div>
            <div style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: 13,
              color: "var(--color-text-primary)", letterSpacing: "-0.01em" }}>{title}</div>
            {subtitle && <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 1 }}>{subtitle}</div>}
          </div>
          {actions && <div style={{ display: "flex", gap: 8, alignItems: "center" }}>{actions}</div>}
        </div>
      )}
      <div style={{ padding }}>{children}</div>
    </Card>
  );
}

// ── Data Table ───────────────────────────────────────────────────
export function DataTable({ columns, rows, emptyText = "No data found" }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ background: "#121e24", borderBottom: "1.5px solid var(--color-border)" }}>
            {columns.map((col, i) => (
              <th key={i} style={{
                textAlign: "left", padding: "10px 14px",
                fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
                color: "var(--color-text-tertiary)", letterSpacing: "0.06em",
                textTransform: "uppercase", whiteSpace: "nowrap",
              }}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} style={{ textAlign: "center", padding: "40px 16px",
                color: "var(--color-text-tertiary)", fontSize: 13 }}>{emptyText}</td>
            </tr>
          ) : (
            rows.map((row, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #223039", transition: "background 0.1s" }}
                onMouseEnter={e => e.currentTarget.style.background = "#19282e"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                {columns.map((col, j) => (
                  <td key={j} style={{ padding: "10px 14px", verticalAlign: "middle",
                    fontFamily: col.mono ? "var(--font-mono)" : "var(--font-body)",
                    fontSize: col.mono ? 11 : 13, color: col.dim ? "var(--color-text-secondary)" : "var(--color-text-primary)",
                    maxWidth: col.maxWidth || "none", overflow: "hidden",
                    textOverflow: "ellipsis", whiteSpace: col.wrap ? "normal" : "nowrap",
                  }}>
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Modal ────────────────────────────────────────────────────────
export function Modal({ open, onClose, title, children, footer, width = 520 }) {
  if (!open) return null;
  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 999,
      background: "rgba(15,23,42,0.45)", backdropFilter: "blur(6px)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20,
    }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{
        background: "var(--color-surface)", borderRadius: "var(--r-xl)",
        width, maxWidth: "95vw", maxHeight: "88vh", overflow: "auto",
        boxShadow: "0 24px 48px rgba(15,23,42,0.18), 0 8px 16px rgba(15,23,42,0.1)",
        border: "1.5px solid var(--color-border)", animation: "fadeUp 0.2s ease",
      }}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "18px 22px", borderBottom: "1.5px solid var(--color-border)",
          background: "#121e24",
        }}>
          <h3 style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: 15,
            color: "var(--color-text-primary)", letterSpacing: "-0.02em" }}>{title}</h3>
          <button onClick={onClose} style={{
            background: "none", border: "none", fontSize: 20, cursor: "pointer",
            color: "var(--color-text-tertiary)", lineHeight: 1, padding: "2px 6px",
            borderRadius: "var(--r-sm)", transition: "all 0.12s",
          }}
            onMouseEnter={e => { e.target.style.background = "#fee2e2"; e.target.style.color = "#e11d48"; }}
            onMouseLeave={e => { e.target.style.background = "none"; e.target.style.color = "var(--color-text-tertiary)"; }}
          >×</button>
        </div>
        <div style={{ padding: "22px" }}>{children}</div>
        {footer && (
          <div style={{ padding: "14px 22px", borderTop: "1.5px solid var(--color-border)",
            display: "flex", justifyContent: "flex-end", gap: 10, background: "#121e24",
          }}>{footer}</div>
        )}
      </div>
    </div>
  );
}

// ── Form Group ───────────────────────────────────────────────────
export function FormGroup({ label, children, hint }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: "block", fontFamily: "var(--font-mono)", fontSize: 11,
        fontWeight: 600, color: "var(--color-text-secondary)", letterSpacing: "0.05em",
        textTransform: "uppercase", marginBottom: 6 }}>{label}</label>
      {children}
      {hint && <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

// ── Grid ────────────────────────────────────────────────────────
export function Grid({ cols = 2, gap = 16, children, style = {} }) {
  return (
    <div className="responsive-grid" style={{
      display: "grid",
      "--grid-cols": cols,
      gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`,
      gap, ...style,
    }}>{children}</div>
  );
}

// ── Chip / Tag ───────────────────────────────────────────────────
export function Chip({ label, color = "#2d6bff" }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "2px 8px",
      borderRadius: 99, fontSize: 11, fontWeight: 600,
      fontFamily: "var(--font-mono)", background: color + "15",
      color, border: `1px solid ${color}30`, whiteSpace: "nowrap",
    }}>{label}</span>
  );
}

// ── IP Pill ──────────────────────────────────────────────────────
export function IPPill({ ip }) {
  return (
    <span style={{
      fontFamily: "var(--font-mono)", fontSize: 11,
      background: "#18372c", border: "1px solid #1f6868",
      color: "#73f5c5", padding: "2px 8px", borderRadius: "var(--r-sm)",
      whiteSpace: "nowrap",
    }}>{ip}</span>
  );
}

// ── Live Feed Item ───────────────────────────────────────────────
export function FeedItem({ time, severity, badgeLabel, message, type }) {
  const sev = severity?.toLowerCase() || "low";
  const dotColors = { critical: "#f43f5e", high: "#f59e0b", medium: "#8b5cf6", low: "#10b981", info: "#0ea5e9" };
  return (
    <div style={{
      display: "flex", alignItems: "flex-start", gap: 10,
      padding: "7px 12px", borderBottom: "1px solid #223039",
      animation: "slideIn 0.2s ease",
    }}>
      <span style={{
        fontFamily: "var(--font-mono)", fontSize: 10,
        color: "var(--color-text-tertiary)", minWidth: 60, marginTop: 1,
        flexShrink: 0,
      }}>{time}</span>
      <span style={{
        width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
        background: dotColors[sev] || "#94a3b8", marginTop: 5,
      }} />
      <Badge label={badgeLabel} status={type === "badge" ? badgeLabel.toLowerCase() : undefined}
        severity={type === "sev" ? severity : undefined} size="xs" />
      <span style={{ fontSize: 12, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>{message}</span>
    </div>
  );
}

// ── Toggle ───────────────────────────────────────────────────────
export function Toggle({ value, onChange }) {
  return (
    <div
      onClick={() => onChange(!value)}
      style={{
        width: 38, height: 22, borderRadius: 99, cursor: "pointer",
        background: value ? "#0f766e" : "#1b2937",
        position: "relative", transition: "background 0.2s", flexShrink: 0,
        border: `1.5px solid ${value ? "#73f5c5" : "#34434b"}`,
      }}
    >
      <div style={{
        width: 16, height: 16, borderRadius: "50%", background: "#edf4f2",
        position: "absolute", top: "50%", transform: "translateY(-50%)",
        left: value ? 18 : 2, transition: "left 0.2s",
        boxShadow: "0 1px 3px rgba(0,0,0,0.2)",
      }} />
    </div>
  );
}

// ── Progress Bar ─────────────────────────────────────────────────
export function ProgressBar({ value, max = 100, color = "#2d6bff", height = 6 }) {
  const pct = Math.min(100, max > 0 ? (value / max) * 100 : 0);
  return (
    <div style={{ height, background: "#1b2937", borderRadius: 99, overflow: "hidden" }}>
      <div style={{
        height: "100%", width: `${pct}%`, background: color,
        borderRadius: 99, transition: "width 0.5s ease",
      }} />
    </div>
  );
}

// ── Empty State ──────────────────────────────────────────────────
export function EmptyState({ icon = "📭", title, sub }) {
  return (
    <div style={{ textAlign: "center", padding: "40px 20px", color: "var(--color-text-tertiary)" }}>
      <div style={{ fontSize: 32, marginBottom: 10 }}>{icon}</div>
      <div style={{ fontWeight: 600, fontSize: 14, color: "var(--color-text-secondary)", marginBottom: 4 }}>{title}</div>
      {sub && <div style={{ fontSize: 12 }}>{sub}</div>}
    </div>
  );
}

// ── Live Pulse ───────────────────────────────────────────────────
export function LivePulse({ active = true, label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{
        width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
        background: active ? "#10b981" : "#94a3b8",
        animation: active ? "pulseDot 2s ease-in-out infinite" : "none",
        display: "inline-block",
      }} />
      {label && <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", fontWeight: 600,
        color: active ? "#047857" : "var(--color-text-tertiary)" }}>{label}</span>}
    </div>
  );
}

// ── Section Divider ──────────────────────────────────────────────
export function Divider({ style = {} }) {
  return <div style={{ height: "1.5px", background: "var(--color-border)", ...style }} />;
}

// ── Tooltip wrapper (simple title fallback) ───────────────────────
export function Tooltip({ tip, children }) {
  return <span title={tip}>{children}</span>;
}

// ── Select ───────────────────────────────────────────────────────
export function Select({ value, onChange, options, style = {} }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      style={{ width: "auto", padding: "6px 10px", fontSize: 12, ...style }}>
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

// ── Breadcrumb ───────────────────────────────────────────────────
export function Breadcrumb({ items }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12,
      fontFamily: "var(--font-mono)", color: "var(--color-text-tertiary)" }}>
      {items.map((item, i) => (
        <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {i > 0 && <span>/</span>}
          <span style={{ color: i === items.length - 1 ? "var(--color-text-secondary)" : "var(--color-text-tertiary)" }}>
            {item}
          </span>
        </span>
      ))}
    </div>
  );
}
