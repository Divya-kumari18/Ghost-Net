import { useEffect } from "react";

const TOAST_STYLES = {
  success: { bg:"#103b3b", border:"#1f6868", text:"#6ee7d8", icon:"✓" },
  error:   { bg:"#321927", border:"#713047", text:"#fda4af", icon:"✕" },
  warning: { bg:"#302610", border:"#70521d", text:"#fcd34d", icon:"⚠" },
  info:    { bg:"#18372c", border:"#1f6868", text:"#73f5c5", icon:"ℹ" },
  critical:{ bg:"#321927", border:"#713047", text:"#fda4af", icon:"🚨" },
};

function ToastItem({ toast, onRemove }) {
  useEffect(() => {
    const t = setTimeout(() => onRemove(toast.id), toast.type === "critical" ? 6000 : 3500);
    return () => clearTimeout(t);
  }, [toast.id]);

  const s = TOAST_STYLES[toast.type] || TOAST_STYLES.info;

  return (
    <div style={{
      display:"flex", alignItems:"flex-start", gap:10,
      background: s.bg, border:`1.5px solid ${s.border}`,
      borderRadius:"var(--r-lg)", padding:"12px 14px",
      maxWidth:340, boxShadow:"var(--shadow-lg)",
      animation:"fadeUp 0.25s ease",
      fontFamily:"var(--font-body)",
    }}>
      <span style={{ fontSize:14, flexShrink:0, marginTop:1 }}>{s.icon}</span>
      <span style={{ fontSize:13, color:s.text, lineHeight:1.5, flex:1 }}>{toast.message}</span>
      <button onClick={() => onRemove(toast.id)} style={{
        background:"none", border:"none", cursor:"pointer",
        color:s.text, opacity:0.6, fontSize:16, lineHeight:1,
        padding:0, flexShrink:0,
      }}>×</button>
    </div>
  );
}

export default function ToastContainer({ toasts, onRemove }) {
  return (
    <div style={{
      position:"fixed", top:70, right:20, zIndex:9999,
      display:"flex", flexDirection:"column", gap:8,
      pointerEvents:"none",
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{ pointerEvents:"all" }}>
          <ToastItem toast={t} onRemove={onRemove} />
        </div>
      ))}
    </div>
  );
}
