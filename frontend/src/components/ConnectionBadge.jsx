import { useState } from "react";

export function ConnectionBadge({ wsStatus, mlOnline, captureRunning }) {
  const [open, setOpen] = useState(false);

  const wsOk   = wsStatus === "connected";
  const wsIcon = { connected:"🟢", connecting:"🟡", disconnected:"🔴", failed:"🔴" }[wsStatus] || "🔴";

  return (
    <div style={{ position:"relative" }}>
      <button
        onClick={() => setOpen(p => !p)}
        style={{
          display:"flex", alignItems:"center", gap:7, padding:"4px 11px",
          borderRadius:99, cursor:"pointer", border:"1.5px solid",
          fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
          background: wsOk ? "#103b3b" : "#321927",
          borderColor: wsOk ? "#1f6868" : "#713047",
          color: wsOk ? "#6ee7d8" : "#fda4af",
          transition:"all 0.15s",
        }}
      >
        <span style={{
          width:6, height:6, borderRadius:"50%",
          background: wsOk ? "#10b981" : "#f43f5e",
          display:"inline-block",
          animation: wsOk ? "pulseDot 2s ease-in-out infinite" : "none",
        }}/>
        {wsOk ? "LIVE" : wsStatus.toUpperCase()}
      </button>

      {open && (
        <div style={{
          position:"absolute", top:"calc(100% + 8px)", right:0, zIndex:300,
          background:"#10191e", border:"1.5px solid var(--color-border)",
          borderRadius:"var(--r-lg)", boxShadow:"var(--shadow-lg)",
          width:260, animation:"fadeUp .18s ease",
          padding:0, overflow:"hidden",
        }}>
          <div style={{ padding:"12px 16px", borderBottom:"1.5px solid var(--color-border)", background:"#121e24" }}>
            <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13, color:"var(--color-text-primary)" }}>
              Connection Status
            </div>
          </div>
          <div style={{ padding:"12px 16px" }}>
            {[
              { label:"WebSocket",  value: wsStatus,              ok: wsOk,           hint:"STOMP / SockJS" },
              { label:"ML Service", value: mlOnline ? "Online" : "Offline", ok: mlOnline, hint:"localhost:5000" },
              { label:"Capture",    value: captureRunning ? "Active" : "Idle", ok: captureRunning, hint:"Npcap / Pcap4J" },
            ].map(row => (
              <div key={row.label} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"7px 0", borderBottom:"1px solid #223039",
              }}>
                <div>
                  <div style={{ fontSize:12, fontWeight:600, color:"var(--color-text-primary)" }}>{row.label}</div>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)" }}>{row.hint}</div>
                </div>
                <span style={{
                  fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
                  padding:"2px 8px", borderRadius:99,
                  background: row.ok ? "#103b3b" : "#1b2937",
                  color:       row.ok ? "#6ee7d8" : "#93a5ad",
                  border:`1.5px solid ${row.ok ? "#1f6868" : "#34434b"}`,
                  textTransform:"uppercase",
                }}>{row.value}</span>
              </div>
            ))}
          </div>
          <button onClick={() => setOpen(false)} style={{
            width:"100%", padding:"9px 0", background:"none", border:"none",
            borderTop:"1.5px solid var(--color-border)", cursor:"pointer",
            fontFamily:"var(--font-mono)", fontSize:11, color:"var(--color-text-tertiary)",
          }}>Close</button>
        </div>
      )}

      {/* Click-outside close */}
      {open && (
        <div style={{ position:"fixed", inset:0, zIndex:299 }} onClick={() => setOpen(false)} />
      )}
    </div>
  );
}
