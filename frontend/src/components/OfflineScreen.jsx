import { useState, useEffect } from "react";
import { checkHealth, checkMlHealth, API_BASE, ML_BASE } from "../api/client.js";

export function OfflineScreen({ error, onRetry, retrying }) {
  const [backendStatus, setBackendStatus] = useState("checking");
  const [mlStatus,      setMlStatus]      = useState("checking");

  useEffect(() => {
    const probe = async () => {
      setBackendStatus("checking");
      setMlStatus("checking");

      checkHealth()
        .then(()  => setBackendStatus("online"))
        .catch(() => setBackendStatus("offline"));

      checkMlHealth()
        .then(()  => setMlStatus("online"))
        .catch(() => setMlStatus("offline"));
    };

    probe();
    const t = setInterval(probe, 5000);
    return () => clearInterval(t);
  }, []);

  const dot = (status) => {
    const cfg = {
      online:   { bg:"#10b981", shadow:"0 0 6px #10b98166", label:"Online"   },
      offline:  { bg:"#f43f5e", shadow:"0 0 6px #f43f5e66", label:"Offline"  },
      checking: { bg:"#f59e0b", shadow:"0 0 6px #f59e0b66", label:"Checking…"},
    }[status] || {};
    return (
      <span style={{ display:"flex", alignItems:"center", gap:7 }}>
        <span style={{
          width:8, height:8, borderRadius:"50%",
          background:cfg.bg, boxShadow:cfg.shadow,
          display:"inline-block",
          animation: status === "checking" ? "pulseDot 1.2s ease-in-out infinite" : "none",
        }}/>
        <span style={{ fontSize:12, fontFamily:"var(--font-mono)", fontWeight:700, color:cfg.bg }}>
          {cfg.label}
        </span>
      </span>
    );
  };

  return (
    <div style={{
      minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center",
      background:"linear-gradient(140deg, #08111d 0%, #0b1726 55%, #102b31 100%)",
      padding:24, fontFamily:"var(--font-body)",
    }}>
      {/* Subtle bg circles */}
      <div style={{ position:"fixed", inset:0, pointerEvents:"none", overflow:"hidden" }}>
        <div style={{ position:"absolute", top:-100, right:-100, width:400, height:400, borderRadius:"50%", background:"radial-gradient(circle, #fecdd333 0%, transparent 70%)" }}/>
        <div style={{ position:"absolute", bottom:-80, left:-80, width:360, height:360, borderRadius:"50%", background:"radial-gradient(circle, #bae6fd33 0%, transparent 70%)" }}/>
      </div>

      <div style={{
        width:480, background:"#10191e", borderRadius:18,
        boxShadow:"0 28px 80px rgba(0,0,0,0.32), 0 0 0 1px rgba(126,231,220,0.08)",
        border:"1px solid #253239", overflow:"hidden", position:"relative", zIndex:1,
        animation:"fadeUp 0.3s ease",
      }}>
        {/* Header */}
        <div style={{
          padding:"28px 32px 22px",
          background:"linear-gradient(145deg, #122b38 0%, #0d161b 100%)",
          borderBottom:"1px solid #253239",
          textAlign:"center",
        }}>
          <div style={{
            width:64, height:64, borderRadius:18, margin:"0 auto 14px",
            background:"linear-gradient(135deg, #f43f5e 0%, #e11d48 100%)",
            display:"flex", alignItems:"center", justifyContent:"center",
            boxShadow:"0 8px 24px rgba(244,63,94,0.3)", fontSize:28,
          }}>⚠</div>
          <h1 style={{
            fontFamily:"var(--font-display)", fontSize:20, fontWeight:800,
            color:"#edf4f2", letterSpacing:"-.02em", marginBottom:6,
          }}>Backend Unreachable</h1>
          <p style={{ fontSize:13, color:"#99aab2", lineHeight:1.6 }}>
            GhostNet requires the Java backend to be running.<br/>
            The app cannot function in offline mode.
          </p>
        </div>

        {/* Service status */}
        <div style={{ padding:"20px 28px" }}>
          <div style={{
            fontSize:10, fontFamily:"var(--font-mono)", color:"#94a3b8",
            textTransform:"uppercase", letterSpacing:".1em", marginBottom:12, fontWeight:600,
          }}>Service Status</div>

          {[
            { label:"Backend API",  hint:API_BASE + "/actuator/health", status:backendStatus, required:true  },
            { label:"ML Service",   hint:ML_BASE  + "/api/health",      status:mlStatus,      required:false },
          ].map(svc => (
            <div key={svc.label} style={{
              display:"flex", alignItems:"center", justifyContent:"space-between",
              padding:"11px 14px", marginBottom:8,
              background: svc.status === "online" ? "#103b3b" : svc.status === "offline" ? "#321927" : "#302610",
              borderRadius:"var(--r-md)",
              border:`1.5px solid ${svc.status === "online" ? "#1f6868" : svc.status === "offline" ? "#713047" : "#70521d"}`,
            }}>
              <div>
                <div style={{ fontWeight:700, fontSize:13, color:"#dce6e8", display:"flex", alignItems:"center", gap:8 }}>
                  {svc.label}
                  {!svc.required && (
                    <span style={{ fontSize:9, fontFamily:"var(--font-mono)", background:"#18372c", color:"#73f5c5", border:"1px solid #1f6868", padding:"1px 6px", borderRadius:99 }}>OPTIONAL</span>
                  )}
                </div>
                <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", marginTop:2 }}>{svc.hint}</div>
              </div>
              {dot(svc.status)}
            </div>
          ))}

          {/* Error detail */}
          {error && (
            <div style={{
              marginTop:4, padding:"10px 14px",
              background:"#321927", border:"1.5px solid #713047",
              borderRadius:"var(--r-md)", fontSize:12, color:"#be123c",
              fontFamily:"var(--font-mono)", lineHeight:1.6, wordBreak:"break-word",
            }}>
              {error}
            </div>
          )}

          {/* Setup instructions */}
          <div style={{
            marginTop:14, padding:"14px 16px",
            background:"#121e24", border:"1.5px solid #253239",
            borderRadius:"var(--r-lg)",
          }}>
            <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"#94a3b8", textTransform:"uppercase", letterSpacing:".08em", marginBottom:10, fontWeight:600 }}>
              How to start the backend
            </div>
            {[
              { n:1, text:"Install Npcap from npcap.com (WinPcap compat mode ✓)" },
              { n:2, text:"Start PostgreSQL and ensure the configured database exists" },
              { n:3, text:"Run start.bat as Administrator" },
              { n:4, text:"Wait for Spring Boot to show: 'GhostNet STARTED'" },
            ].map(s => (
              <div key={s.n} style={{ display:"flex", gap:10, marginBottom:8 }}>
                <span style={{
                  width:20, height:20, borderRadius:"50%", flexShrink:0,
                  background:"#0f766e", color:"#effffc",
                  display:"flex", alignItems:"center", justifyContent:"center",
                  fontSize:10, fontWeight:800, fontFamily:"var(--font-display)",
                }}>{s.n}</span>
                <span style={{ fontSize:12, color:"#99aab2", lineHeight:1.5 }}>{s.text}</span>
              </div>
            ))}
          </div>

          {/* Retry button */}
          <button
            onClick={onRetry}
            disabled={retrying}
            style={{
              width:"100%", marginTop:16, padding:"12px 0",
              background: retrying ? "#e2e8f0" : "linear-gradient(135deg, #2d6bff 0%, #1a52e0 100%)",
              color: retrying ? "#94a3b8" : "#fff",
              border:"none", borderRadius:"var(--r-md)", cursor: retrying ? "not-allowed" : "pointer",
              fontFamily:"var(--font-body)", fontWeight:700, fontSize:14,
              boxShadow: retrying ? "none" : "0 4px 12px rgba(45,107,255,0.3)",
              transition:"all 0.15s",
              display:"flex", alignItems:"center", justifyContent:"center", gap:8,
            }}
          >
            {retrying ? (
              <><span style={{ animation:"spin 1s linear infinite", display:"inline-block" }}>⟳</span> Connecting…</>
            ) : (
              "⟳ Retry Connection"
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
