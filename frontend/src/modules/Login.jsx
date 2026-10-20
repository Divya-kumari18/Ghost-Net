import { useState } from "react";
import { Btn, FormGroup } from "../components/UI.jsx";

export default function Login({ onLogin, error: externalError }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [localError, setLocalError] = useState("");
  const [loading,    setLoading]    = useState(false);

  const error = externalError || localError;

  const handle = async () => {
    if (loading || !username.trim() || !password) return;
    setLocalError("");
    setLoading(true);
    try {
      await onLogin({ username, password, role: username === "admin" ? "admin" : "analyst" });
    } catch (e) {
      setLocalError(e.message || "Login failed. Check your credentials.");
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
      background: "linear-gradient(140deg, #08111d 0%, #0b1726 55%, #102b31 100%)",
      padding: 20,
    }}>
      {/* Background decoration */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", top: -120, right: -120, width: 480, height: 480,
          borderRadius: "50%", background: "radial-gradient(circle, #d9e9ff66 0%, transparent 70%)",
        }} />
        <div style={{
          position: "absolute", bottom: -80, left: -80, width: 360, height: 360,
          borderRadius: "50%", background: "radial-gradient(circle, #ccfbf155 0%, transparent 70%)",
        }} />
      </div>

      <div style={{
        width: 420, background: "#10191e", borderRadius: 18,
        boxShadow: "0 28px 80px rgba(0,0,0,0.32), 0 0 0 1px rgba(126,231,220,0.08)",
        border: "1px solid #253239", overflow: "hidden", position: "relative", zIndex: 1,
        animation: "fadeUp 0.3s ease",
      }}>
        {/* Header */}
        <div style={{
          padding: "36px 36px 28px",
          background: "linear-gradient(145deg, #122b38 0%, #0d161b 100%)",
          borderBottom: "1px solid #253239", textAlign: "center",
        }}>
          <div style={{
            width: 64, height: 64, borderRadius: 18, margin: "0 auto 16px",
            background: "linear-gradient(135deg, #0f766e 0%, #06b6d4 100%)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 10px 28px rgba(6,182,212,0.24)", fontSize: 22,
            color: "#ffffff", fontWeight: 800, fontFamily: "var(--font-display)",
          }}>◌</div>
          <h1 style={{
            fontFamily: "var(--font-display)", fontSize: 24, fontWeight: 800,
            background: "linear-gradient(135deg, #f8fafc 0%, #73f5c5 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            letterSpacing: "-0.04em", marginBottom: 6,
          }}>GhostNet</h1>
          <p style={{ fontSize: 13, color: "#64748b", letterSpacing: "0.02em" }}>
            Integrated Threat Detection · Phase I
          </p>
          <div style={{ marginTop: 10, fontSize: 11, color: "#93a7b1", lineHeight: 1.45 }}>
            Capture · Kafka streaming · correlation · AI/ML · YARA · CVE/CWE · response
          </div>
        </div>

        {/* Form */}
        <div style={{ padding: "28px 36px 32px", background: "#10191e" }}>
          {error && (
            <div style={{
              background: "#fff1f2", border: "1.5px solid #fecdd3", color: "#be123c",
              borderRadius: "var(--r-md)", padding: "10px 14px", fontSize: 13,
              marginBottom: 18, display: "flex", alignItems: "center", gap: 8,
            }}>
              <span>⚠</span> {error}
            </div>
          )}

          <FormGroup label="Operator ID">
            <input
              value={username} onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handle()}
              placeholder="Your username" autoComplete="username" autoFocus
            />
          </FormGroup>

          <FormGroup label="Access Code">
            <input
              type="password" autoComplete="current-password" value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handle()}
              placeholder="••••••••••"
            />
          </FormGroup>

          <Btn
            variant="primary" onClick={handle} disabled={loading || !username.trim() || !password}
            style={{ width: "100%", justifyContent: "center", padding: "11px 0",
              fontSize: 14, marginTop: 8, borderRadius: "var(--r-md)",
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? "Authenticating…" : "Authenticate & Access ›"}
          </Btn>

          <div style={{
            marginTop: 20, padding: "12px 14px", background: "#121e24",
            borderRadius: "var(--r-md)", border: "1px solid #294252",
          }}>
            <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "#93a5ad", marginBottom: 4 }}>
              AUTHORIZED ACCESS
            </div>
            <div style={{ fontSize: 12, color: "#d2e0e4" }}>
              Sign in with your assigned operator account.
            </div>
            <div style={{ fontSize: 10, color: "#93a5ad", marginTop: 8, lineHeight: 1.5 }}>
              Ask your administrator for account access. First-time setup is documented in the project README.
            </div>
          </div>

          <div style={{
            marginTop: 14,
            fontSize: 10,
            color: "#82959e",
            textAlign: "center",
            fontFamily: "var(--font-mono)",
            borderTop: "1px solid #294252",
            paddingTop: 10,
          }}>
            GhostNet · JSSATE / VTU · {new Date().getFullYear()}
          </div>
        </div>
      </div>
    </div>
  );
}
