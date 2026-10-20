// ═══════════════════════════════════════════════════════════════
//  GhostNet Root App
//  Real connections only — no simulation fallback.
//  • Login → JWT → WebSocket → auto-start capture
//  • Offline backend → OfflineScreen (hard block)
//  • ML anomaly scores on every captured packet
// ═══════════════════════════════════════════════════════════════

import { useState, useCallback, useEffect, useRef, lazy, Suspense } from "react";
import { globalStyles } from "./design-system.js";
import { useRealtime } from "./hooks/useRealtime.js";

import LoginModule      from "./modules/Login.jsx";

const Users = lazy(() => import("./modules/Users.jsx"));
const Dashboard = lazy(() => import("./modules/Dashboard.jsx"));
const Network = lazy(() => import("./modules/Network.jsx"));
const WindowsEvents = lazy(() => import("./modules/WindowsEvents.jsx"));
const Malware = lazy(() => import("./modules/Malware.jsx"));
const Incidents = lazy(() => import("./modules/Incidents.jsx"));
const Vulnerability = lazy(() => import("./modules/Vulnerability.jsx"));
const Honeypot = lazy(() => import("./modules/Honeypot.jsx"));
const Reports = lazy(() => import("./modules/Reports.jsx"));
const Settings = lazy(() => import("./modules/Settings.jsx"));

import Sidebar             from "./components/Sidebar.jsx";
import Header              from "./components/Header.jsx";
import AppFooter           from "./components/AppFooter.jsx";
import ToastContainer      from "./components/Toast.jsx";
import { OfflineScreen } from "./components/OfflineScreen.jsx";
import { ConnectionBadge } from "./components/ConnectionBadge.jsx";

let _toastId = 0;

export default function App() {
  const [page,   setPage]   = useState("dashboard");
  const mainRef = useRef(null);
  useEffect(() => { mainRef.current?.scrollTo({top:0}); }, [page]);
  const [toasts, setToasts] = useState([]);
  const [retrying, setRetrying] = useState(false);

  const { authState, data, actions } = useRealtime();

  // ── Toast system ───────────────────────────────────────────────
  const showToast = useCallback((message, type = "info") => {
    const id = ++_toastId;
    setToasts(p => [...p, { id, message, type }]);
  }, []);
  const removeToast = useCallback((id) => {
    setToasts(p => p.filter(t => t.id !== id));
  }, []);

  // ── Handle login ───────────────────────────────────────────────
  const handleLogin = async (credentials) => {
    try {
      const result = await actions.login(credentials.username, credentials.password);
      showToast(
        `Welcome, ${result.user.username}! Live backend connected.`,
        "success"
      );
      if (data.captureRunning) {
        showToast("Packet capture auto-started (Npcap active)", "info");
      }
    } catch (err) {
      // Error is already stored in authState.error — Login component reads it
      throw err;
    }
  };

  // ── Handle logout ──────────────────────────────────────────────
  const handleLogout = async () => {
    await actions.logout().catch(() => {});
    setPage("dashboard");
    showToast("Logged out", "info");
  };

  // ── Retry when offline screen is shown ────────────────────────
  const handleRetry = async () => {
    setRetrying(true);
    // If we have a stale token, try to reconnect WS + sync
    await actions.syncAll().catch(() => {});
    setRetrying(false);
  };

  // ── Capture toggle ─────────────────────────────────────────────
  const handleToggleCapture = async () => {
    try {
      if (data.captureRunning) {
        await actions.stopCapture();
        showToast(`Capture stopped · ${data.capturePackets.toLocaleString()} packets`, "info");
      } else {
        await actions.startCapture();
        showToast("Packet capture started", "success");
      }
    } catch (err) {
      showToast(`Capture error: ${err.message} — Run as Administrator?`, "error");
    }
  };

  // ── Sidebar badges ─────────────────────────────────────────────
  const badges = {
    alerts:    data.alerts.filter(a => ["CRITICAL","HIGH"].includes(a.severity) && a.status === "new").length,
    events:    data.winEvents.filter(e => e.securityRelevant).length,
    malware:   data.malwareScans.filter(s => s.scanResult === "infected").length,
    incidents: data.incidents.filter(i => ["open","investigating"].includes(i.status)).length,
  };

  // ── Props passed to every page ─────────────────────────────────
  const pageProps = {
    onAddUser: async (d) => actions.addUser(d),
    onUpdateUser: async (id,d) => actions.updateUser(id,d),
    appState:  data,      // pages use appState.* for data
    currentUser: authState.user,
    onNavigate: setPage,
    onToggleCapture: handleToggleCapture,
    onToast:    showToast,

    // Network
    onAddRule:           async (rule) => { const r = await actions.createRule(rule);     showToast("Rule created", "success");   return r; },
    onDeleteRule:        async (id)   => { await actions.deleteRule(id);                 showToast("Rule deleted", "warning");          },
    onToggleRule:        async (id)   => { const r = await actions.toggleRule(id);       showToast(r.active ? "Rule enabled" : "Rule disabled", "info"); },
    onUpdateAlertStatus: async (id, s)=> { await actions.updateAlertStatus(id, s);      showToast("Alert updated", "success");          },

    // Incidents
    onCreateIncident: async (d)       => { const r = await actions.createIncident(d);   showToast("Incident created", "success"); return r; },
    onUpdateIncident: async (id, s)   => { await actions.updateIncident(id, s);         showToast(`Status → ${s}`, "success");          },
    onAddNote:        async (id, note)=> { await actions.addNote(id, note);             showToast("Note added", "success");             },

    // Malware
    onScanFile: async (filePath) => {
      const result = await actions.scanFile(filePath);
      if (result.scanResult === "infected")   showToast(`🚨 MALWARE: ${result.threatName || "Unknown"}`, "critical");
      else if (result.scanResult === "suspicious") showToast(`⚠ Suspicious: ${result.fileName}`, "warning");
      else if (result.scanResult === "clean") showToast(`No detections: ${result.fileName}`, "success");
      else showToast(`Scan incomplete: ${result.threatName || result.fileName}`, "error");
      return result;
    },
    onStartMalwareFullScan: async (rootPath = "") => {
      const job = await actions.startMalwareFullScan(rootPath);
      showToast("Full-system malware scan started", "info");
      return job;
    },
    onGetMalwareFullScanStatus: async (jobId) => {
      return actions.getMalwareFullScanStatus(jobId);
    },
    onStopMalwareFullScan: async (jobId) => {
      const job = await actions.stopMalwareFullScan(jobId);
      showToast("Stop requested for full-system scan", "warning");
      return job;
    },

    // Vulnerability
    onCreateScan:    async (d)   => { const r = await actions.createScan(d);    showToast("Scan started: "+d.targets, "info"); return r; },
    onStartContinuousInterfaceScan: async (d) => {
      const r = await actions.startContinuousInterfaceScan(d);
      showToast(`Continuous interface scan started on ${d.interfaceName}`, "success");
      return r;
    },
    onGetScanRuntimeStatus: async (scanId) => {
      return actions.getScanRuntimeStatus(scanId);
    },
    onStopScanRuntime: async (scanId) => {
      const r = await actions.stopScanRuntime(scanId);
      showToast("Continuous interface scan stop requested", "warning");
      return r;
    },
    onUpdateFinding: async (id,s)=> actions.updateFinding(id, s),
    onListInterfaces: async () => {
      return actions.listInterfaces();
    },

    // Honeypots
    onDeployHoneypot: async (d)  => { const r = await actions.deployHoneypot(d); showToast("Honeypot deployed: "+d.name, "success"); return r; },
    onToggleHoneypot: async (id) => { await actions.toggleHoneypot(id);          showToast("Honeypot toggled", "info");                     },

  };

  // ══════════════════════════════════════════════════════════════
  //  RENDER STATES
  // ══════════════════════════════════════════════════════════════

  // 1. Initial loading / connecting
  if (authState.loading) {
    return (
      <>
        <style>{globalStyles}</style>
        <div style={{
          minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center",
          background:"linear-gradient(140deg, #08111d 0%, #0b1726 55%, #102b31 100%)",
          flexDirection:"column", gap:16,
        }}>
          <div style={{
            width:64, height:64, borderRadius:18,
            background:"linear-gradient(135deg, #0f766e, #06b6d4)",
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:22,
            color:"#ffffff", fontWeight:800, fontFamily:"var(--font-display)",
            boxShadow:"0 10px 28px rgba(6,182,212,0.24)",
          }}>◌</div>
          <div style={{ fontFamily:"var(--font-display)", fontSize:18, fontWeight:800,
            color:"#edf4f2", letterSpacing:"0.01em" }}>GhostNet</div>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ animation:"spin 1s linear infinite", display:"inline-block",
              fontSize:16, color:"#73f5c5" }}>⟳</span>
            <span style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"#93a5ad" }}>
              Connecting to backend…
            </span>
          </div>
        </div>
      </>
    );
  }

  // 2. Logged in but WebSocket disconnected/failed → show banner, not full block
  //    (WebSocket reconnects automatically, REST still works)

  // 3. Not authenticated → Login screen
  //    If login fails because backend is down → show OfflineScreen
  if (!authState.connected) {
    // Distinguish: never attempted vs failed with backend-down error
    const isBackendDown = authState.error &&
      (authState.error.includes("fetch") ||
       authState.error.includes("Failed to fetch") ||
       authState.error.includes("NetworkError") ||
       authState.error.includes("health check"));

    if (isBackendDown) {
      return (
        <>
          <style>{globalStyles}</style>
          <OfflineScreen
            error={authState.error}
            onRetry={handleRetry}
            retrying={retrying}
          />
          <ToastContainer toasts={toasts} onRemove={removeToast} />
        </>
      );
    }

    // Normal login screen (or login error like wrong password)
    return (
      <>
        <style>{globalStyles}</style>
        <LoginModule onLogin={handleLogin} error={authState.error} />
        <ToastContainer toasts={toasts} onRemove={removeToast} />
      </>
    );
  }

  // 4. Authenticated → full app
  const pages = {
    dashboard:  <Dashboard    {...pageProps} />,
    network:    <Network      {...pageProps} />,
    events:     <WindowsEvents {...pageProps} />,
    malware:    <Malware      {...pageProps} />,
    incidents:  <Incidents    {...pageProps} />,
    vuln:       <Vulnerability {...pageProps} />,
    honeypot:   <Honeypot     {...pageProps} />,
    reports:    <Reports      {...pageProps} />,
    users: authState.user?.role === "admin" ? <Users {...pageProps} /> : null,
    settings:   <Settings     {...pageProps} />,
  };

  return (
    <>
      <style>{globalStyles}</style>
      <div className="app-shell" style={{ display:"flex", height:"100vh", overflow:"hidden", background:"var(--color-bg)" }}>

        <Sidebar
          user={authState.user}
          activePage={page}
          onNavigate={setPage}
          badges={badges}
          status={{ capture: data.captureRunning, ml: authState.mlOnline, ws: authState.wsStatus === "connected" }}
        />

        <div className="app-content" style={{ flex:1, minWidth:0, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          <Header
            page={page}
            onNavigate={setPage}
            user={authState.user}
            captureRunning={data.captureRunning}
            onToggleCapture={handleToggleCapture}
            onLogout={handleLogout}
            onToast={showToast}
            onRefresh={() => actions.syncAll({strict:true})}
            extra={
              <ConnectionBadge
                wsStatus={authState.wsStatus}
                mlOnline={authState.mlOnline}
                captureRunning={data.captureRunning}
              />
            }
          />

          {/* WebSocket warning banner (non-blocking) */}
          {authState.wsStatus !== "connected" && authState.wsStatus !== "connecting" && (
            <div style={{
              background:"#fffbeb", borderBottom:"1.5px solid #fde68a",
              padding:"8px 22px", display:"flex", alignItems:"center", gap:10,
              fontSize:12, color:"#b45309",
            }}>
              <span>⚠</span>
              <span>
                WebSocket {authState.wsStatus} — real-time push paused.
                REST polling active every 15s.
                {authState.wsStatus === "failed"
                  ? " Reload the page to retry."
                  : " Reconnecting automatically…"}
              </span>
            </div>
          )}

          <main ref={mainRef} style={{
            flex:1, overflowY:"auto",
            padding:"38px 40px",
            background:"var(--color-bg)",
          }}>
            <Suspense fallback={
              <div style={{ display:"flex", alignItems:"center", gap:8, color:"#93a7b1", fontFamily:"var(--font-mono)", fontSize:12 }}>
                <span style={{ animation:"spin 1s linear infinite", display:"inline-block" }}>⟳</span>
                Loading module...
              </div>
            }>
              {pages[page] || pages.dashboard}
            </Suspense>
          </main>
          <AppFooter />
        </div>
      </div>

      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </>
  );
}
