import { useEffect, useState } from "react";
import { Panel, Grid, StatCard, Btn, FormGroup, EmptyState, ModuleHeader } from "../components/UI.jsx";
import { reports as reportsApi } from "../api/client.js";
import { saveBlobWithPicker, triggerBrowserDownload } from "../utils/fileDownload.js";
import { fmtDateTime, now } from "../utils/dateFormatter.js";
import { createReportBlob } from "../utils/reportExport.js";

const TEMPLATES = [
  { id:1, name:"Security Summary",       type:"security",      desc:"Selected-period threat overview — alerts, incidents, malware detections",    icon:"🛡" },
  { id:2, name:"Compliance Report",      type:"compliance",    desc:"Incident and Windows event evidence for the selected period",       icon:"📋" },
  { id:3, name:"Executive Dashboard",    type:"executive",     desc:"Database totals and supporting security records",           icon:"📊" },
  { id:4, name:"Vulnerability Report",   type:"vulnerability", desc:"Findings with CVE/CWE references and remediation steps",icon:"🔍" },
  { id:5, name:"Windows Event Report",   type:"windows-events",desc:"System event logs with Event IDs, levels, users, channels, and security context", icon:"🪟" },
];

const FORMAT_COLORS = {
  pdf:  { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  html: { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd" },
  csv:  { bg:"#ecfdf5", text:"#047857", border:"#a7f3d0" },
  json: { bg:"#f5f3ff", text:"#6d28d9", border:"#ddd6fe" },
};

export default function Reports({ onToast }) {
  const [days,setDays]=useState(30);
  const [generated, setGenerated] = useState([]);
  const [generating, setGenerating] = useState(null);
  const [format, setFormat] = useState("pdf");
  const [snapshot, setSnapshot] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);

  const refreshSnapshot = async ({ silent = false } = {}) => {
    setSyncing(true);
    try {
      const payload = await reportsApi.syncData({ days, limit: 5000 });
      setSnapshot(payload);
      const ts = now().toISOString();
      setLastSyncedAt(ts);
      if (!silent) onToast("Selected-period database snapshot refreshed", "success");
      return payload;
    } catch {
      setSnapshot(null);
      if (!silent) onToast("Failed to load report snapshot", "error");
      return null;
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => {
    let mounted = true;
    (async () => {
      const payload = await refreshSnapshot({ silent: true });
      if (!mounted || !payload) return;
    })();
    return () => { mounted = false; };
  }, [days]);

  const downloadGeneratedReport = async (report) => {
    try {
      if (!report.blob) {
        onToast("No file available for this report", "warning");
        return;
      }

      try {
        const mime = report.format === "pdf"
          ? "application/pdf"
          : report.format === "csv"
            ? "text/csv"
            : report.format === "json"
              ? "application/json"
              : "text/html";
        const saved = await saveBlobWithPicker(report.blob, report.name, mime);
        if (saved) {
          onToast("Report saved: " + report.name, "success");
          return;
        }
      } catch {
        // User canceled picker or browser does not support it.
      }

      triggerBrowserDownload(report.blob, report.name);
      onToast("Downloading " + report.name, "info");
    } catch (e) {
      onToast("Download failed: " + (e.message || "unknown error"), "error");
    }
  };

  const generate = async (template) => {
    setGenerating(template.id);
    onToast(`Generating ${template.name}…`, "info");

    try {
      const reportSnapshot=await refreshSnapshot({silent:true});
      if(!reportSnapshot)throw new Error('Could not refresh database snapshot. No report was generated.');
      const built=createReportBlob(template,format,reportSnapshot);
      const report = {
        id: Date.now(),
        name: built.fileName,
        type: template.type,
        format,
        size: `${Math.max(1, Math.round(built.blob.size / 1024))} KB`,
        generatedAt: now().toISOString(),
        status: "completed",
        blob: built.blob,
      };
      setGenerated(p => [report, ...p]);
      onToast(`${template.name} generated successfully`, "success");
    } catch (e) {
      onToast(`Failed to generate ${template.name}: ${e.message || "unknown error"}`, "error");
    } finally {
      setGenerating(null);
    }
  };

  const syncedSummary = snapshot?.summary || {};
  const stats = [
    {icon:'!',label:`Alerts (${days}d)`,value:syncedSummary.alerts??'—',color:'#e11d48'},
    {icon:'!',label:'Open incidents in period',value:syncedSummary.openIncidents??'—',color:'#f59e0b'},
    {icon:'!',label:'Infected scan results',value:syncedSummary.infectedFiles??'—',color:'#7c3aed'},
    {icon:'!',label:'Critical findings in period',value:syncedSummary.criticalVulns??'—',color:'#2d6bff'},
  ];
  const checkItems = snapshot?.checks || [];
  const syncedCves = snapshot?.cveRecords || [];
  const statusStyles = {
    pass: { bg:"#dcfce7", text:"#166534" },
    warn: { bg:"#fee2e2", text:"#b91c1c" },
    info: { bg:"#dbeafe", text:"#1d4ed8" },
  };

  return (
    <div className="page-enter module-page">
      <ModuleHeader eyebrow="EVIDENCE" title="Reports" subtitle="Database snapshots with explicit reporting periods, record coverage, and supporting evidence" />
      <div style={{marginBottom:20,maxWidth:280}}><FormGroup label="Reporting period"><select aria-label="Reporting period" value={days} disabled={generating!==null||syncing} onChange={e=>{setSnapshot(null);setDays(Number(e.target.value));}}><option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option></select></FormGroup></div>
      <p style={{color:'var(--color-text-secondary)',fontSize:12}}>Totals cover the selected period. Exports include up to 5,000 latest records per category and disclose any limit reached. Open incidents use current status; infected results count scans.</p>
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        {stats.map(s => (
          <StatCard key={s.label} icon={s.icon} label={s.label} value={s.value} color={s.color} />
        ))}
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        <Panel title="Data Health Checks" subtitle="Ensure synced data is ready for export">
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12, gap:12 }}>
            <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)" }}>
              {days}-day snapshot: {lastSyncedAt ? fmtDateTime(lastSyncedAt) : "Pending"}
            </div>
            <Btn size="xs" variant="ghost" onClick={() => refreshSnapshot()} disabled={syncing}>
              {syncing ? "Refreshing..." : "Refresh Data"}
            </Btn>
          </div>
          {checkItems.length === 0 ? (
            <EmptyState icon="🧪" title="No checks yet" sub="Sync data to view readiness checks" />
          ) : (
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {checkItems.map((item) => {
                const palette = statusStyles[item.status] || statusStyles.info;
                return (
                  <div key={item.id} style={{
                    padding:"10px 12px",
                    border:"1px solid var(--color-border)",
                    borderRadius:"var(--r-md)",
                    background:"#121e24",
                    boxShadow:"var(--shadow-xs)",
                  }}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:12 }}>
                      <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)" }}>{item.label}</div>
                      <span style={{
                        fontSize:10,
                        fontFamily:"var(--font-mono)",
                        textTransform:"uppercase",
                        padding:"2px 8px",
                        borderRadius:999,
                        background:palette.bg,
                        color:palette.text,
                      }}>{(item.status || "info").toUpperCase()}</span>
                    </div>
                    <div style={{ fontSize:12, color:"var(--color-text-tertiary)", marginTop:4 }}>{item.detail}</div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel title="Top CVE Records" subtitle="Most frequent CVE findings in sync window">
          {syncedCves.length === 0 ? (
            <EmptyState icon="📄" title="No CVE data" sub="Run vulnerability scans to populate CVE records" />
          ) : (
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
                <thead>
                  <tr style={{ textAlign:"left", background:"#19282e", borderBottom:"1px solid #253239" }}>
                    {['CVE','Total','Critical','High','Medium','Last Seen'].map((h) => (
                      <th key={h} style={{ padding:"8px 10px", fontFamily:"var(--font-mono)", fontSize:10, color:"#93a7b1", textTransform:"uppercase", letterSpacing:"0.05em" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {syncedCves.slice(0,5).map((record) => (
                    <tr key={record.cveId} style={{ borderBottom:"1px solid #223039" }}>
                      <td style={{ padding:"8px 10px", fontFamily:"var(--font-mono)", color:"#dce6e8" }}>{record.cveId}</td>
                      <td style={{ padding:"8px 10px" }}>{record.totalFindings}</td>
                      <td style={{ padding:"8px 10px", color:"#b91c1c" }}>{record.criticalCount}</td>
                      <td style={{ padding:"8px 10px", color:"#ea580c" }}>{record.highCount}</td>
                      <td style={{ padding:"8px 10px", color:"#ca8a04" }}>{record.mediumCount}</td>
                      <td style={{ padding:"8px 10px", color:"#93a7b1" }}>{record.lastObserved ? fmtDateTime(record.lastObserved) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </Grid>

      <Grid cols={2} gap={16}>
        {/* Templates */}
        <Panel title="Report Templates" subtitle="Click Generate to create a report">
          <div style={{ padding:"0 4px" }}>
            {/* Format selector */}
            <div style={{ padding:"12px 14px 0", marginBottom:4 }}>
              <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
                textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:8, fontWeight:600 }}>Output Format</div>
              <div style={{ display:"flex", gap:8 }}>
                {["pdf","html","csv","json"].map(f => {
                  const fc = FORMAT_COLORS[f];
                  return (
                    <button key={f} disabled={generating!==null} onClick={() => setFormat(f)} style={{
                      padding:"4px 12px", borderRadius:99, border:`1.5px solid ${format===f ? fc.text : "#e2e8f0"}`,
                      background: format===f ? fc.bg : "transparent",
                      color: format===f ? fc.text : "var(--color-text-tertiary)",
                      fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700, cursor:"pointer",
                      textTransform:"uppercase", transition:"all 0.14s",
                    }}>{f}</button>
                  );
                })}
              </div>
            </div>

            {TEMPLATES.map(t => (
              <div key={t.id} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"14px 14px", borderTop:"1.5px solid var(--color-border)",
              }}
                onMouseEnter={e => e.currentTarget.style.background = "#19282e"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div style={{ display:"flex", gap:12, alignItems:"flex-start", flex:1 }}>
                  <div style={{
                    width:36, height:36, borderRadius:"var(--r-md)", background:"#f0f5ff",
                    border:"1.5px solid #c1d4ff", display:"flex", alignItems:"center",
                    justifyContent:"center", fontSize:18, flexShrink:0,
                  }}>{t.icon}</div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontWeight:700, fontSize:13, color:"var(--color-text-primary)", marginBottom:2 }}>{t.name}</div>
                    <div style={{ fontSize:12, color:"var(--color-text-tertiary)", lineHeight:1.4 }}>{t.desc}</div>
                  </div>
                </div>
                <Btn size="sm" variant={generating===t.id ? "ghost" : "outline"}
                  disabled={generating!==null||syncing}
                  onClick={() => generate(t)}
                  style={{ marginLeft:12, flexShrink:0 }}>
                  {generating===t.id
                    ? <><span style={{ display:"inline-block", animation:"spin 1s linear infinite" }}>⟳</span> Generating…</>
                    : "Generate"}
                </Btn>
              </div>
            ))}
          </div>
        </Panel>

        {/* Generated Reports */}
        <Panel title="Generated Reports" subtitle="Download or share reports">
          {generated.length === 0 ? (
            <EmptyState icon="📂" title="No reports generated yet"
              sub="Select a template and click Generate to create your first report" />
          ) : (
            <div>
              {generated.map(r => {
                const fc = FORMAT_COLORS[r.format] || FORMAT_COLORS.pdf;
                return (
                  <div key={r.id} style={{
                    display:"flex", alignItems:"center", justifyContent:"space-between",
                    padding:"12px 16px", borderBottom:"1px solid #223039",
                  }}>
                    <div style={{ display:"flex", gap:10, alignItems:"center", flex:1, minWidth:0 }}>
                      <div style={{
                        width:32, height:32, borderRadius:"var(--r-md)",
                        background:fc.bg, border:`1.5px solid ${fc.border}`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
                        color:fc.text, flexShrink:0,
                      }}>{r.format.toUpperCase()}</div>
                      <div style={{ minWidth:0 }}>
                        <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)",
                          overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.name}</div>
                        <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--color-text-tertiary)", marginTop:1 }}>
                          {r.size} · {fmtDateTime(r.generatedAt)}
                        </div>
                      </div>
                    </div>
                    <div style={{ display:"flex", gap:6, flexShrink:0, marginLeft:10 }}>
                      <Btn size="xs" variant="ghost" onClick={() => downloadGeneratedReport(r)}>⬇ Download</Btn>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </Grid>

    </div>
  );
}
