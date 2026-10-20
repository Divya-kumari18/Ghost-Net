import { useMemo, useState, useEffect } from "react";
import { dashboard } from "../api/client.js";
import { StatCard, Panel, Grid, Badge, IPPill, FeedItem, ProgressBar, LivePulse, EmptyState, Select, ModuleHeader } from "../components/UI.jsx";
import { fmtTime } from "../utils/dateFormatter.js";
function fmtNum(n) {
  return n >= 1000000 ? (n/1000000).toFixed(1)+"M" : n >= 1000 ? (n/1000).toFixed(1)+"K" : String(n);
}

const TIME_RANGE_OPTIONS = [
  { value: "1h",  label: "Last 1 hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "30d", label: "Last 30 days" },
];

const TIME_RANGE_MS = {
  "1h":  60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

function parseTs(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function filterByWindow(list, pickTimestamp, nowMs, windowMs) {
  return list.filter((item) => {
    const ts = parseTs(pickTimestamp(item));
    if (!ts) return false;
    return nowMs - ts.getTime() <= windowMs;
  });
}

function miniTrendPoints(values, w = 440, h = 110, pad = 14) {
  if (!values.length) return "";
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? (w - pad * 2) / (values.length - 1) : 0;
  return values.map((v, i) => {
    const x = pad + i * step;
    const y = h - pad - ((v / max) * (h - pad * 2));
    return `${x},${y}`;
  }).join(" ");
}

function areaPath(points, h = 110, pad = 14) {
  if (!points.length) return "";
  const first = points[0].split(",");
  const last = points[points.length - 1].split(",");
  return `M ${first[0]} ${h - pad} L ${points.join(" L ")} L ${last[0]} ${h - pad} Z`;
}

export default function Dashboard({ appState, onNavigate }) {
  const {
    alerts,
    incidents,
    malwareScans,
    winEvents,
    honeypots,
    idsRules,
    vulnFindings,
    capturePackets,
    captureRunning,
    captureLoops,
    captureRestarts,
    feedItems,
    trafficFeed,
  } = appState;

  const [timeRange, setTimeRange] = useState("24h");
  const [metrics,setMetrics]=useState(null);
  useEffect(()=>{
    let active=true;setMetrics(null);
    const refresh=()=>dashboard.metrics(timeRange).then(value=>{if(active)setMetrics(value);}).catch(()=>{if(active)setMetrics(null);});
    refresh();const timer=setInterval(refresh,15000);
    return ()=>{active=false;clearInterval(timer);};
  },[timeRange]);

  const nowMs = Date.now();
  const selectedWindowMs = TIME_RANGE_MS[timeRange] || TIME_RANGE_MS["24h"];
  const selectedRangeLabel = TIME_RANGE_OPTIONS.find(o => o.value === timeRange)?.label || "Last 24 hours";

  const alertsInWindow = useMemo(
    () => filterByWindow(alerts, (a) => a.timestamp, nowMs, selectedWindowMs),
    [alerts, nowMs, selectedWindowMs]
  );
  const incidentsInWindow = useMemo(
    () => filterByWindow(incidents, (i) => i.createdAt, nowMs, selectedWindowMs),
    [incidents, nowMs, selectedWindowMs]
  );
  const malwareInWindow = useMemo(
    () => filterByWindow(malwareScans, (m) => m.scanTime, nowMs, selectedWindowMs),
    [malwareScans, nowMs, selectedWindowMs]
  );
  const eventsInWindow = useMemo(
    () => filterByWindow(winEvents, (e) => e.eventTime, nowMs, selectedWindowMs),
    [winEvents, nowMs, selectedWindowMs]
  );

  const critAlerts  = alertsInWindow.filter(a => a.severity === "CRITICAL").length;
  const highAlerts  = alertsInWindow.filter(a => a.severity === "HIGH").length;
  const medAlerts   = alertsInWindow.filter(a => a.severity === "MEDIUM").length;
  const lowAlerts   = alertsInWindow.filter(a => a.severity === "LOW").length;
  const openInc     = incidentsInWindow.filter(i => ["open","investigating"].includes(i.status)).length;
  const secEvts     = eventsInWindow.filter(e => e.securityRelevant).length;
  const infected    = malwareInWindow.filter(s => s.scanResult === "infected").length;
  const totalAlerts = critAlerts + highAlerts + medAlerts + lowAlerts || 1;
  const activeHPs   = honeypots.filter(h => h.active).length;
  const openVulns   = vulnFindings.filter(f => f.status === "open").length;
  const activeRules = idsRules.filter(r => r.active).length;

  const moduleStatus = [
    { icon:"⌁", label:"Capture + IDS",   status:captureRunning ? "Active" : "Stopped",    color:"#10b981", sub:`${activeRules} rules · Pcap4j`, page:"network"   },
    { icon:"▤", label:"Event Ingest",    status:appState.dashStats?.eventReader?.running ? "Polling" : "Unavailable",   color:"#06b6d4", sub:"Windows logs · 5s",      page:"events"    },
    { icon:"◈", label:"Malware Watch",   status:appState.mlStatus?.services?.yara?.ready ? "YARA ready" : "Limited",     color:"#10b981", sub:"YARA + VirusTotal",       page:"malware"   },
    { icon:"⌕", label:"CVE / CWE Scan",  status: openVulns > 0 ? "Findings" : "Idle", color: openVulns > 0 ? "#f59e0b" : "#94a3b8", sub:`${openVulns} open`, page:"vuln" },
    { icon:"⊙", label:"Honeypot Grid",   status: activeHPs > 0 ? `${activeHPs} Active` : "Inactive", color: activeHPs > 0 ? "#10b981" : "#94a3b8", sub:"Attacker traps", page:"honeypot" },
    { icon:"◎", label:"AI / ML Engine",  status:appState.mlStatus?.services?.anomaly?.ready ? "Trained" : "Untrained",    color:"#0f766e", sub:"Anomaly analysis",          page:"network"   },
  ];

  const severityCounts = [critAlerts, highAlerts, medAlerts, lowAlerts];
  const severityTotal = Math.max(1, severityCounts.reduce((a, b) => a + b, 0));
  const sevPct = severityCounts.map(v => (v / severityTotal) * 100);
  const trendRaw = alertsInWindow.slice(0, 24);
  const trendBuckets = new Array(12).fill(0);
  alertsInWindow.forEach(alert => {
    const age=nowMs-new Date(alert.timestamp).getTime();
    const index=11-Math.floor(age/(selectedWindowMs/12));
    if(index>=0 && index<12) trendBuckets[index] += 1;
  });
  const trendPolyline = miniTrendPoints(trendBuckets);
  const trendArea = areaPath(trendPolyline ? trendPolyline.split(" ") : []);

  return (
    <div className="page-enter module-page">
      <ModuleHeader eyebrow="YOUR SECURITY AT A GLANCE." title="Overview" subtitle="Monitor your security posture, investigate threats, and keep your environment protected."/>
      <div style={{ display:"flex", justifyContent:"flex-end", marginBottom:12 }}>
        <Select
          value={timeRange}
          onChange={setTimeRange}
          options={TIME_RANGE_OPTIONS}
          style={{ minWidth: 160 }}
        />
      </div>

      {/* Top stats */}
      <Grid cols={4} gap={16} style={{ marginBottom:20 }}>
        <StatCard icon="🚨" label="Active Alerts"    value={metrics?.activeAlerts ?? "—"}
          sub={`${selectedRangeLabel} · Critical + High`} color="#e11d48" onClick={() => onNavigate("network")} />
        <StatCard icon="🔥" label="Open Incidents"   value={metrics?.openIncidents ?? "—"}
          sub={selectedRangeLabel} color="#f59e0b" onClick={() => onNavigate("incidents")} />
        <StatCard icon="📦" label="Packets Captured" value={metrics ? fmtNum(metrics.packets) : "—"}
          sub={selectedRangeLabel} color="#2d6bff" onClick={() => onNavigate("network")} />
        <StatCard icon="🪟" label="Security Events"  value={metrics?.securityEvents ?? "—"}
          sub={selectedRangeLabel} color="#7c3aed" onClick={() => onNavigate("events")} />
      </Grid>

      <Panel title="GhostNet Detection Pipeline" subtitle="Five-layer architecture · real-time event path" style={{ marginBottom: 20 }}>
        <div style={{ padding: "18px 20px", display:"grid", gridTemplateColumns:"repeat(5, minmax(0, 1fr))", gap:0 }}>
          {[
            { step:"01", title:"Collect", detail:"Pcap4j · logs · feeds", color:"#06b6d4", page:"network" },
            { step:"02", title:"Stream", detail:"Persistent event pipeline", color:"#0f766e", page:"network" },
            { step:"03", title:"Correlate", detail:"Rules · CVE / CWE", color:"#f59e0b", page:"incidents" },
            { step:"04", title:"Analyze", detail:"IDS · YARA · AI / ML", color:"#14b8a6", page:"malware" },
            { step:"05", title:"Respond", detail:"Alerts · reports · action", color:"#e11d48", page:"reports" },
          ].map((stage, i, stages) => (
            <div key={stage.step} onClick={() => onNavigate(stage.page)} style={{ position:"relative", cursor:"pointer", padding:"2px 14px 2px 0" }}>
              {i < stages.length - 1 && <div style={{ position:"absolute", top:17, left:34, right:0, height:1, background:"linear-gradient(90deg, #9fb8bb, #dce7e7)" }} />}
              <div style={{ position:"relative", display:"flex", alignItems:"center", gap:9 }}>
                <div style={{ width:34, height:34, borderRadius:"50%", background:stage.color, color:"#fff", display:"grid", placeItems:"center", fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700, boxShadow:`0 0 0 5px ${stage.color}18` }}>{stage.step}</div>
                <div style={{ minWidth:0 }}>
                  <div style={{ fontFamily:"var(--font-display)", fontSize:12, fontWeight:700, color:"var(--color-text-primary)" }}>{stage.title}</div>
                  <div style={{ fontSize:10, color:"var(--color-text-tertiary)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{stage.detail}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        <Panel title="Recent Alert Activity" subtitle={`${selectedRangeLabel} · Last 12 slices · loaded records`}>
          <div style={{ padding:16 }}>
            <svg viewBox="0 0 440 110" style={{ width:"100%", height:120, display:"block" }}>
              <defs>
                <linearGradient id="trendFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor="#2d6bff" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#2d6bff" stopOpacity="0.03" />
                </linearGradient>
              </defs>
              {[20, 40, 60, 80].map(y => (
                <line key={y} x1="14" y1={y} x2="426" y2={y} stroke="#2b4352" strokeWidth="1" />
              ))}
              {trendArea && <path d={trendArea} fill="url(#trendFill)" />}
              {trendPolyline && <polyline points={trendPolyline} fill="none" stroke="#2d6bff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            </svg>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(5, minmax(0,1fr))", gap:8, marginTop:8 }}>
              <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#82959e", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Total Flow</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#edf4f2" }}>{fmtNum(alertsInWindow.length)}</div>
              </div>
              <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#82959e", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Peak Slice</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#edf4f2" }}>{Math.max(...trendBuckets, 0)}</div>
              </div>
              <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#82959e", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Capture</div>
                <div style={{ fontSize:14, fontWeight:700, color: captureRunning ? "#6ee7d8" : "#82959e" }}>{captureRunning ? "Live" : "Idle"}</div>
              </div>
              <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#82959e", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Capture Loops</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#7dd3fc" }}>{fmtNum(captureLoops || 0)}</div>
                <div style={{ fontSize:10, color:"#82959e", marginTop:2 }}>Restarts: {fmtNum(captureRestarts || 0)}</div>
              </div>
              <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#82959e", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Infected Files</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#b91c1c" }}>{infected}</div>
              </div>
            </div>
          </div>
        </Panel>

        <Panel title="Threat Composition" subtitle="Current alert composition">
          <div style={{ padding:16, display:"flex", gap:18, alignItems:"center" }}>
            <svg viewBox="0 0 160 160" style={{ width:150, height:150, flexShrink:0 }}>
              <circle cx="80" cy="80" r="52" stroke="#253239" strokeWidth="20" fill="none" />
              <circle cx="80" cy="80" r="52" stroke="#e11d48" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[0] / 100) * 327} 327`} transform="rotate(-90 80 80)" strokeLinecap="butt" />
              <circle cx="80" cy="80" r="52" stroke="#f59e0b" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[1] / 100) * 327} 327`} transform={`rotate(${((sevPct[0] / 100) * 360) - 90} 80 80)`} strokeLinecap="butt" />
              <circle cx="80" cy="80" r="52" stroke="#8b5cf6" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[2] / 100) * 327} 327`} transform={`rotate(${(((sevPct[0] + sevPct[1]) / 100) * 360) - 90} 80 80)`} strokeLinecap="butt" />
              <circle cx="80" cy="80" r="52" stroke="#10b981" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[3] / 100) * 327} 327`} transform={`rotate(${(((sevPct[0] + sevPct[1] + sevPct[2]) / 100) * 360) - 90} 80 80)`} strokeLinecap="butt" />
              <circle cx="80" cy="80" r="34" fill="#10191e" />
              <text x="80" y="76" textAnchor="middle" style={{ fontSize:11, fill:"#82959e", fontFamily:"var(--font-mono)" }}>ALERTS</text>
              <text x="80" y="96" textAnchor="middle" style={{ fontSize:20, fill:"#edf4f2", fontWeight:700 }}>{severityCounts.reduce((a, b) => a + b, 0)}</text>
            </svg>
            <div style={{ flex:1 }}>
              {[
                ["Critical", critAlerts, "#e11d48"],
                ["High", highAlerts, "#f59e0b"],
                ["Medium", medAlerts, "#8b5cf6"],
                ["Low", lowAlerts, "#10b981"],
              ].map(([label, value, color]) => (
                <div key={label} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{ width:8, height:8, borderRadius:"50%", background:color, display:"inline-block" }} />
                    <span style={{ fontSize:12, color:"#99aab2", fontWeight:500 }}>{label}</span>
                  </div>
                  <span style={{ fontFamily:"var(--font-mono)", fontWeight:700, color }}>{value}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        {/* Live Feed */}
        <Panel
          title="Correlated Event Stream"
          subtitle={captureRunning ? "Streaming live" : "Start capture to stream"}
          actions={<LivePulse active={captureRunning} label={captureRunning ? "LIVE" : "IDLE"} />}
        >
          <div style={{ maxHeight:280, overflowY:"auto" }}>
            {feedItems.length === 0 ? (
              <EmptyState icon="📡" title="No alerts yet" sub="Start packet capture to begin monitoring" />
            ) : (
              feedItems.slice(0,20).map((f, i) => (
                <FeedItem key={i} time={f.time} severity={f.severity}
                  badgeLabel={f.label} message={f.message} type="sev" />
              ))
            )}
          </div>
        </Panel>

        {/* Threat Breakdown */}
        <Panel title="Threat Breakdown" subtitle={selectedRangeLabel}>
          <div style={{ padding:18 }}>
            {[
              { label:"Critical", count:critAlerts, color:"#e11d48", pct:(critAlerts/totalAlerts)*100 },
              { label:"High",     count:highAlerts, color:"#f59e0b", pct:(highAlerts/totalAlerts)*100  },
              { label:"Medium",   count:medAlerts,  color:"#8b5cf6", pct:(medAlerts/totalAlerts)*100   },
              { label:"Low",      count:lowAlerts,  color:"#10b981", pct:(lowAlerts/totalAlerts)*100   },
            ].map(s => (
              <div key={s.label} style={{ marginBottom:14 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                  <span style={{ fontSize:13, color:"var(--color-text-secondary)", fontWeight:500 }}>{s.label}</span>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700, color:s.color }}>{s.count}</span>
                </div>
                <ProgressBar value={s.pct} max={100} color={s.color} height={5} />
              </div>
            ))}

            <div style={{ marginTop:20, paddingTop:16, borderTop:"1.5px solid var(--color-border)" }}>
              <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
                textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:10, fontWeight:600 }}>
                Protocol Distribution
              </div>
              <div style={{ display:"flex", alignItems:"flex-end", gap:6, height:48 }}>
                {[
                  { label:"TCP",  pct:72, color:"#2d6bff"  },
                  { label:"UDP",  pct:18, color:"#10b981"  },
                  { label:"ICMP", pct:7,  color:"#f59e0b"  },
                  { label:"Other",pct:3,  color:"#94a3b8"  },
                ].map(p => (
                  <div key={p.label} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:4 }}>
                    <div style={{ width:"100%", background:p.color+"22", borderRadius:4,
                      height: `${p.pct * 0.48}px`, position:"relative", overflow:"hidden",
                      border:`1px solid ${p.color}33`,
                    }}>
                      <div style={{ position:"absolute", bottom:0, left:0, right:0,
                        background:p.color, height:`${p.pct}%`, borderRadius:"3px 3px 0 0", opacity:0.7 }} />
                    </div>
                    <span style={{ fontSize:9, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)" }}>{p.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      </Grid>

      {/* Module Status Grid */}
      <Grid cols={3} gap={12}>
        {moduleStatus.map((m, i) => (
          <div key={i}
            onClick={() => onNavigate(m.page)}
            style={{
              background:"var(--color-surface)", border:"1.5px solid var(--color-border)",
              borderRadius:"var(--r-lg)", padding:"16px 18px",
              cursor:"pointer", transition:"all 0.15s",
              boxShadow:"var(--shadow-xs)",
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = m.color+"55"; e.currentTarget.style.boxShadow = "var(--shadow-md)"; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = "var(--color-border)"; e.currentTarget.style.boxShadow = "var(--shadow-xs)"; }}
          >
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
              <span style={{ fontSize:20 }}>{m.icon}</span>
              <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                <span style={{ width:6, height:6, borderRadius:"50%", background:m.color,
                  display:"inline-block", animation:"pulseDot 2s ease-in-out infinite" }} />
                <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                  color:m.color, textTransform:"uppercase" }}>{m.status}</span>
              </div>
            </div>
            <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13,
              color:"var(--color-text-primary)", marginBottom:2 }}>{m.label}</div>
            <div style={{ fontSize:11, color:"var(--color-text-tertiary)" }}>{m.sub}</div>
          </div>
        ))}
      </Grid>

      {/* Recent Alerts Table */}
      {alertsInWindow.length > 0 && (
        <div style={{ marginTop:20 }}>
          <Panel title="Recent Alerts" subtitle="Latest security detections"
            actions={
              <button onClick={() => onNavigate("network")} style={{
                fontFamily:"var(--font-body)", fontSize:12, fontWeight:600,
                color:"#2d6bff", background:"none", border:"none", cursor:"pointer",
              }}>View All →</button>
            }>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:13 }}>
                <thead>
                  <tr style={{ background:"#121e24", borderBottom:"1.5px solid var(--color-border)" }}>
                    {["Time","Severity","Source","Destination","Rule","Status"].map(h => (
                      <th key={h} style={{ textAlign:"left", padding:"10px 14px",
                        fontFamily:"var(--font-mono)", fontSize:10, fontWeight:600,
                        color:"var(--color-text-tertiary)", textTransform:"uppercase", letterSpacing:"0.06em",
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alertsInWindow.slice(0,5).map(a => (
                    <tr key={a.alertId}
                      style={{ borderBottom:"1px solid #223039", transition:"background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = "#19282e"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <td style={{ padding:"9px 14px", fontFamily:"var(--font-mono)", fontSize:11,
                        color:"var(--color-text-tertiary)", whiteSpace:"nowrap" }}>{fmtTime(a.timestamp)}</td>
                      <td style={{ padding:"9px 14px" }}><Badge severity={a.severity} /></td>
                      <td style={{ padding:"9px 14px" }}><IPPill ip={a.sourceIp} /></td>
                      <td style={{ padding:"9px 14px", fontFamily:"var(--font-mono)", fontSize:11,
                        color:"var(--color-text-secondary)" }}>{a.destinationIp}:{a.destinationPort}</td>
                      <td style={{ padding:"9px 14px", fontSize:12, color:"var(--color-text-secondary)",
                        maxWidth:160, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {a.ruleName}</td>
                      <td style={{ padding:"9px 14px" }}><Badge status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
