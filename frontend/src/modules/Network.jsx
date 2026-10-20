import { useState } from "react";
import { Panel, Grid, StatCard, Badge, Btn, EmptyState, Select, ModuleHeader } from "../components/UI.jsx";
import Icon from "../components/Icon.jsx";


const sev = { 1:"Low", 2:"Medium", 3:"High", 4:"Critical" };
const sevColor = { 1:"#10b981", 2:"#8b5cf6", 3:"#f59e0b", 4:"#e11d48" };

const PRESET_IDS_RULES = [
  {slug:'ssh-attempts',label:'Repeated SSH Connections',description:'10 new TCP connection attempts from a source to a host within 60 seconds.',
   rule:{ruleName:'Repeated SSH Connections',ruleContent:'Repeated SYN packets to SSH; authentication failures require server logs.',ruleType:'custom',severity:3,portPattern:'22',protocolPattern:'TCP',thresholdCount:10,windowSeconds:60}},
  {slug:'http-sqli',label:'HTTP SQL Injection Pattern',description:'SQL keywords in visible HTTP payloads.',
   rule:{ruleName:'HTTP SQL Injection Pattern',ruleContent:'Structured HTTP payload signature',ruleType:'custom',severity:3,portPattern:'80,8080',protocolPattern:'TCP',payloadPattern:'(?i)(union\\s+select|sleep\\s*\\(|benchmark\\s*\\()'}},
  {slug:'port-scan',label:'Port Scan Pattern',description:'20 distinct destination ports from one source to one host in 60 seconds.',
   rule:{ruleName:'Port Scan Pattern',ruleContent:'Distinct SYN destination ports',ruleType:'custom',severity:3,portPattern:'any',protocolPattern:'TCP',thresholdCount:20,windowSeconds:60,distinctPorts:true}},
  {slug:'powershell',label:'PowerShell Download Pattern',description:'Download command strings in unencrypted payloads.',
   rule:{ruleName:'PowerShell Download Pattern',ruleContent:'Visible script download signature',ruleType:'custom',severity:4,protocolPattern:'TCP',payloadPattern:'(?i)(downloadstring|invoke-webrequest|powershell -enc)'}},
];

export default function Network({ appState, onAddRule, onDeleteRule, onToggleRule, onUpdateAlertStatus, onToast, onToggleCapture, onNavigate }) {
  const { alerts, idsRules, capturePackets, captureRunning, trafficFeed } = appState;
  const [selectedPacketIdx, setSelectedPacketIdx] = useState(0);
  const [presetBusy, setPresetBusy] = useState(null);
  const [ruleBusy, setRuleBusy] = useState(null);
  const [deleteBusy, setDeleteBusy] = useState(null);
  const packetRows = (trafficFeed || []).slice(0, 80).map((p, idx) => ({
    no: idx + 1,
    time: p.time || "--:--:--",
    src: p.src || "0.0.0.0",
    dst: p.dst || "0.0.0.0",
    protocol: (p.protocol || "OTHER").toUpperCase(),
    length: p.size || 0,
    port: p.port || "-",
    info: `${(p.protocol || "IP").toUpperCase()} ${p.src || "?"} → ${p.dst || "?"}${p.port ? `:${p.port}` : ""}`,
  }));
  const selectedPacket = packetRows[selectedPacketIdx] || null;
  const protoColor = (proto) => ({ TCP:"#2d6bff", UDP:"#0ea5e9", ICMP:"#f59e0b", DNS:"#8b5cf6" }[proto] || "#64748b");

  const handlePresetAction = async (preset) => {
    if (presetBusy) return;
    setPresetBusy(preset.slug);
    try {
      const existing = idsRules.find(r => r.ruleName === preset.rule.ruleName);
      if (!existing) {
        await onAddRule(preset.rule);
      } else {
        await onToggleRule(existing.ruleId);
      }
    } catch (err) {
      onToast?.(`Preset action failed: ${err.message || "unknown error"}`, "error");
    } finally {
      setPresetBusy(null);
    }
  };

  const handleRuleToggle = async (ruleId) => {
    setRuleBusy(ruleId);
    try {
      await onToggleRule(ruleId);
    } catch (err) {
      onToast?.(`Unable to toggle rule: ${err.message || "unknown"}`, "error");
    } finally {
      setRuleBusy(null);
    }
  };

  const handleRuleDelete = async (ruleId) => {
    setDeleteBusy(ruleId);
    try {
      await onDeleteRule(ruleId);
    } catch (err) {
      onToast?.(`Delete failed: ${err.message || "unknown"}`, "error");
    } finally {
      setDeleteBusy(null);
    }
  };

  return (
    <div className="page-enter module-page">
      <ModuleHeader eyebrow="YOUR NETWORK UNDER WATCH." title="Network" subtitle="Understand traffic, security alerts, and unusual network behavior." actions={<Btn variant="primary" onClick={onToggleCapture}><Icon name="network" size={16}/>{captureRunning?'Stop capture':'Start monitoring'}</Btn>} />
      <div className="protection-banner"><span className="protection-icon"><Icon name="shield" size={22}/></span><div><strong>{captureRunning?'Your network is under watch':'Your network workspace is ready'}</strong><p>{captureRunning?'GhostNet is capturing traffic and checking your active detection rules.':'Start monitoring to capture traffic and detect unusual network activity.'}</p></div><span className="protection-state"><span className={`status-dot ${captureRunning?'is-live':''}`}/>{captureRunning?'Monitoring active':'Capture idle'}</span></div>
      {/* Stats */}
      <Grid cols={4} gap={22} style={{ marginBottom:20 }}>
        <StatCard icon="📦" label="Packets Captured" value={capturePackets >= 1000 ? (capturePackets/1000).toFixed(1)+"K" : capturePackets}
          sub="This session" color="#2d6bff" />
        <StatCard icon="🚨" label="Total Alerts"   value={alerts.length}  sub="All time"    color="#e11d48" />
        <StatCard icon="⚡" label="Critical/High"  value={(alerts.filter(a => a.severity === "CRITICAL").length) + (alerts.filter(a => a.severity === "HIGH").length)} sub="Needs attention" color="#f59e0b" />
        <StatCard icon="📋" label="Active Rules"   value={idsRules.filter(r => r.active).length}    sub={`of ${idsRules.length} total`} color="#10b981" />
      </Grid>

      <div className="network-summary">
        <section className="network-summary-card"><span className="summary-tag">{captureRunning?'Monitoring':'Ready to monitor'}</span><h3>Network capture</h3><p>{capturePackets.toLocaleString()} packets captured<br/>Live packet inspection and protocol analysis</p><button className="summary-link" onClick={onToggleCapture}><span className={`status-dot ${captureRunning?'is-live':''}`}/>{captureRunning?'Stop monitoring':'Start monitoring'}<Icon name="arrow" size={15}/></button></section>
        <section className="network-summary-card"><span className="summary-tag">Detection</span><h3>Intrusion detection</h3><p>{idsRules.filter(r=>r.active).length} active rules · {idsRules.length} configured<br/>{alerts.filter(a=>a.status==='new').length} alerts awaiting review</p><button className="summary-link" onClick={()=>onNavigate('incidents')}>Investigate incidents<Icon name="arrow" size={15}/></button></section>
        <section className="network-summary-card"><span className="summary-tag">Exposure</span><h3>Vulnerability watch</h3><p>{(appState.vulnFindings||[]).filter(f=>f.status==='open').length} open findings<br/>{(appState.vulnScans||[]).length} assessments in scan history</p><button className="summary-link" onClick={()=>onNavigate('vuln')}>Review vulnerabilities<Icon name="arrow" size={15}/></button></section>
      </div>
      <div className="section-label">Traffic & detection tools</div>
      <Panel title="Live Traffic Analyzer" subtitle="Wireshark-style packet list and decode view" padding="0">
        <div style={{ borderBottom:"1.5px solid #253239", background:"#121e24", padding:"10px 14px", display:"flex", gap:12, alignItems:"center", flexWrap:"wrap" }}>
          {["TCP", "UDP", "ICMP", "OTHER"].map((proto) => (
            <span key={proto} style={{ display:"inline-flex", alignItems:"center", gap:6, fontFamily:"var(--font-mono)", fontSize:10, color:"#99aab2", background:"#10191e", border:"1px solid #34434b", borderRadius:99, padding:"3px 8px" }}>
              <span style={{ width:8, height:8, borderRadius:"50%", background:protoColor(proto), display:"inline-block" }} />
              {proto}
            </span>
          ))}
          <span style={{ marginLeft:"auto", fontFamily:"var(--font-mono)", fontSize:10, color:"#64748b" }}>
            Showing {packetRows.length} packets
          </span>
        </div>

        <div style={{ display:"grid", gridTemplateColumns:"1fr", minHeight:180 }}>
          <div style={{ overflow:"auto", maxHeight:400 }}>
            <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
              <thead style={{ position:"sticky", top:0, zIndex:2 }}>
                <tr style={{ background:"#19282e", borderBottom:"1.5px solid #2b5870" }}>
                  {["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"].map((h) => (
                    <th key={h} style={{ textAlign:"left", padding:"8px 10px", fontFamily:"var(--font-mono)", fontSize:10, color:"#93a7b1", textTransform:"uppercase", letterSpacing:"0.04em", whiteSpace:"nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {packetRows.length === 0 ? (
                  <tr><td colSpan={7} style={{ padding:"24px 12px", color:"#64748b", textAlign:"center" }}>No packet frames yet. Start capture to inspect traffic.</td></tr>
                ) : packetRows.map((r, idx) => {
                  const selected = idx === selectedPacketIdx;
                  return (
                    <tr
                      key={idx}
                      onClick={() => setSelectedPacketIdx(idx)}
                      style={{
                        cursor:"pointer",
                        background:selected ? "#18372c" : idx % 2 ? "#111c22" : "#10191e",
                        borderBottom:"1px solid #223039",
                      }}
                    >
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#64748b" }}>{r.no}</td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#a6b8c1", whiteSpace:"nowrap" }}>{r.time}</td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#dce6e8" }}>{r.src}</td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#dce6e8" }}>{r.dst}</td>
                      <td style={{ padding:"7px 10px" }}>
                        <span style={{ fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700, color:protoColor(r.protocol), background:protoColor(r.protocol)+"20", border:`1px solid ${protoColor(r.protocol)}55`, borderRadius:99, padding:"2px 7px" }}>{r.protocol}</span>
                      </td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#a6b8c1" }}>{r.length}</td>
                      <td style={{ padding:"7px 10px", color:"#a6b8c1", whiteSpace:"nowrap", maxWidth:260, overflow:"hidden", textOverflow:"ellipsis" }}>{r.info}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ background:"#121e24", padding:"12px 14px", borderTop:"1.5px solid #253239", marginTop:16 }}>
          <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13, color:"#c5d3d8", marginBottom:10 }}>Packet Detail</div>
            {selectedPacket ? (
              <>
                <div style={{ background:"#121e24", border:"1px solid #2b5870", borderRadius:10, padding:"10px 12px", marginBottom:10 }}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", textTransform:"uppercase" }}>Frame</div>
                  <div style={{ marginTop:6, fontSize:12, color:"#dce6e8", lineHeight:1.6 }}>
                    Frame {selectedPacket.no}: {selectedPacket.length} bytes on wire<br />
                    Arrival Time: {selectedPacket.time}<br />
                    Encapsulation: Ethernet II / IPv4
                  </div>
                </div>
                <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:10, padding:"10px 12px", marginBottom:10 }}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", textTransform:"uppercase" }}>Internet Protocol</div>
                  <div style={{ marginTop:6, fontSize:12, color:"#dce6e8", lineHeight:1.6 }}>
                    Source: {selectedPacket.src}<br />
                    Destination: {selectedPacket.dst}<br />
                    TTL: 64 (estimated)
                  </div>
                </div>
                <div style={{ background:"#121e24", border:"1px solid #253239", borderRadius:10, padding:"10px 12px" }}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", textTransform:"uppercase" }}>Transport / Application</div>
                  <div style={{ marginTop:6, fontSize:12, color:"#dce6e8", lineHeight:1.6 }}>
                    Protocol: {selectedPacket.protocol}<br />
                    Port: {selectedPacket.port}<br />
                    Info: {selectedPacket.info}
                  </div>
                </div>
              </>
            ) : (
              <div style={{ color:"#64748b", fontSize:12 }}>Select a packet row to inspect decoded details.</div>
            )}
          </div>
      </Panel>

      {/* IDS Rules */}
      <div style={{ marginTop: 24 }}>
        <Panel title="Predefined IDS Profiles" subtitle="One-click activation of common signatures" padding="0">
          <div style={{ padding: "16px" }}>
            <Grid cols={2} gap={12}>
              {PRESET_IDS_RULES.map((preset) => {
                const existing = idsRules.find(r => r.ruleName === preset.rule.ruleName);
                const isActive = existing?.active;
                const actionLabel = !existing ? "Activate" : isActive ? "Deactivate" : "Activate";
                return (
                  <div key={preset.slug} style={{
                    border: "1.5px solid var(--color-border)",
                    borderRadius: "var(--r-lg)",
                    padding: "14px 16px",
                    background: "var(--color-surface)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 13, color: "var(--color-text-primary)" }}>{preset.label}</div>
                        <div style={{ fontSize: 11, color: "var(--color-text-tertiary)" }}>{preset.description}</div>
                      </div>
                      <Badge size="xs" severity={sev[ preset.rule.severity ] || "Medium"} label={sev[preset.rule.severity] || "Medium"} />
                    </div>
                    <Btn
                      size="sm"
                      variant={isActive ? "danger" : "outline"}
                      onClick={() => handlePresetAction(preset)}
                      disabled={presetBusy === preset.slug}
                    >
                      {presetBusy === preset.slug ? "Working..." : actionLabel}
                    </Btn>
                    {existing && (
                      <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--color-text-tertiary)" }}>
                        Rule #{existing.ruleId} · {existing.active ? "Active" : "Disabled"}
                      </div>
                    )}
                  </div>
                );
              })}
            </Grid>
          </div>
        </Panel>
      </div>

      <div style={{ marginTop: 20 }}>
        <Panel title="Active IDS Rules" subtitle="Toggle or delete live detection signatures" padding="0">
          {(!idsRules || idsRules.length === 0) ? (
            <EmptyState icon="🛑" title="No IDS rules" sub="Add or activate presets to begin inspection" />
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ background: "#19282e", borderBottom: "1px solid #253239" }}>
                    {['Name','Type','Severity','Patterns','Status','Actions'].map((col) => (
                      <th key={col} style={{ textAlign: "left", padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#93a7b1", textTransform: "uppercase", letterSpacing: "0.05em" }}>{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {idsRules.map((rule) => (
                    <tr key={rule.ruleId} style={{ borderBottom: "1px solid #223039" }}>
                      <td style={{ padding: "10px 14px" }}>
                        <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>{rule.ruleName}</div>
                        <div style={{ fontSize: 11, color: "var(--color-text-tertiary)" }}>SID {rule.ruleId}</div>
                      </td>
                      <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 11 }}>{(rule.ruleType || "custom").toUpperCase()}</td>
                      <td style={{ padding: "10px 14px" }}>
                        <span style={{
                          fontSize: 11,
                          fontFamily: "var(--font-mono)",
                          padding: "2px 8px",
                          borderRadius: 99,
                          background: (sevColor[rule.severity] || "#64748b") + "25",
                          color: sevColor[rule.severity] || "#64748b",
                        }}>{sev[rule.severity] || "Unknown"}</span>
                      </td>
                      <td style={{ padding: "10px 14px", fontSize: 11, color: "var(--color-text-tertiary)", fontFamily: "var(--font-mono)" }}>
                        {(rule.portPattern || rule.protocolPattern || rule.payloadPattern || "-")}
                      </td>
                      <td style={{ padding: "10px 14px" }}>
                        <Badge size="xs" status={rule.active ? "active" : "inactive"} />
                      </td>
                      <td style={{ padding: "10px 14px", display: "flex", gap: 8 }}>
                        <Btn
                          size="xs"
                          variant={rule.active ? "ghost" : "success"}
                          onClick={() => handleRuleToggle(rule.ruleId)}
                          disabled={ruleBusy === rule.ruleId}
                        >
                          {ruleBusy === rule.ruleId ? "Saving..." : rule.active ? "Deactivate" : "Activate"}
                        </Btn>
                        <Btn
                          size="xs"
                          variant="danger"
                          onClick={() => handleRuleDelete(rule.ruleId)}
                          disabled={deleteBusy === rule.ruleId}
                        >
                          {deleteBusy === rule.ruleId ? "Removing..." : "Delete"}
                        </Btn>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
