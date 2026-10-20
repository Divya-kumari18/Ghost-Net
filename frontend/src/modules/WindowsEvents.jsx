import { useMemo, useState } from "react";
import { Panel, Grid, StatCard, Badge, DataTable, EmptyState, ModuleHeader } from "../components/UI.jsx";

import { EVENT_DEFINITIONS, eventName, eventProvider, eventKey, eventLevel } from "../utils/windowsEvents.js";
import { fmtTime } from "../utils/dateFormatter.js";

const EVENT_SEVERITY = {
  4625:{ sev:"HIGH",     color:"#e11d48" },
  7045:{ sev:"CRITICAL", color:"#e11d48" },
  4688:{ sev:"HIGH",     color:"#f59e0b" },
  4740:{ sev:"HIGH",     color:"#e11d48" },
  4698:{ sev:"CRITICAL", color:"#e11d48" },
  4720:{ sev:"MEDIUM",   color:"#8b5cf6" },
  4672:{ sev:"HIGH",     color:"#f59e0b" },
  4624:{ sev:"INFO",     color:"#10b981" },
  7036:{ sev:"INFO",     color:"#0ea5e9" },
};

const CHANNEL_COLORS = {
  Security:    { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  System:      { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd" },
  Application: { bg:"#f5f3ff", text:"#6d28d9", border:"#ddd6fe" },
};

export default function WindowsEvents({ appState }) {
  const { winEvents } = appState;
  const [referenceQuery,setReferenceQuery]=useState('');
  const [referencePage,setReferencePage]=useState(0);
  const referenceMatches=useMemo(()=>EVENT_DEFINITIONS.filter(entry=>`${entry.eventId} ${entry.name} ${entry.source} ${entry.channel}`.toLowerCase().includes(referenceQuery.toLowerCase().trim())),[referenceQuery]);
  const referenceRows=referenceMatches.slice(referencePage*15,(referencePage+1)*15);
  const total     = winEvents.length;
  const security  = winEvents.filter(e => e.securityRelevant).length;
  const failed    = winEvents.filter(e => Number(e.eventId) === 4625 && e.channel === "Security").length;
  const critical  = winEvents.filter(e => [7045,4740,4698].includes(Number(e.eventId))).length;

  // Providers can reuse an ID; keep distinct events separate in frequency counts.
  const counts=new Map();
  winEvents.forEach(event=>{const key=eventKey(event);const row=counts.get(key)||{key,event,count:0};row.count++;counts.set(key,row);});
  const topIds=Array.from(counts.values()).sort((a,b)=>b.count-a.count).slice(0,8);

  return (
    <div className="page-enter module-page">
      <ModuleHeader eyebrow="LOG INGEST" title="Windows events" subtitle="Security, system, and application events correlated from the host event stream" />
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        <StatCard icon="📋" label="Loaded events" value={total}   sub="Current loaded records"   color="#2d6bff" />
        <StatCard icon="🔐" label="Security Events"    value={security} sub="Relevant events" color="#7c3aed" />
        <StatCard icon="🚫" label="Failed Logins"      value={failed}   sub="Event ID 4625"  color="#e11d48" />
        <StatCard icon="⚡" label="Critical Events"    value={critical} sub="Needs review"   color="#f59e0b" />
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        {/* Live Stream */}
        <Panel title="Live Event Stream"
          subtitle="Windows Event Log API · Polling every 5s"
          actions={
            <div style={{ display:"flex", gap:6 }}>
              {["Security","System","Application"].map(ch => {
                const c = CHANNEL_COLORS[ch];
                return (
                  <span key={ch} style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                    padding:"2px 7px", borderRadius:99, background:c.bg, color:c.text, border:`1px solid ${c.border}` }}>
                    {ch}
                  </span>
                );
              })}
            </div>
          }
        >
          <div style={{ maxHeight:300, overflowY:"auto" }}>
            {winEvents.length === 0 ? (
              <EmptyState icon="🪟" title="No events yet" sub="Windows Event reader polling…" />
            ) : (
              winEvents.map(e => {
                const meta = EVENT_SEVERITY[e.eventId] || { sev:"INFO", color:"#94a3b8" };
                const ch   = CHANNEL_COLORS[e.channel] || CHANNEL_COLORS.Application;
                return (
                  <div key={e.logId} style={{
                    display:"flex", gap:10, alignItems:"flex-start",
                    padding:"8px 14px", borderBottom:"1px solid #223039",
                  }}>
                    <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
                      color:"var(--color-text-tertiary)", flexShrink:0, marginTop:1, minWidth:55 }}>
                      {fmtTime(e.eventTime)}
                    </span>
                    <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                      padding:"2px 6px", borderRadius:99, background:ch.bg, color:ch.text,
                      border:`1px solid ${ch.border}`, flexShrink:0 }}>
                      {e.channel}
                    </span>
                    <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700,
                      color: meta.color, flexShrink:0, minWidth:36 }}>{e.eventId}</span>
                    <span style={{ fontSize:12, color:"var(--color-text-secondary)",
                      lineHeight:1.5, overflow:"hidden" }}>
                      <strong style={{display:"block",color:"var(--color-text-primary)",fontWeight:500}}>{eventName(e)}</strong>
                      {String(e.message||"No event payload recorded").substring(0,90)}{String(e.message||"").length > 90 ? "…" : ""}
                    </span>
                    {e.securityRelevant && (
                      <span style={{ fontSize:9, fontFamily:"var(--font-mono)", fontWeight:700,
                        color:"#be123c", background:"#fff1f2", border:"1px solid #fecdd3",
                        padding:"2px 6px", borderRadius:99, flexShrink:0, marginTop:1 }}>
                        SEC
                      </span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </Panel>

        {/* Top Event IDs */}
        <Panel title="Top event codes" subtitle="Frequency analysis">
          <div style={{ padding:"0 4px" }}>
            {topIds.length === 0 ? (
              <EmptyState icon="📊" title="No data" sub="Events will appear after polling" />
            ) : (
              topIds.map(({key,event,count}) => {
                const id=event.eventId;
                const meta = EVENT_SEVERITY[+id] || { sev:"INFO", color:"#94a3b8" };
                const pct  = (count / (topIds[0]?.count || 1)) * 100;
                return (
                  <div key={key} style={{ padding:"10px 14px", borderBottom:"1px solid #223039" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:5 }}>
                      <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700,
                        color:meta.color, minWidth:40 }}>{id}</span>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:12, color:"var(--color-text-secondary)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          {eventName(event)}
                        </div>
                        <div style={{ fontSize:10, color:"var(--color-text-tertiary)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          {eventProvider(event)}
                        </div>
                      </div>
                      <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700,
                        color:"var(--color-text-primary)" }}>{count}</span>
                      <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                        padding:"2px 7px", borderRadius:99,
                        background:meta.color+"15", color:meta.color, border:`1px solid ${meta.color}33` }}>
                        {meta.sev}
                      </span>
                    </div>
                    <div style={{ height:3, background:"#1b2937", borderRadius:99, overflow:"hidden" }}>
                      <div style={{ height:"100%", width:`${pct}%`, background:meta.color,
                        borderRadius:99, transition:"width 0.5s ease" }} />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </Panel>
      </Grid>

      {/* Full Event Log Table */}
      <Panel title="Event Log Table" subtitle="Full Windows Event Log entries">
        <DataTable
          columns={[
            { label:"Time",      render: r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11 }}>{fmtTime(r.eventTime)}</span> },
            { label:"Channel",   render: r => {
              const c = CHANNEL_COLORS[r.channel] || CHANNEL_COLORS.Application;
              return <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                padding:"2px 7px", borderRadius:99, background:c.bg, color:c.text, border:`1px solid ${c.border}` }}>{r.channel}</span>;
            }},
            { label:"Event ID",  render: r => <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700,
              color: (EVENT_SEVERITY[r.eventId]||{}).color || "#94a3b8" }}>{r.eventId}</span> },
            { label:"Event Name", render: r => <span style={{ fontSize:12, color:"var(--color-text-secondary)" }}>
              {eventName(r)}</span>, wrap:true, maxWidth:"240px" },
            { label:"Level",     render: r => <Badge label={eventLevel(r)} status={eventLevel(r).toLowerCase()} /> },
            { label:"Provider / Source", render: r => <span style={{ fontSize:11, color:"var(--color-text-secondary)" }}>
              {eventProvider(r)}</span> },
            { label:"Computer",  key:"computerName", mono:true, dim:true },
            { label:"Message",   render: r => <span style={{ fontSize:12, color:"var(--color-text-secondary)" }}>
              {String(r.message||"No event payload recorded").substring(0,70)}{String(r.message||"").length > 70 ? "…" : ""}</span>, wrap:true, maxWidth:"260px" },
            { label:"Security",  render: r => r.securityRelevant
              ? <span style={{ fontSize:9, fontFamily:"var(--font-mono)", fontWeight:700, color:"#be123c",
                  background:"#fff1f2", border:"1px solid #fecdd3", padding:"2px 6px", borderRadius:99 }}>⚠ YES</span>
              : <span style={{ fontSize:11, color:"var(--color-text-tertiary)" }}>—</span>
            },
          ]}
          rows={winEvents}
          emptyText="No events yet — Windows Event reader polling…"
        />
      </Panel>
      <div style={{marginTop:24}}><Panel title="Event code reference" subtitle={`${EVENT_DEFINITIONS.length} provider-specific definitions · reference only, not generated activity`}>
        <div style={{padding:18}}><input aria-label="Search event codes" placeholder="Search a code, name, or provider — e.g. 4625, service, PowerShell" value={referenceQuery} onChange={e=>{setReferenceQuery(e.target.value);setReferencePage(0);}}/></div>
        <DataTable columns={[{label:'Code',key:'eventId',mono:true},{label:'Event name',key:'name',wrap:true},{label:'Channel',key:'channel',wrap:true},{label:'Provider',key:'source',wrap:true}]} rows={referenceRows} emptyText="No matching event definitions"/>
        <div style={{padding:18,display:'flex',alignItems:'center',gap:12,flexWrap:'wrap',color:'var(--color-text-secondary)',fontSize:12}}>
          <span>{referenceMatches.length} matching definitions · Page {referencePage+1} of {Math.max(1,Math.ceil(referenceMatches.length/15))}</span>
          <button className="summary-link" style={{marginTop:0}} disabled={referencePage===0} onClick={()=>setReferencePage(p=>p-1)}>Previous codes</button>
          <button className="summary-link" style={{marginTop:0}} disabled={(referencePage+1)*15>=referenceMatches.length} onClick={()=>setReferencePage(p=>p+1)}>Next codes</button>
        </div>
      </Panel></div>
    </div>
  );
}
