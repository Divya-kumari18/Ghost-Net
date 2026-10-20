import { useEffect, useState } from 'react';

import { Panel, Btn, FormGroup, ModuleHeader } from '../components/UI.jsx';

import { systemSettings, integrations } from '../api/client.js';

export default function Settings({currentUser,onToast,onNavigate}) {

  const [settings,setSettings]=useState(null);

  const [services,setServices]=useState(null);

  const [checking,setChecking]=useState(null);

  const [drafts,setDrafts]=useState({});

  const [saving,setSaving]=useState(null);

  const editService=(id,change)=>setDrafts(previous=>({...previous,[id]:{...previous[id],...change}}));

  const saveService=async(id)=>{

    setSaving(id);

    try {const draft={...services[id],...drafts[id]};const result=await integrations.save(id,{enabled:!!draft.enabled,baseUrl:draft.baseUrl,apiKey:draft.apiKey||'',clearApiKey:!!draft.clearApiKey});setServices(previous=>({...previous,[id]:result}));setDrafts(previous=>({...previous,[id]:{}}));onToast('Integration saved; new requests use the updated configuration','success');}

    catch(err){onToast(err.message,'error');}finally{setSaving(null);}

  };

  const [serviceError,setServiceError]=useState('');

  useEffect(()=>{integrations.status().then(setServices).catch(err=>setServiceError(err.message));},[]);

  const checkService=async(id)=>{

    setChecking(id);

    try { const result=await integrations.check(id); setServices(previous=>({...previous,[id]:{...previous[id],...result}})); }

    catch(err) {onToast(err.message,'error');}

    finally {setChecking(null);}

  };

  const [font,setFont]=useState(Number(localStorage.getItem('ghostnet.fontSize')||14));

  useEffect(()=>{systemSettings.get().then(setSettings).catch(err=>onToast(err.message,'error'));},[]);

  useEffect(()=>{document.body.style.fontSize=`${font}px`;localStorage.setItem('ghostnet.fontSize',String(font));},[font]);

  const admin=currentUser?.role==='admin';

  return <div className="module-page settings-page">

    <ModuleHeader eyebrow="CONTROL PLANE" title="Settings" subtitle="Effective server policy and local display preferences"/>

    <Panel title="Account"><div style={{padding:20}}>{currentUser?.username} · {currentUser?.email} · {currentUser?.role}{admin&&<Btn onClick={()=>onNavigate('users')}>Manage users</Btn>}</div></Panel>

    <Panel title="Display"><div style={{padding:20}}><FormGroup label="Font size"><input type="number" min="10" max="22" value={font} onChange={e=>setFont(Math.max(10,Math.min(22,Number(e.target.value))))}/></FormGroup></div></Panel>

    <Panel title="Detection and retention policy">

      {settings&&<div style={{padding:20}}>

        <FormGroup label="Malware model confidence threshold (%)"><input type="number" min="50" max="100" disabled={!admin} value={settings.criticalThreshold} onChange={e=>setSettings({...settings,criticalThreshold:Number(e.target.value)})}/></FormGroup>

        <FormGroup label="Raw telemetry retention (days)"><input type="number" min="1" max="3650" disabled={!admin} value={settings.retentionHotDays} onChange={e=>setSettings({...settings,retentionHotDays:Number(e.target.value)})}/></FormGroup>

        <label><input type="checkbox" disabled={!admin} checked={settings.retentionEnabled} onChange={e=>setSettings({...settings,retentionEnabled:e.target.checked})}/> Enable raw telemetry cleanup</label>

        <p>This policy applies to packet metadata and Windows events that did not generate alerts. Security evidence and incident timelines remain available.</p>

        <p>Last updated by: {settings.updatedBy||'Default policy'} {settings.updatedAt||''}</p>

        {admin&&<Btn onClick={async()=>{try{setSettings(await systemSettings.save(settings));onToast('Server policy saved','success');}catch(err){onToast(err.message,'error');}}}>Save server policy</Btn>}

      </div>}

    </Panel>

    <Panel title="Security integrations" subtitle="Backend credentials and live connection checks">

      {serviceError && <p role="alert" style={{padding:20,color:'#fda4af'}}>{serviceError}</p>}

      <div className="integration-grid">

        {[{id:'zap',name:'OWASP ZAP',description:'Web vulnerability assessments against your authorized targets.',variable:'GHOSTNET_ZAP_API_KEY'},

          {id:'virustotal',name:'VirusTotal',description:'Uploaded malware-scan files are sent to VirusTotal for analysis when enabled. Submitted files may be retained or shared by VirusTotal.',variable:'GHOSTNET_VIRUSTOTAL_API_KEY'}].map(service=>{

          const state=services?.[service.id];

          const draft={...state,...drafts[service.id]};

          const dirty=Object.keys(drafts[service.id]||{}).length>0;

          return <section className="integration-card" key={service.id}>

            <h3>{service.name}</h3><p>{service.description}</p>

            <div role="status" style={{color:state?.connected?'#6ee7d8':'#fcd34d',marginBottom:12}}>{state?.message||'Loading configuration…'}</div>

            {state?.checkedAt&&<small>Checked {new Date(state.checkedAt).toLocaleString()}</small>}

            {state&&<div style={{marginTop:16}}>

              <label><input type="checkbox" aria-label={`${service.name} enabled`} disabled={!admin||saving!==null} checked={!!draft.enabled} onChange={e=>editService(service.id,{enabled:e.target.checked})}/> Enabled</label>

              <FormGroup label="Service endpoint"><input aria-label={`${service.name} endpoint`} type="url" disabled={!admin||saving!==null} value={draft.baseUrl||''} onChange={e=>editService(service.id,{baseUrl:e.target.value})}/></FormGroup>

              {admin&&<>

                <FormGroup label="API key"><input aria-label={`${service.name} API key`} type="password" autoComplete="new-password" disabled={saving!==null} placeholder={state.configured?'Saved key - leave blank to keep':'Enter API key'} value={draft.apiKey||''} onChange={e=>editService(service.id,{apiKey:e.target.value,clearApiKey:false})}/></FormGroup>

                <label><input type="checkbox" checked={!!draft.clearApiKey} disabled={saving!==null} onChange={e=>editService(service.id,{clearApiKey:e.target.checked,apiKey:''})}/> Remove saved key</label>

                <div style={{display:'flex',gap:8,marginTop:16,flexWrap:'wrap'}}>

                  <Btn disabled={!dirty||saving!==null||checking!==null} onClick={()=>saveService(service.id)}>{saving===service.id?'Saving…':'Save configuration'}</Btn>

                  <Btn disabled={checking!==null||saving!==null||dirty||!state.enabled||!state.configured} onClick={()=>checkService(service.id)}>{checking===service.id?'Checking…':'Test connection'}</Btn>

                  {dirty&&<Btn variant="ghost" disabled={saving!==null} onClick={()=>setDrafts(previous=>({...previous,[service.id]:{}}))}>Cancel edits</Btn>}

                </div>

                <p style={{fontSize:12}}>Saved keys are encrypted on the backend and never returned to the browser. Save changes before testing. No restart is needed.</p>

              </>}

            </div>}

          </section>;

        })}

      </div>

      <p style={{padding:'0 20px 20px',color:'var(--color-text-secondary)',fontSize:12}}>Connection checks contact the configured service. VirusTotal connection checks validate reputation lookup only; file upload access may depend on your account plan. Uploads and analysis polling consume API quota, and submitted samples may be shared. Keys stay on the backend.</p>

    </Panel>

  </div>;

}
