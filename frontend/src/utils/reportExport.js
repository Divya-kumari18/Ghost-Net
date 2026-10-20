import { jsPDF } from 'jspdf';
import { eventName, eventLevel, eventProvider } from './windowsEvents.js';

const htmlEscape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const csvCell=value=>'"'+(/^[\s]*[=+@-]/.test(String(value??''))?"'":"")+String(value??'').replace(/"/g,'""')+'"';
const iso=value=>value?new Date(value).toISOString():'Not recorded';
const columns={
  alerts:['alertId','timestamp','alertType','severity','sourceIp','destinationIp','alertMessage','protocol','status'],
  incidents:['incidentNumber','title','severity','status','createdAt','description','affectedAssets'],
  malwareScans:['scanId','fileName','scanTime','scanResult','scanEngine','threatName','virustotalPositives','virustotalTotal','quarantined','fileHash'],
  vulnFindings:['findingId','hostIp','vulnerabilityName','severity','status','cveId','cweId','createdAt','description','remediation'],
  winEvents:['logId','eventId','eventName','channel','level','source','computerName','userName','eventTime','securityRelevant','message'],
};
const labels={alerts:'Network alerts',incidents:'Incidents',malwareScans:'Malware scan results',vulnFindings:'Vulnerability findings',winEvents:'Windows events'};
export function reportModel(template,snapshot) {
  if(!snapshot?.summary||!snapshot?.since||!snapshot?.until)throw new Error('A fresh database snapshot is required');
  const keys=template.type==='windows-events'?['winEvents']:template.type==='vulnerability'?['vulnFindings']:template.type==='compliance'?['incidents','winEvents']:['alerts','incidents','malwareScans','vulnFindings'];
  return {title:template.name,type:template.type,generatedAt:iso(snapshot.generatedAt||snapshot.until),since:iso(snapshot.since),until:iso(snapshot.until),days:snapshot.days,summary:snapshot.summary,
    checks:snapshot.checks||[],sections:keys.map(key=>({key,title:labels[key],columns:columns[key],coverage:snapshot.coverage?.[key],rows:(snapshot.data?.[key]||[]).map(row=>key==='winEvents'?{...row,eventName:eventName(row),level:eventLevel(row),source:eventProvider(row)}:row)}))};
}
export function createReportBlob(template,format,snapshot) {
  const report=reportModel(template,snapshot);
  const name=`${template.name.replace(/\s+/g,'_')}_${report.generatedAt.replace(/[:.]/g,'-')}`;
  const metrics=report.type==='windows-events'
    ? [['Windows events',report.summary.windowsEvents],['Security-relevant events',report.summary.windowsSecurityEvents],['Events included in export',report.sections[0].rows.length],['Providers in included events',new Set(report.sections[0].rows.map(row=>row.source)).size]]
    : report.type==='vulnerability'
    ? [['Findings created in period',report.summary.vulnerabilityFindings],['Critical findings in period',report.summary.criticalVulns],['Findings included in export',report.sections[0].rows.length],['Hosts in included findings',new Set(report.sections[0].rows.map(row=>row.hostIp)).size]]
    : [['Alerts',report.summary.alerts],['Open incidents created in period',report.summary.openIncidents],['Infected scan results',report.summary.infectedFiles],['Critical findings created in period',report.summary.criticalVulns]];
  const period=`Period (UTC): ${report.since} to ${report.until}`;
  const fieldLabel=key=>key.replace(/([a-z])([A-Z])/g,'$1 $2').replace(/^./,c=>c.toUpperCase());
  const coverage=section=>`${section.rows.length} of ${section.coverage?.total??section.rows.length} records included${(section.coverage?.total??0)>section.rows.length?' (latest records only; export limit reached)':''}`;
  if(format==='json')return {blob:new Blob([JSON.stringify(report,null,2)],{type:'application/json'}),fileName:name+'.json',mime:'application/json'};
  if(format==='csv') {
    const lines=[['GhostNet',report.title],['Generated at (UTC)',report.generatedAt],['Period start (UTC)',report.since],['Period end (UTC)',report.until],[],['Metric','Count'],...metrics];
    for(const section of report.sections)lines.push([],[section.title,coverage(section)],section.columns,...section.rows.map(row=>section.columns.map(key=>row[key])));
    return {blob:new Blob(['\uFEFF'+lines.map(row=>row.map(csvCell).join(',')).join('\r\n')],{type:'text/csv'}),fileName:name+'.csv',mime:'text/csv'};
  }
  if(format==='html') {
    const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${htmlEscape(report.title)}</title><style>body{font:14px Arial,sans-serif;color:#20323a;margin:40px;line-height:1.5}header{border-bottom:4px solid #35ba95;padding-bottom:18px}h1{font-size:26px}h2{margin-top:28px}table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:11px}th,td{padding:8px;border:1px solid #d6e0e2;text-align:left;overflow-wrap:anywhere;vertical-align:top}th{background:#eaf5f1}small{color:#52646c}@media print{thead{display:table-header-group}tr{break-inside:avoid}body{margin:12mm}}</style></head><body><header><strong>GhostNet / Security Intelligence</strong><h1>${htmlEscape(report.title)}</h1><div>${htmlEscape(period)}</div><small>Generated (UTC): ${htmlEscape(report.generatedAt)}</small></header><h2>Database summary</h2><table><tr>${metrics.map(([label])=>`<th>${htmlEscape(label)}</th>`).join('')}</tr><tr>${metrics.map(([,value])=>`<td>${htmlEscape(value??0)}</td>`).join('')}</tr></table><p>Counts cover the selected period. Open incidents reflect their status at generation time. Infected results count scans, not unique files or confirmed quarantine actions.</p>${report.sections.map(section=>`<h2>${section.title}</h2><p>${htmlEscape(coverage(section))}</p>${section.rows.length?`<table><thead><tr>${section.columns.map(key=>`<th>${htmlEscape(fieldLabel(key))}</th>`).join('')}</tr></thead><tbody>${section.rows.map(row=>`<tr>${section.columns.map(key=>`<td>${htmlEscape(row[key])}</td>`).join('')}</tr>`).join('')}</tbody></table>`:'<p>No matching records in this period.</p>'}`).join('')}<footer><p>Confidential - generated from GhostNet database records. Absence of findings does not establish absence of threats.</p></footer></body></html>`;
    return {blob:new Blob([html],{type:'text/html'}),fileName:name+'.html',mime:'text/html'};
  }
  if(format!=='pdf')throw new Error('Unsupported report format');
  const doc=new jsPDF({unit:'pt',format:'a4'});
  const width=doc.internal.pageSize.getWidth(),height=doc.internal.pageSize.getHeight(),margin=42,contentWidth=width-2*margin;
  let y=42;
  // Built-in PDF fonts support Latin characters; normalize punctuation rather than corrupting it.
  const pdfText=value=>String(value??'Not recorded').replace(/[\u2010-\u2015]/g,'-').replace(/[\u2018\u2019]/g,"'").replace(/[\u201c\u201d]/g,'"').replace(/[^\x20-\x7E\xA0-\xFF\n\r\t]/g,'?');
  const page=()=>{doc.addPage();y=44;};
  const ensure=space=>{if(y+space>height-48)page();};
  const text=(value,{bold=false,size=10,color=[45,64,73],indent=0}={})=>{
    doc.setFont('helvetica',bold?'bold':'normal');doc.setFontSize(size);doc.setTextColor(...color);
    const lines=doc.splitTextToSize(pdfText(value),contentWidth-indent);
    for(const line of lines){ensure(size*1.4);doc.text(line,margin+indent,y);y+=size*1.4;}
    y+=4;
  };
  doc.setFillColor(15,32,39);doc.rect(0,0,width,95,'F');
  text('GHOSTNET / SECURITY INTELLIGENCE',{bold:true,size:11,color:[109,239,197]});
  text(report.title,{bold:true,size:22,color:[255,255,255]});y=119;
  text(period,{size:9});text(`Generated (UTC): ${report.generatedAt}`,{size:9});y+=10;
  text('Database summary',{bold:true,size:14});
  const gap=12,cardWidth=(contentWidth-gap)/2;
  metrics.forEach(([label,value],index)=>{
    const x=margin+(index%2)*(cardWidth+gap),top=y+Math.floor(index/2)*83;
    doc.setFillColor(235,246,241);doc.roundedRect(x,top,cardWidth,71,5,5,'F');
    doc.setFont('helvetica','normal');doc.setFontSize(9);doc.setTextColor(45,64,73);
    doc.text(doc.splitTextToSize(label,cardWidth-24),x+12,top+18);
    doc.setFont('helvetica','bold');doc.setFontSize(21);doc.text(String(value??0),x+12,top+56);
  });y+=180;
  text('Counts cover the selected period. Open incidents reflect their status at generation time. Infected results count scans, not unique files or confirmed quarantine actions.',{size:9});
  for(const section of report.sections){
    if(!section.rows.length){ensure(44);y+=8;text(section.title,{bold:true,size:11});text(`No matching records in this period. ${coverage(section)}.`,{size:9});continue;}
    ensure(82);y+=12;text(section.title,{bold:true,size:14});text(coverage(section),{size:9});
    section.rows.forEach((row,index)=>{
      ensure(55);text(`${index+1}. ${row.eventName||row.vulnerabilityName||row.title||row.fileName||row.alertType||section.title}`,{bold:true,size:11});
      for(const key of section.columns){if(row[key]!==undefined&&row[key]!==null&&row[key]!=='')text(`${fieldLabel(key)}: ${row[key]}`,{size:9,indent:8});}
      y+=8;
    });
  }
  if(report.sections.some(section=>section.rows.some(row=>section.columns.some(key=>/[^\x20-\x7E\xA0-\xFF\n\r\t\u2010-\u2015\u2018\u2019\u201c\u201d]/.test(String(row[key]??''))))))text('Some characters are outside this PDF font and appear as ?. Use HTML or JSON export for the original Unicode evidence.',{size:9});
  ensure(65);y+=12;text('Confidential - generated from GhostNet database records. Absence of findings does not establish absence of threats.',{size:9});
  const pages=doc.getNumberOfPages();
  for(let index=1;index<=pages;index++){doc.setPage(index);doc.setDrawColor(190,209,207);doc.line(margin,height-34,width-margin,height-34);doc.setFontSize(8);doc.setTextColor(72,91,98);doc.text('GhostNet | Confidential',margin,height-20);doc.text(`Page ${index} of ${pages}`,width-margin,height-20,{align:'right'});}
  return {blob:doc.output('blob'),fileName:name+'.pdf',mime:'application/pdf'};
}
