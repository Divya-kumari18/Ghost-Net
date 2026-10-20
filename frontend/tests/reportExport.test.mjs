import test from 'node:test';
import assert from 'node:assert/strict';
import {createReportBlob,reportModel} from '../src/utils/reportExport.js';
const template={name:'Security Summary',type:'security'};
const snapshot={since:'2026-10-10T12:00:00Z',until:'2026-10-11T12:00:00Z',generatedAt:'2026-10-11T12:00:00Z',days:1,summary:{alerts:120,openIncidents:18,infectedFiles:2,criticalVulns:4},coverage:{alerts:{included:1,total:120}},data:{alerts:[{alertId:1,alertMessage:'=HYPERLINK("evil") <script>bad</script>',severity:'high'}]}};
test('exports database totals independently of detail limits',()=>{
  const report=reportModel(template,snapshot);assert.equal(report.summary.alerts,120);assert.equal(report.sections[0].rows.length,1);assert.equal(report.sections[0].coverage.total,120);
});
test('HTML escapes evidence and reports truncated coverage',async()=>{
  const html=await createReportBlob(template,'html',snapshot).blob.text();assert.ok(html.includes('120 records included'));assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));assert.ok(html.includes('2026-10-10T12:00:00.000Z'));
});
test('CSV protects formula cells and includes actual alert text',async()=>{
  const csv=await createReportBlob(template,'csv',snapshot).blob.text();assert.ok(csv.includes("\"'=HYPERLINK"));assert.ok(csv.includes('alertMessage'));assert.ok(csv.includes('120'));
});
test('Windows export includes all loaded events and resolved names',async()=>{
  const data={...snapshot,data:{winEvents:Array.from({length:25},(_,i)=>({logId:i,eventId:7036,channel:'System',source:'Service Control Manager',level:'Unknown',rawXml:'<Level>0</Level>'}))}};
  const report=reportModel({name:'Windows Event Report',type:'windows-events'},data);assert.equal(report.sections[0].rows.length,25);assert.equal(report.sections[0].rows[0].eventName,'Service state changed');assert.equal(report.sections[0].rows[0].level,'LogAlways');
});
test('requires a database snapshot rather than falling back to partial UI data',()=>assert.throws(()=>reportModel(template,null)));
test('long PDF evidence paginates and retains the final record',async()=>{
  const data={...snapshot,data:{incidents:Array.from({length:30},(_,i)=>({title:`Evidence record ${i}`,description:'Long evidence '.repeat(30),status:'open'}))}};
  const pdf=await createReportBlob(template,'pdf',data).blob.text();assert.ok(pdf.includes('Evidence record 29'));assert.ok(pdf.includes('Page 2 of'));
});
