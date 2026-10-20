import {test} from 'node:test';
import assert from 'node:assert/strict';
import {eventName,eventProvider,eventKey,eventLevel,EVENT_DEFINITIONS} from '../src/utils/windowsEvents.js';

test('common system events get names and retain the actual provider',()=>{
  const event={eventId:7036,channel:'System',source:'Service Control Manager'};
  assert.equal(eventName(event),'Service state changed');
  assert.equal(eventProvider(event),'Service Control Manager');
});
test('same numeric code resolves independently by provider and channel',()=>{
  assert.equal(eventName({eventId:1001,channel:'Application',source:'Windows Error Reporting'}),'Windows error report generated');
  assert.equal(eventName({eventId:1001,channel:'System',source:'Microsoft-Windows-WER-SystemErrorReporting'}),'System restarted after a bug check');
  assert.notEqual(eventKey({eventId:1,source:'a',channel:'System'}),eventKey({eventId:1,source:'b',channel:'System'}));
});
test('an unlisted provider does not inherit another providers definition',()=>{
  assert.equal(eventName({eventId:4624,source:'CustomProvider',channel:'Application',message:'User=alice'}),'CustomProvider · Event 4624');
});
test('real descriptions and missing messages have useful fallbacks',()=>{
  assert.equal(eventName({eventId:999,source:'CustomProvider',message:'[Backup completed] path=x'}),'Backup completed');
  assert.equal(eventName({eventId:999,channel:'System',message:null}),'System · Event 999');
  assert.equal(eventProvider({eventId:999}),'Provider not recorded');
});
test('logoff uses 4634 and catalog keys are unique',()=>{
  assert.match(eventName({eventId:'4634',channel:'Security',source:'Microsoft-Windows-Security-Auditing'}),/logged off/i);
  assert.equal(new Set(EVENT_DEFINITIONS.map(eventKey)).size,EVENT_DEFINITIONS.length);
});
test('previously stored unknown levels resolve from the original XML',()=>{
  assert.equal(eventLevel({level:'Unknown',rawXml:'<Event><System><Level>0</Level></System></Event>'}),'LogAlways');
  assert.equal(eventLevel({level:'Unknown',rawXml:'<Level>42</Level>'}),'Level 42');
  assert.equal(eventLevel({level:'Unknown'}),'Not recorded');
});
