import definitions from '../../../backend/src/main/resources/windows-events.json' with {type:'json'};

export const EVENT_DEFINITIONS = definitions;
const normalize = value => String(value ?? '').trim().toLowerCase();
const catalog = new Map(definitions.map(entry => [`${normalize(entry.source)}|${normalize(entry.channel)}|${entry.eventId}`,entry]));
const auditCatalog = new Map(definitions.filter(entry=>entry.channel==='Security').map(entry=>[entry.eventId,entry]));
export const eventKey = event => `${normalize(event.source)}|${normalize(event.channel)}|${event.eventId}`;

export function findEventDefinition(event) {
  const exact = catalog.get(eventKey(event));
  if (exact) return exact;
  if (normalize(event.channel)==='security' && (!normalize(event.source)||normalize(event.source)==='microsoft-windows-security-auditing')) {
    return auditCatalog.get(Number(event.eventId));
  }
  return undefined;
}

export function eventName(event) {
  const known = findEventDefinition(event);
  if (known) return known.name;
  const message = String(event.message ?? '').trim();
  const bracketed = message.match(/^\[([^\]]+)\]/)?.[1];
  const prefix = bracketed || message.split(/\||\r?\n/)[0].trim();
  if (prefix && prefix.length <= 160 && !/[=<>]/.test(prefix) && !/^(unknown|event\s*\d+|n\/a)/i.test(prefix)) return prefix;
  return `${String(event.source || event.channel || 'Windows').trim()} · Event ${event.eventId ?? 'ID unavailable'}`;
}

export function eventProvider(event) {
  return event.source?.trim() || findEventDefinition(event)?.source || 'Provider not recorded';
}

export function eventLevel(event) {
  if (event.level && normalize(event.level)!=='unknown') return event.level;
  const code = String(event.rawXml||'').match(/<(?:\w+:)?Level>\s*(\d+)\s*<\//)?.[1];
  return ({0:'LogAlways',1:'Critical',2:'Error',3:'Warning',4:'Information',5:'Verbose'})[code]
    || (code ? `Level ${code}` : 'Not recorded');
}
