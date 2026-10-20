const shapes = {
  overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
  network: <path d="M2 12h4l3-8 5 16 3-8h5"/>,
  incidents: <><path d="m12 3 10 18H2Z"/><path d="M12 9v5m0 3v.1"/></>,
  malware: <><rect x="7" y="6" width="10" height="13" rx="4"/><path d="M9 3v3m6-3v3M3 9h4m10 0h4M3 14h4m10 0h4M5 21l3-3m8 0 3 3M12 7v11"/></>,
  vuln: <><path d="M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6Z"/><path d="M12 7v6m0 3v.1"/></>,
  honeypot: <><path d="m12 2 9 5v10l-9 5-9-5V7Zm0 0v20M3 7l9 5 9-5M7 4l10 6"/></>,
  events: <><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 13h2m3 0h5m-10 3h10"/></>,
  reports: <><path d="M6 2h8l4 4v16H6Zm8 0v5h4M9 12h6m-6 4h6"/></>,
  settings: <><path d="M3 6h18M3 12h18M3 18h18"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="9" cy="18" r="2"/></>,
  search: <><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></>,
  shield: <><path d="m12 2 9 4-1 9-8 7-8-7-1-9Z"/><path d="m8 12 3 3 5-6"/></>,
  arrow: <path d="M5 12h14m-5-5 5 5-5 5"/>,
};
export default function Icon({name='shield',size=20,...props}) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>{shapes[name]||shapes.shield}</svg>;
}
