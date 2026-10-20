// GhostNet Design System
// GhostNet control-room theme: graphite surfaces, cyan telemetry, amber risk.

export const colors = {
  primary:  { 50:'#f0f5ff', 100:'#e0eaff', 200:'#c1d4ff', 300:'#93b4ff', 400:'#5b8eff', 500:'#2d6bff', 600:'#1a52e0', 700:'#1340b8', 800:'#0f308f', 900:'#0b2270' },
  slate:    { 50:'#f8fafc', 100:'#f1f5f9', 200:'#e2e8f0', 300:'#cbd5e1', 400:'#94a3b8', 500:'#64748b', 600:'#475569', 700:'#334155', 800:'#1e293b', 900:'#0f172a' },
  red:      { 50:'#fff1f2', 100:'#ffe4e6', 200:'#fecdd3', 400:'#fb7185', 500:'#f43f5e', 600:'#e11d48', 700:'#be123c', 800:'#9f1239', 900:'#881337' },
  amber:    { 50:'#fffbeb', 100:'#fef3c7', 200:'#fde68a', 400:'#fbbf24', 500:'#f59e0b', 600:'#d97706', 700:'#b45309', 800:'#92400e', 900:'#78350f' },
  emerald:  { 50:'#ecfdf5', 100:'#d1fae5', 200:'#a7f3d0', 400:'#34d399', 500:'#10b981', 600:'#059669', 700:'#047857', 800:'#065f46', 900:'#064e3b' },
  sky:      { 50:'#f0f9ff', 100:'#e0f2fe', 200:'#bae6fd', 400:'#38bdf8', 500:'#0ea5e9', 600:'#0284c7', 700:'#0369a1', 800:'#075985', 900:'#0c4a6e' },
  teal:     { 50:'#f0fdfa', 100:'#ccfbf1', 200:'#99f6e4', 400:'#2dd4bf', 500:'#14b8a6', 600:'#0d9488', 700:'#0f766e', 800:'#115e59', 900:'#134e4a' },
  rose:     { 50:'#fff1f2', 100:'#ffe4e6', 200:'#fecdd3', 400:'#fb7185', 600:'#e11d48', 800:'#9f1239' },
};

export const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --font-display: 'Segoe UI', Arial, sans-serif;
    --font-body: 'Segoe UI', Arial, sans-serif;
    --font-mono: 'Consolas', monospace;
    --color-bg: #0a1014; --color-surface: #10191e;
    --color-border: #253239; --color-border-mid: #34434b;
    --color-text-primary: #edf4f2; --color-text-secondary: #99aab2; --color-text-tertiary: #82959e;
    --color-accent: #73f5c5; --color-accent-soft: #18372c; --color-ink: #0d161b;
    --color-cyan: #73f5c5; --color-amber: #dbb56c;
    --sidebar-bg: #0d161b; --sidebar-border: #253239; --sidebar-w: 260px; --header-h: 64px;
    --r-sm: 5px; --r-md: 6px; --r-lg: 9px; --r-xl: 14px; --r-full: 9999px;
    --shadow-xs: none; --shadow-sm: none; --shadow-md: 0 8px 24px #0002; --shadow-lg: 0 16px 36px #0004;
  }
  html, body, #root { height: 100%; }
  body {
    font-family: var(--font-body); font-size: 14px; line-height: 1.6;
    color: var(--color-text-primary);
    background:
      linear-gradient(rgba(45,212,191,0.045) 1px, transparent 1px),
      linear-gradient(90deg, rgba(45,212,191,0.045) 1px, transparent 1px),
      radial-gradient(circle at 8% 10%, #12333b 0%, transparent 30%),
      radial-gradient(circle at 92% 88%, #2b2114 0%, transparent 28%),
      var(--color-bg);
    background-size: 32px 32px, 32px 32px, auto, auto, auto;
    position: relative;
    isolation: isolate;
    -webkit-font-smoothing: antialiased;
  }
  body::before {
    content: "GHOSTNET // SIGNAL INTELLIGENCE";
    position: fixed;
    z-index: -1;
    top: 34%;
    left: 6%;
    color: #0f766e;
    opacity: 0.035;
    font-family: var(--font-display);
    font-size: clamp(42px, 8vw, 128px);
    font-weight: 700;
    letter-spacing: 0.12em;
    white-space: nowrap;
    transform: rotate(-11deg);
    pointer-events: none;
  }
  body::after {
    content: "";
    position: fixed;
    inset: 0;
    z-index: -1;
    pointer-events: none;
    opacity: 0.16;
    background: repeating-linear-gradient(0deg, transparent 0, transparent 3px, rgba(15,118,110,0.035) 4px);
    mix-blend-mode: screen;
  }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #355263; border-radius: 99px; }
  ::-webkit-scrollbar-thumb:hover { background: #4c7180; }
  input, select, textarea {
    font-family: var(--font-body); font-size: 13px;
    color: var(--color-text-primary); background: #122333;
    border: 1.5px solid var(--color-border); border-radius: var(--r-md);
    padding: 8px 12px; outline: none; width: 100%;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  input:focus, select:focus, textarea:focus {
    border-color: #2dd4bf;
    box-shadow: 0 0 0 3px rgba(45,212,191,0.14);
  }
  textarea { resize: vertical; min-height: 80px; }
  input[type="checkbox"], input[type="radio"] { width: auto; accent-color: var(--color-accent); }
  button:focus-visible, a:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 3px; }
  .app-header { flex-shrink: 0; }
  .integration-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; padding: 20px; }
  .settings-page { display: grid; gap: 18px; }
  .settings-page .module-header { margin-bottom: 0; }
  .integration-card code { overflow-wrap: anywhere; }
  .integration-card { padding: 20px; border: 1px solid var(--color-border); border-radius: 12px; background: #122333; }
  .integration-card h3 { font-family: var(--font-display); margin-bottom: 8px; }
  .integration-card p { color: var(--color-text-secondary); margin: 8px 0 16px; }
  @media (max-width: 1100px) {
    .app-header { height: auto !important; min-height: 56px; flex-wrap: wrap; padding: 12px 16px !important; gap: 10px !important; }
  }
  @media (max-width: 760px) {
    .app-shell { flex-direction: column; }
    .app-sidebar { width: 100% !important; min-width: 0 !important; height: auto !important; position: relative !important; }
    .app-sidebar > div { display: none !important; }
    .app-sidebar nav { display: flex; gap: 4px; overflow-x: auto; padding: 8px !important; flex: none !important; }
    .app-sidebar nav > div { display: none; }
    .app-sidebar nav button { width: auto !important; white-space: nowrap; flex-shrink: 0; }
    .app-content { min-height: 0; }
    main { padding: 16px 12px !important; }
    .integration-grid { grid-template-columns: 1fr; padding: 12px; }
  }
  @keyframes fadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulseDot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.8)} }
  @keyframes slideIn { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
  .page-enter { animation: fadeUp 0.22s ease both; }
  .module-page { max-width: 1600px; margin: 0 auto; padding-bottom: 24px; }
  .module-header {
    display: flex; align-items: flex-end; justify-content: space-between; gap: 20px;
    min-height: 76px; padding: 4px 2px 18px; margin-bottom: 18px;
    border-bottom: 1px solid var(--color-border);
  }
  .module-header h2 {
    margin: 3px 0 4px; color: var(--color-text-primary);
    font-family: var(--font-display); font-size: 25px; line-height: 1.1;
    font-weight: 700; letter-spacing: -0.03em;
  }
  .module-header p { margin: 0; color: var(--color-text-secondary); font-size: 12px; }
  .module-eyebrow {
    display: flex; align-items: center; gap: 7px; color: var(--color-accent);
    font-family: var(--font-mono); font-size: 10px; font-weight: 600;
    letter-spacing: 0.11em; text-transform: uppercase;
  }
  .module-eyebrow-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-cyan); box-shadow: 0 0 0 4px rgba(6,182,212,0.12); }
  .module-header-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
  @media (max-width: 760px) {
    .module-header { align-items: flex-start; flex-direction: column; gap: 12px; }
    .module-header-actions { width: 100%; flex-wrap: wrap; }
  }

  body { background: var(--color-bg); }
  body::before, body::after { display: none; }
  input, select, textarea { background: #121c22; border-width: 1px; }
  .workspace-sidebar { width: var(--sidebar-w); min-width: var(--sidebar-w); height: 100dvh; display: flex; flex-direction: column; background: var(--sidebar-bg); border-right: 1px solid var(--color-border); }
  .brand { display: flex; align-items: center; gap: 12px; padding: 27px 26px 32px; font-size: 29px; font-weight: 750; letter-spacing: -1.2px; }
  .brand > span > span { color: var(--color-accent); }
  .brand-shield { background: var(--color-accent); color: #113c2e; width: 43px; height: 47px; display: grid; place-items: center; clip-path: polygon(50% 0,100% 18%,88% 73%,50% 100%,12% 73%,0 18%); }
  .workspace-card { border: 1px solid var(--color-border); border-radius: 8px; margin: 0 18px 28px; padding: 14px 12px; display: flex; gap: 12px; align-items: center; }
  .workspace-avatar { width: 36px; height: 38px; background: #1a2a30; border: 1px solid #30434a; border-radius: 5px; display: grid; place-items: center; color: #add3c4; flex-shrink: 0; font-size: 12px; }
  .workspace-card strong, .sidebar-user strong { display: block; font-size: 13px; font-weight: 600; }
  .workspace-card small, .sidebar-user small { display: block; color: var(--color-text-tertiary); font-size: 11px; margin-top: 3px; text-transform: capitalize; }
  .workspace-chevron { margin-left: auto; color: var(--color-text-tertiary); }
  .workspace-sidebar nav { flex: 1; overflow-y: auto; padding: 0 18px; }
  .nav-eyebrow { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: #6f838e; padding: 6px 14px 22px; }
  .nav-item { display: flex; width: 100%; align-items: center; gap: 16px; padding: 14px 16px; min-height: 49px; margin-bottom: 5px; border: 0; border-radius: 6px; background: transparent; color: #9baeb8; text-align: left; cursor: pointer; font: 14px var(--font-body); transition: background .15s,color .15s; }
  .nav-item:hover { background: #1a2931; color: #e4efed; }
  .nav-item[aria-current=page] { background: #19392e; color: #73f5c5; font-weight: 600; }
  .nav-count { margin-left: auto; font-size: 10px; border: 1px solid #665134; background: #413521; padding: 1px 6px; border-radius: 4px; color: #e9c584; }
  .nav-secondary { margin-top: 4px; }
  .nav-item:nth-last-child(2) { border-top: 1px solid var(--color-border); border-radius: 0; margin-top: 26px; padding-top: 24px; }
  .sidebar-bottom { padding: 20px 28px 18px; }
  .workspace-health { display: flex; gap: 8px; align-items: center; font-size: 11px; color: #aabdbf; }
  .status-dot { width: 6px; height: 6px; display: inline-block; background: #7e8e95; border-radius: 2px; flex-shrink: 0; }
  .status-dot.is-live { background: #73f5c5; box-shadow: 0 0 8px #73f5c520; }
  .sidebar-bottom small { font-size: 10px; color: #6f838e; display: block; margin: 5px 0 0 14px; }
  .sidebar-user { display: flex; gap: 12px; align-items: center; padding: 20px 24px; border-top: 1px solid var(--color-border); }
  .sidebar-user > svg { margin-left: auto; color: #6f838e; }
  .workspace-header { min-height: 64px; flex-shrink: 0; padding: 0 36px; display: flex; align-items: center; gap: 24px; border-bottom: 1px solid var(--color-border); background: #0a1014; z-index: 110; }
  .breadcrumb { display: flex; gap: 22px; align-items: center; color: #80939e; font-size: 12px; }
  .breadcrumb strong { color: #d9e6e5; font-weight: 500; }
  .header-tools { margin-left: auto; display: flex; gap: 20px; align-items: center; }
  .environment-tag { font: 9px var(--font-mono); color: #8fa5b1; letter-spacing: 1.1px; border: 1px solid #293941; border-radius: 4px; padding: 6px 9px; white-space: nowrap; }
  .module-search { display: flex; align-items: center; gap: 10px; position: relative; color: #82959e; }
  .module-search input { background: transparent; border: 0; padding: 6px 0; width: 135px; font-size: 12px; box-shadow: none; }
  kbd { font: 9px var(--font-mono); border: 1px solid #293941; padding: 2px 5px; white-space: nowrap; border-radius: 3px; }
  .header-icon { color: #8da4ad; background: transparent; border: 0; cursor: pointer; padding: 4px; }
  .header-avatar { width: 33px; height: 33px; border-radius: 50%; border: 1px solid #2c473d; background: #1e352c; color: #b5d9cb; cursor: pointer; font-size: 10px; }
  .search-results { position: absolute; top: 40px; right: 0; background: #101b21; border: 1px solid #314149; border-radius: 8px; width: 320px; box-shadow: 0 12px 30px #0007; padding: 6px; z-index: 150; }
  .search-results button { display: flex; align-items: center; gap: 12px; width: 100%; background: transparent; color: #b1c5cd; border: 0; padding: 10px; text-align: left; cursor: pointer; border-radius: 4px; }
  .search-results button:hover { background: #19392e; }
  .search-results strong { font-size: 12px; display: block; color: #edf4f2; }
  .search-results small { display: block; color: #82959e; font-size: 10px; margin-top: 3px; }
  .search-results p { padding: 14px; font-size: 12px; }
  .module-page { max-width: 1440px; }
  .module-header { align-items: center; padding: 0; margin-bottom: 32px; border: 0; min-height: 100px; }
  .module-header h2 { font-size: 34px; font-weight: 650; letter-spacing: -1.1px; margin: 12px 0; }
  .module-header p { font-size: 13px; color: #8298a2; max-width: 680px; }
  .module-eyebrow { color: #849ca7; font-size: 9px; letter-spacing: 2.2px; }
  .module-eyebrow-dot { width: 5px; height: 5px; border-radius: 1px; background: #73f5c5; box-shadow: none; }
  .stat-card { padding: 24px; border: 1px solid var(--color-border); border-radius: 9px; background: #10191e; min-height: 164px; }
  .stat-card-top { display: flex; align-items: center; justify-content: space-between; gap: 10px; color: #8fa6b0; font-size: 12px; }
  .stat-icon { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 6px; }
  .stat-value { color: #f0f6f4; font: 650 35px/1.2 var(--font-display); letter-spacing: -1px; margin: 16px 0; }
  .stat-bottom { display: flex; gap: 8px; align-items: center; font-size: 10px; color: #89a19f; }
  .protection-banner { display: flex; align-items: center; gap: 18px; background: linear-gradient(105deg,#132e25,#101b1b); border: 1px solid #26483c; border-radius: 8px; padding: 21px 25px; margin-bottom: 26px; }
  .protection-icon { width: 42px; height: 42px; display: grid; place-items: center; border-radius: 50%; background: #1d4434; border: 1px solid #2c5d46; color: #73f5c5; flex-shrink: 0; }
  .protection-banner strong { font-size: 13px; font-weight: 600; }
  .protection-banner > div { flex: 1; min-width: 0; }
  .protection-banner p { font-size: 11px; color: #829e99; margin-top: 4px; }
  .protection-state { display: flex; align-items: center; gap: 10px; margin-left: auto; color: #73f5c5; font-size: 11px; white-space: nowrap; }
  .network-summary { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 24px; margin: 26px 0 32px; }
  .network-summary-card { background: #10191e; border: 1px solid var(--color-border); padding: 30px; border-radius: 9px; min-height: 210px; }
  .summary-tag { display: inline-flex; padding: 3px 8px; border-radius: 3px; background: #1d2d37; color: #9dc0d0; font-size: 9px; }
  .network-summary-card h3 { font-size: 19px; font-weight: 600; margin: 23px 0 10px; color: #e8f1f0; }
  .network-summary-card p { color: #849ca7; font-size: 12px; line-height: 1.8; }
  .summary-link { display: inline-flex; align-items: center; gap: 8px; background: transparent; border: 0; padding: 0; color: #73f5c5; font-size: 12px; cursor: pointer; margin-top: 22px; }
  .section-label { font-size: 10px; color: #7c939e; letter-spacing: 1.8px; text-transform: uppercase; margin: 30px 0 18px; }
  .app-footer { flex-shrink: 0; display: flex; justify-content: space-between; gap: 16px; padding: 13px 40px; color: #607a86; font-size: 10px; background: #0a1014; }
  .app-footer .footer-brand { color: #8ca59f; }
  @media(min-width:761px) and (max-height:950px) { .brand { padding-top:20px; padding-bottom:20px; } .workspace-card { margin-bottom:18px; } .nav-item { min-height:42px; padding-top:10px; padding-bottom:10px; } .nav-eyebrow { padding-bottom:14px; } .sidebar-user { padding:14px 24px; } }
  @media(max-width:1200px) { .environment-tag { display:none; } .header-tools { gap:14px; } .workspace-header { padding:0 24px; } .network-summary-card { padding:24px; } }
  @media(max-width:1000px) { :root { --sidebar-w:224px; } .brand { font-size:25px; padding-left:22px; } .responsive-grid { grid-template-columns:repeat(2,minmax(0,1fr)) !important; } .network-summary { gap:14px; } .network-summary-card { padding:18px; } .module-search input { width:100px; } .header-tools { gap:10px; } }
  @media(max-width:760px) {
    .workspace-sidebar { height:auto; width:100%; min-width:0; }
    .workspace-sidebar nav { display:flex; overflow-x:auto; padding:8px !important; gap:4px; }
    .workspace-sidebar .nav-item { min-height:42px; width:auto; padding:10px 14px; margin:0; white-space:nowrap; flex-shrink:0; border:0; border-radius:5px; }
    .workspace-header { min-height:56px; padding:10px 14px !important; gap:12px !important; }
    .module-search { display:none; } .header-tools { gap:14px; } .breadcrumb { gap:12px; }
    .module-header { min-height:0; margin-bottom:24px; gap:18px; } .module-header h2 { font-size:29px; }
    .module-header-actions { flex-wrap:wrap; }
    .protection-banner { flex-wrap:wrap; gap:12px; padding:18px; } .protection-state { margin-left:60px; }
    .stat-card { padding:18px; min-height:150px; } .stat-value { font-size:29px; }
    .network-summary { grid-template-columns:1fr; gap:16px; } .network-summary-card { min-height:190px; padding:24px; }
    .app-footer { padding:12px; flex-wrap:wrap; font-size:9px; }
  }
`;

export const severityConfig = (sev) => {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { bg:'#321927', border:'#713047', text:'#fda4af', dot:'#fb7185', label:'Critical' };
  if (s === 'high')     return { bg:'#302610', border:'#70521d', text:'#fcd34d', dot:'#fbbf24', label:'High'     };
  if (s === 'medium')   return { bg:'#172e42', border:'#2b5870', text:'#7dd3fc', dot:'#38bdf8', label:'Medium'   };
  if (s === 'low')      return { bg:'#103b3b', border:'#1f6868', text:'#6ee7d8', dot:'#34d399', label:'Low'      };
  return                        { bg:'#1b2937', border:'#355263', text:'#b4c6d1', dot:'#78909c', label: sev||'—'  };
};

export const statusConfig = (st) => {
  const s = (st || '').toLowerCase().replace(/_/g, '-');
  if (s === 'open')             return { bg:'#321927', border:'#713047', text:'#fda4af' };
  if (s === 'investigating')    return { bg:'#302610', border:'#70521d', text:'#fcd34d' };
  if (s === 'contained')        return { bg:'#172e42', border:'#2b5870', text:'#7dd3fc' };
  if (s === 'resolved')         return { bg:'#103b3b', border:'#1f6868', text:'#6ee7d8' };
  if (s === 'closed')           return { bg:'#1b2937', border:'#355263', text:'#b4c6d1' };
  if (s === 'new')              return { bg:'#12333a', border:'#1f6868', text:'#8ee7dc' };
  if (s === 'infected')         return { bg:'#321927', border:'#713047', text:'#fda4af' };
  if (s === 'suspicious')       return { bg:'#302610', border:'#70521d', text:'#fcd34d' };
  if (s === 'clean')            return { bg:'#103b3b', border:'#1f6868', text:'#6ee7d8' };
  if (s === 'running')          return { bg:'#12333a', border:'#1f6868', text:'#8ee7dc' };
  if (s === 'completed')        return { bg:'#103b3b', border:'#1f6868', text:'#6ee7d8' };
  if (s === 'active')           return { bg:'#103b3b', border:'#1f6868', text:'#6ee7d8' };
  if (s === 'false-positive')   return { bg:'#1b2937', border:'#355263', text:'#b4c6d1' };
  return                                { bg:'#1b2937', border:'#355263', text:'#b4c6d1' };
};
