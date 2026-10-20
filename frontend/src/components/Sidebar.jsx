import Icon from './Icon.jsx';
import { modules } from '../modules/registry.js';
export default function Sidebar({activePage,onNavigate,badges={},status={},user}) {
  return <aside className="app-sidebar workspace-sidebar">
    <div className="brand"><span className="brand-shield"><Icon name="shield" size={29}/></span><span>Ghost<span>Net</span></span></div>
    <div className="workspace-card"><span className="workspace-avatar">G</span><div><strong>Security workspace</strong><small>Local environment</small></div><span className="workspace-chevron">⌄</span></div>
    <nav aria-label="Main navigation"><div className="nav-eyebrow">Workspace</div>
      {modules.map(item=><button type="button" key={item.id} className={`nav-item ${item.secondary?'nav-secondary':''}`} aria-current={activePage===item.id?'page':undefined} onClick={()=>onNavigate(item.id)}>
        <Icon name={item.icon} size={19}/><span>{item.label}</span>{badges[item.badge]>0&&<span className="nav-count">{badges[item.badge]}</span>}
      </button>)}
    </nav>
    <div className="sidebar-bottom"><div className="workspace-health"><span className={`status-dot ${status.ws?'is-live':''}`}/>{status.ws?'Live feed connected':'Live feed disconnected'}</div><small>{status.capture?'Packet capture active':'Packet capture idle'} · ML {status.ml?'online':'unavailable'}</small></div>
    <div className="sidebar-user"><span className="workspace-avatar">{(user?.username||'G').slice(0,2).toUpperCase()}</span><div><strong>{user?.username}</strong><small>{user?.role==='admin'?'Security administrator':user?.role}</small></div><Icon name="overview" size={16}/></div>
  </aside>;
}
