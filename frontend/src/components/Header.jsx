import { useEffect, useRef, useState } from 'react';
import Icon from './Icon.jsx';
import { modules } from '../modules/registry.js';
export default function Header({page,user,onNavigate,onLogout,onToast,onRefresh,extra}) {
  const [query,setQuery]=useState('');
  const [searchOpen,setSearchOpen]=useState(false);
  const searchRef=useRef(null);
  const active=modules.find(item=>item.id===page);
  useEffect(()=>{const key=e=>{if((e.ctrlKey||e.metaKey)&&e.key==='k'){e.preventDefault();searchRef.current?.focus();setSearchOpen(true);}if(e.key==='Escape')setSearchOpen(false);};document.addEventListener('keydown',key);return()=>document.removeEventListener('keydown',key);},[]);
  const matches=modules.filter(item=>(item.label+' '+item.description).toLowerCase().includes(query.toLowerCase()));
  return <header className="app-header workspace-header">
    <div className="breadcrumb"><span>Workspace</span><span>/</span><strong>{active?.label||'Users'}</strong></div>
    <div className="header-tools"><span className="environment-tag">LOCAL WORKSPACE</span>
      <div className="module-search"><Icon name="search" size={16}/><input ref={searchRef} aria-label="Search modules" placeholder="Search anything…" value={query} onFocus={()=>setSearchOpen(true)} onBlur={()=>setSearchOpen(false)} onChange={e=>{setQuery(e.target.value);setSearchOpen(true);}} onKeyDown={e=>{if(e.key==='Enter'&&matches[0]){onNavigate(matches[0].id);setQuery('');setSearchOpen(false);searchRef.current.blur();}}}/><kbd>Ctrl K</kbd>
        {searchOpen&&<div className="search-results">{matches.length?matches.map(item=><button key={item.id} onMouseDown={e=>e.preventDefault()} onClick={()=>{onNavigate(item.id);setSearchOpen(false);setQuery('');searchRef.current.blur();}}><Icon name={item.icon} size={17}/><span><strong>{item.label}</strong><small>{item.description}</small></span></button>):<p>No matching modules</p>}</div>}
      </div>
      <button className="header-icon" aria-label="Refresh live data" title="Refresh live data" onClick={async()=>{try{await onRefresh();onToast('Data refreshed','success');}catch(err){onToast(err.message,'error');}}}><span style={{fontSize:20}}>⟳</span></button>
      <button className="header-avatar" aria-label="Open account settings" title="Account settings" onClick={()=>onNavigate('settings')}>{(user?.username||'G').slice(0,2).toUpperCase()}</button>
      <button className="header-icon logout-button" aria-label="Sign out" title="Sign out" onClick={onLogout}>⏻</button>
    </div>
  </header>;
}

