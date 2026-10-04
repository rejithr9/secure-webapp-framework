import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";
import { useSwfConfig } from "../config";
import { Alert, Brand } from "./ui";

function ThemeSwitch() {
  const { theme, setTheme } = useAuth();
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button onClick={() => setTheme(next)} aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`}>
      {theme === "dark" ? "☀ Light" : "☾ Dark"}
    </button>
  );
}

function UserMenu() {
  const { state, config, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  return (
    <div className="menu" ref={ref}>
      <button onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open}>
        {state?.user?.username} ▾
      </button>
      {open && (
        <div className="menu-list" role="menu" onClick={() => setOpen(false)}>
          <div className="menu-label">
            Signed in as <strong>{state?.user?.username}</strong>
            {state?.user?.role === "admin" && " (admin)"}
          </div>
          <Link to="/account" role="menuitem">
            My account
          </Link>
          {config?.keys_enabled && (
            <Link to="/keys" role="menuitem">
              My keys
            </Link>
          )}
          <Link to="/activity" role="menuitem">
            My activity
          </Link>
          <button role="menuitem" onClick={() => signOut()}>
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function Layout() {
  const { state, config, notice, clearNotice } = useAuth();
  const app = useSwfConfig();
  const isAdmin = state?.user?.role === "admin";
  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        <nav className="nav">
          <NavLink to="/" end>
            {app.homeLabel ?? "Home"}
          </NavLink>
          {(app.nav ?? [])
            .filter((item) => item.label && (!item.adminOnly || isAdmin))
            .map((item) => (
              <NavLink key={item.path} to={item.path}>
                {item.label}
              </NavLink>
            ))}
          {config?.keys_enabled && <NavLink to="/keys">My keys</NavLink>}
          <NavLink to="/activity">My activity</NavLink>
          {isAdmin && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <div className="topbar-right">
          <ThemeSwitch />
          <UserMenu />
        </div>
      </header>
      <main className="content">
        {notice && (
          <Alert kind="warning">
            <span className="notice-bar">
              {notice}
              <button className="link" onClick={clearNotice}>
                Dismiss
              </button>
            </span>
          </Alert>
        )}
        <Outlet />
      </main>
      {app.shellExtras}
    </div>
  );
}
