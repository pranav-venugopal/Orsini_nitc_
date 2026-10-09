import { useState } from "react";
import { Activity, Crosshair, LayoutDashboard, LogOut, Menu, MessageSquare, ShieldCheck, X } from "lucide-react";
import { NavLink, useLocation } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";
import type { UserRole } from "../types/api";

const links = [
  { to: "/chat", label: "Assistant", icon: MessageSquare },
  { to: "/dashboard", label: "Security monitor", icon: LayoutDashboard },
  { to: "/red-team", label: "Red-team lab", icon: Crosshair },
];

export default function AppSidebar({ theme, role, username, onToggleTheme, onSignOut }: {
  theme: "light" | "dark";
  role: UserRole;
  username: string;
  onToggleTheme: () => void;
  onSignOut: () => void;
}) {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const visibleLinks = role === "admin" ? links : links.slice(0, 1);
  return (
    <>
      <header className="flex items-center justify-between border-b border-white/10 bg-[#071c2b] px-4 py-3 text-white md:hidden">
        <span className="flex items-center gap-2 font-semibold"><ShieldCheck size={19} className="text-cyan-300" /> Secure AI</span>
        <div className="flex items-center gap-2">
          <button aria-expanded={open} aria-controls="nav" aria-label={open ? "Close navigation" : "Open navigation"} onClick={() => setOpen(!open)}
            className="grid size-10 place-items-center border border-white/20 text-white hover:border-cyan-300 hover:text-cyan-200">{open ? <X size={19} /> : <Menu size={19} />}</button>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        </div>
      </header>
      <nav id="nav" aria-label="Main"
        className={`${open ? "block" : "hidden"} border-b border-white/10 bg-[#071c2b] p-3 text-white md:sticky md:top-0 md:flex md:h-screen md:w-60 md:shrink-0 md:flex-col md:border-b-0 md:border-r md:border-white/10 md:p-5`}>
        <div className="mb-10 hidden items-center gap-3 px-2 md:flex">
          <div className="grid size-11 place-items-center border border-cyan-300/40 bg-cyan-300/10 text-cyan-200 shadow-[0_0_24px_rgba(29,213,245,0.12)]">
            <ShieldCheck size={25} strokeWidth={1.7} />
          </div>
          <div>
            <p className="font-display text-3xl uppercase leading-none">Secure AI</p>
            <p className="mt-1 text-[10px] uppercase text-cyan-100/55">Defense gateway</p>
          </div>
        </div>
        <p className="mb-3 hidden px-3 text-[10px] uppercase text-white/40 md:block">Workspace</p>
        <ul className="space-y-1 md:flex-1">
          {visibleLinks.map((link) => {
            const isActive = location.pathname === link.to || location.pathname.startsWith(`${link.to}/`);
            const Icon = link.icon;
            return (
              <li key={link.to}>
                <NavLink to={link.to} end onClick={() => setOpen(false)}
                  className={`group flex items-center gap-3 rounded-xl border px-3 py-3 text-sm transition-all duration-300 ${isActive ? "border-cyan-200/25 bg-cyan-300/[0.12] text-white shadow-[0_10px_35px_rgba(0,200,255,0.1),inset_0_1px_0_rgba(255,255,255,0.12)] backdrop-blur-xl" : "border-transparent text-white/60 hover:border-white/10 hover:bg-white/[0.06] hover:text-white"}`}>
                  <Icon size={18} strokeWidth={1.8} className={isActive ? "text-cyan-200" : "text-white/45 group-hover:text-cyan-100"} />
                  <span className="flex-1">{link.label}</span>
                  {isActive && <span className="size-1.5 rounded-full bg-cyan-300 shadow-[0_0_10px_#37dbfa]" />}
                </NavLink>
              </li>
            );
          })}
        </ul>
        <div className="mt-4 border-t border-white/10 pt-4 md:mt-6">
          <div className="hidden items-center gap-2 px-2 text-[10px] uppercase text-white/45 md:flex">
            <Activity size={13} className="text-cyan-300" /> Local gateway
          </div>
          <div className="mt-1 flex items-center gap-2 px-2 text-xs text-white/70 md:mt-3">
            <span className="size-1.5 animate-pulse bg-cyan-300" /> Runtime connected
          </div>
          <div className="mt-4 flex items-center justify-between gap-3 px-2">
            <div className="min-w-0">
              <p className="truncate text-xs text-white/85">{username}</p>
              <p className="mt-0.5 text-[9px] uppercase tracking-[0.08em] text-white/40">{role} access</p>
            </div>
            <button type="button" onClick={onSignOut} aria-label="Sign out" title="Sign out" className="grid size-9 shrink-0 place-items-center rounded-full border border-white/15 text-white/60 transition-colors hover:border-rose-300/50 hover:text-white"><LogOut size={15} /></button>
          </div>
        </div>
      </nav>
    </>
  );
}
