import { Crosshair, LayoutDashboard, LogOut, MessageSquare, Wrench } from "lucide-react";
import { NavLink } from "react-router-dom";
import ThemeToggle from "./ThemeToggle";
import Brand from "./Brand";
import type { UserRole } from "../types/api";

const links = [
  { to: "/chat", label: "Assistant", icon: MessageSquare },
  { to: "/tools", label: "Agent tools", icon: Wrench },
  { to: "/dashboard", label: "Security monitor", icon: LayoutDashboard },
  { to: "/red-team", label: "Red-team lab", icon: Crosshair },
];

export default function WorkspaceNav({ theme, role, username, onToggleTheme, onSignOut }: {
  theme: "light" | "dark";
  role: UserRole;
  username: string;
  onToggleTheme: () => void;
  onSignOut: () => void;
}) {
  const visibleLinks = role === "admin" ? links : links.slice(0, 2);
  return (
    <header className="workspace-header z-30 shrink-0 border-b border-edge/55 px-4 py-3 backdrop-blur-2xl md:px-8">
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center gap-x-5 gap-y-2">
        <Brand />
        <nav aria-label="Main" className="order-3 -mx-1 flex w-[calc(100%+0.5rem)] items-center gap-1 overflow-x-auto pb-0.5 md:order-none md:mx-0 md:w-auto md:flex-1 md:justify-center">
          {visibleLinks.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end className={({ isActive }) => `nav-pill inline-flex shrink-0 items-center gap-2 rounded-full px-3 py-2 text-xs font-medium transition-all sm:px-4 sm:text-sm ${isActive ? "nav-pill-active" : "text-mute hover:bg-panel/55 hover:text-text"}`}>
              <Icon size={15} strokeWidth={1.8} />{label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex shrink-0 items-center gap-2 sm:gap-3">
          <div className="hidden text-right sm:block">
            <p className="max-w-36 truncate text-xs font-medium text-text">{username}</p>
            <p className="text-[9px] uppercase tracking-[0.12em] text-mute">{role} workspace</p>
          </div>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
          <button type="button" onClick={onSignOut} aria-label="Sign out" title="Sign out" className="grid size-10 shrink-0 place-items-center rounded-full border border-edge/65 bg-panel/60 text-mute transition-colors hover:border-rose-400/50 hover:text-status-error">
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}
