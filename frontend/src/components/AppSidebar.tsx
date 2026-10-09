import { useState } from "react";
import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Chat", icon: "💬" },
  { to: "/dashboard", label: "Security dashboard", icon: "🛡" },
  { to: "/red-team", label: "Red-team playground", icon: "🧪" },
];

export default function AppSidebar() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <header className="flex items-center justify-between border-b border-edge bg-panel px-4 py-3 md:hidden">
        <span className="font-semibold">Secure AI Assistant</span>
        <button aria-expanded={open} aria-controls="nav" onClick={() => setOpen(!open)}
          className="rounded-lg border border-edge px-3 py-1 text-sm">{open ? "Close" : "Menu"}</button>
      </header>
      <nav id="nav" aria-label="Main"
        className={`${open ? "block" : "hidden"} border-b border-edge bg-panel p-3 md:static md:block md:w-60 md:shrink-0 md:border-b-0 md:border-r md:p-4`}>
        <p className="mb-4 hidden px-2 font-semibold md:block">Secure AI Assistant</p>
        <ul className="space-y-1">
          {links.map((l) => (
            <li key={l.to}>
              <NavLink to={l.to} end onClick={() => setOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-node text-white ring-1 ring-edge" : "text-mute hover:bg-node/60"}`}>
                <span aria-hidden>{l.icon}</span>{l.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
    </>
  );
}
