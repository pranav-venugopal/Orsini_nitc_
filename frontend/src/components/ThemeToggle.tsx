import { Moon, Sun } from "lucide-react";

type ThemeToggleProps = { theme: "light" | "dark"; onToggle: () => void };

export default function ThemeToggle({ theme, onToggle }: ThemeToggleProps) {
  const dark = theme === "dark";
  const label = dark ? "Switch to light mode" : "Switch to dark mode";
  const Icon = dark ? Sun : Moon;

  return (
    <button type="button" onClick={onToggle} className="theme-toggle" aria-label={label} title={label} aria-pressed={dark}>
      <Icon size={17} strokeWidth={1.8} />
    </button>
  );
}