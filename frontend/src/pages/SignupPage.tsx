import { useState, type FormEvent } from "react";
import { ArrowLeft, ArrowRight, LoaderCircle, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import ThemeToggle from "../components/ThemeToggle";
import Brand from "../components/Brand";
import SignalArtwork from "../components/SignalArtwork";
import { ApiError } from "../services/api";
import type { SessionUser } from "../types/api";

type Theme = "light" | "dark";
const USERNAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,30}[A-Za-z0-9])$/;

function passwordRequirements(password: string) {
  return [
    { label: "At least 12 characters", valid: password.length >= 12 },
    { label: "One uppercase letter", valid: /[A-Z]/.test(password) },
    { label: "One lowercase letter", valid: /[a-z]/.test(password) },
    { label: "One number", valid: /\d/.test(password) },
    { label: "One symbol", valid: /[^A-Za-z0-9]/.test(password) },
  ];
}

export default function SignupPage({ theme, onToggleTheme, onSignUp }: {
  theme: Theme;
  onToggleTheme: () => void;
  onSignUp: (username: string, password: string) => Promise<SessionUser>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [usernameTouched, setUsernameTouched] = useState(false);
  const [confirmationTouched, setConfirmationTouched] = useState(false);
  const [usernameError, setUsernameError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [formError, setFormError] = useState("");
  const [pending, setPending] = useState(false);
  const requirements = passwordRequirements(password);
  const passwordIsValid = requirements.every((requirement) => requirement.valid);
  const usernameIsValid = USERNAME_PATTERN.test(username);
  const confirmationError = confirmationTouched && confirmation !== password ? "Passwords don't match yet." : "";

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (pending) return;
    setUsernameTouched(true);
    setConfirmationTouched(true);
    setUsernameError(usernameIsValid ? "" : "Use 3–32 letters, numbers, periods, underscores, or hyphens. Start and end with a letter or number.");
    setPasswordError(passwordIsValid ? "" : "Meet every password requirement before continuing.");
    setFormError("");
    if (!usernameIsValid || !passwordIsValid || confirmation !== password) return;

    setPending(true);
    try {
      await onSignUp(username, password);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "Account creation was unsuccessful.";
      if (reason instanceof ApiError && reason.field === "username") setUsernameError(message);
      else if (reason instanceof ApiError && reason.field === "password") setPasswordError(message);
      else setFormError(message);
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="public-home page-enter min-h-screen overflow-hidden px-4 text-text md:px-8">
      <header className="mx-auto flex h-[76px] max-w-7xl items-center justify-between border-b border-edge/45">
        <Brand to="/" />
        <div className="flex items-center gap-3">
          <Link to="/" className="hidden items-center gap-2 text-xs text-mute transition-colors hover:text-text sm:inline-flex"><ArrowLeft size={14} /> Home</Link>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        </div>
      </header>

      <main className="mx-auto grid min-h-[calc(100vh-77px)] max-w-7xl items-center gap-8 py-8 lg:grid-cols-[minmax(0,1.05fr)_minmax(350px,0.8fr)] lg:gap-14">
        <div className="order-2 lg:order-1">
          <p className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-[0.12em] text-accent"><span className="size-1.5 rounded-full bg-accent" /> Member workspace</p>
          <h1 className="display-title font-display text-5xl font-semibold leading-[0.98] text-text sm:text-6xl lg:text-7xl">A calmer way<br /><span className="bg-gradient-to-r from-cyan-600 via-sky-500 to-blue-700 bg-clip-text text-transparent">to think clearly.</span></h1>
          <p className="mt-5 max-w-lg text-sm leading-6 text-mute sm:text-base">Create a private, chat-only account. Administrator tools stay restricted to provisioned admins.</p>
          <SignalArtwork className="mt-7 h-[200px] sm:h-[260px]" />
        </div>

        <section className="surface-glass order-1 rounded-[30px] p-6 sm:p-9 lg:order-2">
          <div className="mb-6">
            <p className="text-[10px] uppercase tracking-[0.12em] text-accent">Member access</p>
            <h2 className="mt-2 font-display text-4xl font-semibold tracking-tight text-text sm:text-5xl">Create account</h2>
            <p className="mt-2 text-sm text-mute">Sign up for a member account with chat access.</p>
          </div>
          <form onSubmit={submit} noValidate className="space-y-4">
            <div>
              <label htmlFor="username" className="mb-2 block text-xs font-medium text-text">Username</label>
              <input id="username" name="username" autoComplete="username" required minLength={3} maxLength={32} value={username}
                onBlur={() => setUsernameTouched(true)} onChange={(event) => { setUsername(event.target.value); setUsernameError(""); }}
                aria-invalid={Boolean(usernameError || (usernameTouched && username.length > 0 && !usernameIsValid))} aria-describedby="username-hint username-error"
                className="auth-input w-full rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all focus:border-cyan-500 focus:ring-4 focus:ring-cyan-400/15" />
              <p id="username-hint" className="mt-1.5 text-[11px] text-mute">3–32 characters; use letters, numbers, . _ or -.</p>
              <p id="username-error" className="mt-1 min-h-4 text-xs text-status-error" role={usernameError ? "alert" : undefined}>
                {usernameError || (usernameTouched && username.length > 0 && !usernameIsValid ? "Check the username length and allowed characters." : "")}
              </p>
            </div>
            <div>
              <label htmlFor="password" className="mb-2 block text-xs font-medium text-text">Password</label>
              <input id="password" name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password}
                onChange={(event) => { setPassword(event.target.value); setPasswordError(""); }}
                aria-invalid={Boolean(passwordError || (password.length > 0 && !passwordIsValid))} aria-describedby="password-rules password-error"
                className="auth-input w-full rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all focus:border-cyan-500 focus:ring-4 focus:ring-cyan-400/15" />
              <ul id="password-rules" className="mt-2 grid grid-cols-1 gap-1 sm:grid-cols-2" aria-label="Password requirements">
                {requirements.map(({ label, valid }) => (
                  <li key={label} className={`flex items-center gap-2 text-[11px] ${valid ? "text-auth-valid" : "text-mute"}`}>
                    <span aria-hidden="true" className={`size-1.5 rounded-full ${valid ? "bg-emerald-500" : "bg-edge"}`} />{label}
                  </li>
                ))}
              </ul>
              <p id="password-error" className="mt-1 min-h-4 text-xs text-status-error" role={passwordError ? "alert" : undefined}>{passwordError}</p>
            </div>
            <div>
              <label htmlFor="confirm-password" className="mb-2 block text-xs font-medium text-text">Confirm password</label>
              <input id="confirm-password" name="confirm-password" type="password" autoComplete="new-password" required maxLength={128} value={confirmation}
                onBlur={() => setConfirmationTouched(true)} onChange={(event) => setConfirmation(event.target.value)}
                aria-invalid={Boolean(confirmationError)} aria-describedby="confirmation-error"
                className="auth-input w-full rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all focus:border-cyan-500 focus:ring-4 focus:ring-cyan-400/15" />
              <p id="confirmation-error" className="mt-1 min-h-4 text-xs text-status-error" role={confirmationError ? "alert" : undefined}>{confirmationError}</p>
            </div>
            {formError && <p role="alert" className="auth-error rounded-2xl border px-4 py-3 text-sm">{formError}</p>}
            <button type="submit" disabled={pending} className="group flex h-12 w-full items-center justify-center gap-2 rounded-full bg-brand px-5 text-sm font-semibold text-white shadow-[0_14px_36px_rgba(5,45,68,0.22)] transition-all hover:-translate-y-0.5 hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-50">
              {pending ? <><LoaderCircle size={16} className="animate-spin" /> Creating account</> : <>Create member account <ArrowRight size={16} className="transition-transform group-hover:translate-x-1" /></>}
            </button>
          </form>
          <p className="mt-5 border-t border-edge/40 pt-5 text-center text-sm text-mute">Already have an account? <Link to="/login" className="font-medium text-accent underline-offset-4 hover:underline">Sign in</Link></p>
          <div className="mt-5 flex items-center gap-2 text-[10px] uppercase tracking-[0.08em] text-mute"><ShieldCheck size={13} className="text-accent" /> Member accounts cannot access admin tools</div>
        </section>
      </main>
    </div>
  );
}
