"use client";

import { useState } from "react";
import Link from "next/link";
import { createClient } from "@/lib/supabaseClient";

/* ── SVG Shield Icon ─────────────────────────────────────────── */
function ShieldIcon() {
  return (
    <svg
      className="w-10 h-10 text-cyber-blue drop-shadow-[0_0_12px_rgba(0,212,255,0.5)]"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2L3 7v5c0 5.25 3.75 10.13 9 11.43C17.25 22.13 21 17.25 21 12V7l-9-5z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

/* ── Success Checkmark Icon ──────────────────────────────────── */
function CheckCircleIcon() {
  return (
    <svg
      className="w-14 h-14 text-cyber-green drop-shadow-[0_0_18px_rgba(0,255,136,0.5)]"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M8 12l3 3 5-6" />
    </svg>
  );
}

/* ── Page ─────────────────────────────────────────────────────── */
export default function SignupPage() {
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    // ── Client-side validation ──────────────────────────────
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);

    try {
      const supabase = createClient();
      const { error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            display_name: displayName,
          },
        },
      });

      if (authError) {
        setError(authError.message);
        return;
      }

      setSuccess(true);
    } catch (err) {
      setError("An unexpected error occurred. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-aegis-bg bg-hex-grid flex items-center justify-center px-4">
      {/* Ambient glow */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-aegis-glow/[0.03] rounded-full blur-[120px]" />
      </div>

      <div className="relative w-full max-w-md animate-fade-up">
        {/* ── Card ─────────────────────────────────────────────── */}
        <div className="bg-aegis-surface border border-aegis-border p-8 md:p-10 space-y-8">
          {/* Top edge accent line */}
          <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-aegis-glow/60 to-transparent" />

          {/* ── Header ──────────────────────────────────────────── */}
          <div className="flex flex-col items-center gap-3 text-center">
            <ShieldIcon />
            <div>
              <h1 className="text-2xl font-sans font-bold text-cyber-blue tracking-tight">
                AegisAPI
              </h1>
              <p className="text-xs font-sans text-text-muted uppercase tracking-[0.25em] mt-1">
                Operator Registration
              </p>
            </div>
          </div>

          {/* ── Divider ─────────────────────────────────────────── */}
          <div className="h-px bg-aegis-border" />

          {/* ── Success State ───────────────────────────────────── */}
          {success ? (
            <div className="flex flex-col items-center gap-5 py-6 animate-fade-up">
              <CheckCircleIcon />
              <div className="text-center space-y-2">
                <h2 className="text-lg font-sans font-semibold text-text-primary">
                  Registration Initiated
                </h2>
                <p className="text-sm text-text-secondary leading-relaxed max-w-xs">
                  Check your email for a confirmation link to activate your
                  operator account.
                </p>
              </div>
              <div className="w-full h-px bg-aegis-border mt-2" />
              <Link
                href="/login"
                className="text-sm text-cyber-blue hover:text-cyber-blue/80 font-medium transition-colors"
              >
                ← Return to Sign In
              </Link>
            </div>
          ) : (
            /* ── Form ──────────────────────────────────────────── */
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* ── Error Alert ─────────────────────────────────── */}
              {error && (
                <div className="bg-threat-high/10 border border-threat-high/40 px-4 py-3 flex items-start gap-3 animate-fade-up">
                  <svg
                    className="w-5 h-5 text-threat-high shrink-0 mt-0.5"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                  >
                    <path
                      fillRule="evenodd"
                      d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z"
                      clipRule="evenodd"
                    />
                  </svg>
                  <span className="text-sm text-threat-high font-mono">
                    {error}
                  </span>
                </div>
              )}

              {/* ── Display Name ─────────────────────────────────── */}
              <div className="space-y-1.5">
                <label className="text-xs font-sans text-text-muted uppercase tracking-widest">
                  Display Name
                </label>
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Operator callsign"
                  className="w-full bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm
                             px-3.5 py-2.5 placeholder:text-text-dim
                             focus:outline-none focus:border-aegis-glow focus:ring-1 focus:ring-aegis-glow/30
                             transition-colors duration-150"
                />
              </div>

              {/* ── Email ────────────────────────────────────────── */}
              <div className="space-y-1.5">
                <label className="text-xs font-sans text-text-muted uppercase tracking-widest">
                  Email
                </label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@aegis.io"
                  className="w-full bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm
                             px-3.5 py-2.5 placeholder:text-text-dim
                             focus:outline-none focus:border-aegis-glow focus:ring-1 focus:ring-aegis-glow/30
                             transition-colors duration-150"
                />
              </div>

              {/* ── Password ─────────────────────────────────────── */}
              <div className="space-y-1.5">
                <label className="text-xs font-sans text-text-muted uppercase tracking-widest">
                  Password
                </label>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-aegis-panel border border-aegis-border text-text-primary font-mono text-sm
                             px-3.5 py-2.5 placeholder:text-text-dim
                             focus:outline-none focus:border-aegis-glow focus:ring-1 focus:ring-aegis-glow/30
                             transition-colors duration-150"
                />
              </div>

              {/* ── Confirm Password ─────────────────────────────── */}
              <div className="space-y-1.5">
                <label className="text-xs font-sans text-text-muted uppercase tracking-widest">
                  Confirm Password
                </label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className={`w-full bg-aegis-panel border text-text-primary font-mono text-sm
                             px-3.5 py-2.5 placeholder:text-text-dim
                             focus:outline-none focus:ring-1 transition-colors duration-150
                             ${
                               confirmPassword &&
                               confirmPassword !== password
                                 ? "border-threat-high/60 focus:border-threat-high focus:ring-threat-high/30"
                                 : "border-aegis-border focus:border-aegis-glow focus:ring-aegis-glow/30"
                             }`}
                />
                {confirmPassword && confirmPassword !== password && (
                  <p className="text-xs text-threat-high font-mono mt-1">
                    Passwords do not match
                  </p>
                )}
              </div>

              {/* ── Submit ────────────────────────────────────────── */}
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-aegis-glow text-white font-sans font-medium text-sm
                           py-2.5 mt-2
                           hover:brightness-110 active:brightness-90
                           disabled:opacity-50 disabled:cursor-not-allowed
                           transition-all duration-150
                           flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <svg
                      className="animate-spin h-4 w-4 text-white"
                      viewBox="0 0 24 24"
                      fill="none"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                      />
                    </svg>
                    <span>Creating Account…</span>
                  </>
                ) : (
                  "Create Account"
                )}
              </button>

              {/* ── Footer Link ──────────────────────────────────── */}
              <p className="text-center text-sm text-text-muted pt-2">
                Already have an account?{" "}
                <Link
                  href="/login"
                  className="text-cyber-blue hover:text-cyber-blue/80 font-medium transition-colors"
                >
                  Sign In
                </Link>
              </p>
            </form>
          )}
        </div>

        {/* ── Bottom classification strip ───────────────────────── */}
        <div className="mt-4 flex items-center justify-center gap-2 text-text-dim">
          <div className="h-px w-8 bg-aegis-border" />
          <span className="text-[10px] font-mono uppercase tracking-widest">
            Secure Enrollment
          </span>
          <div className="h-px w-8 bg-aegis-border" />
        </div>
      </div>
    </div>
  );
}
