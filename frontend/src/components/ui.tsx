import { useId, type InputHTMLAttributes, type ReactNode } from "react";
import { useAuth } from "../auth";
import { DEFAULT_LOGO, useSwfConfig } from "../config";

export function Alert({ kind, children }: { kind: "error" | "success" | "info" | "warning"; children: ReactNode }) {
  if (!children) return null;
  return (
    <div className={`alert ${kind}`} role={kind === "error" ? "alert" : "status"}>
      {children}
    </div>
  );
}

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: ReactNode;
}

export function Field({ label, hint, className, ...input }: FieldProps) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} className={className} {...input} />
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

/** Six-digit authenticator code input. */
export function CodeField({
  value,
  onChange,
  label = "6-digit code",
  autoFocus,
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
  autoFocus?: boolean;
}) {
  return (
    <Field
      label={label}
      hint="Open your authenticator app and type the code shown for this app. It changes every 30 seconds."
      className="code"
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      pattern="[0-9]{6}"
      required
      autoFocus={autoFocus}
      value={value}
      onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
    />
  );
}

export function Brand() {
  const { config } = useAuth();
  const { logoSrc } = useSwfConfig();
  return (
    <div className="brand">
      <img src={logoSrc ?? DEFAULT_LOGO} alt="" />
      <span>{config?.app_name ?? ""}</span>
    </div>
  );
}

export function AuthCard({ children, wide }: { children: ReactNode; wide?: boolean }) {
  const { signInFooter } = useSwfConfig();
  return (
    <div className="auth-page">
      <div className={`auth-card${wide ? " wide" : ""}`}>
        <Brand />
        {children}
        {signInFooter && <div className="small muted auth-footer">{signInFooter}</div>}
      </div>
    </div>
  );
}

export function Card({ children, className = "", style }: { children: ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`card ${className}`} style={style}>
      {children}
    </div>
  );
}

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="page-header">
      <h1>{title}</h1>
      {children && <p>{children}</p>}
    </div>
  );
}
