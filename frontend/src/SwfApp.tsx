import type { ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AdminPage } from "./admin/Admin";
import { AuthProvider, requiredPath, useAuth } from "./auth";
import { FRAMEWORK_PATHS, SwfConfigContext, type SwfAppConfig } from "./config";
import { Layout } from "./components/Layout";
import { AccountPage } from "./pages/Account";
import { ActivityPage } from "./pages/Activity";
import { KeysPage } from "./pages/Keys";
import { SecondStepPage, SignInPage } from "./pages/SignIn";
import { TotpSetupPage } from "./pages/TotpSetup";
import { ChangeInitialPasswordPage, TermsPage } from "./pages/Welcome";

/** Sends the user to the one step they must complete, or lets them into the app. */
function Gate({ children }: { children: ReactNode }) {
  const { state } = useAuth();
  const location = useLocation();
  if (state === null) {
    return <div className="auth-page muted">Loading…</div>;
  }
  const required = requiredPath(state);
  if (required && location.pathname !== required) return <Navigate to={required} replace />;
  const inSignInFlow = location.pathname.startsWith("/sign-in") || location.pathname.startsWith("/welcome");
  if (!required && inSignInFlow) return <Navigate to="/" replace />;
  return <>{children}</>;
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { state } = useAuth();
  return state?.user?.role === "admin" ? <>{children}</> : <Navigate to="/" replace />;
}

function KeysOnly({ children }: { children: ReactNode }) {
  const { config } = useAuth();
  if (config === null) return null;
  return config.keys_enabled ? <>{children}</> : <Navigate to="/" replace />;
}

function AppRoutes({ config }: { config: SwfAppConfig }) {
  return (
    <Gate>
      <Routes>
        <Route path="/sign-in" element={<SignInPage />} />
        <Route path="/sign-in/code" element={<SecondStepPage />} />
        <Route path="/sign-in/set-up-2fa" element={<TotpSetupPage />} />
        <Route path="/welcome/password" element={<ChangeInitialPasswordPage />} />
        <Route path="/welcome/terms" element={<TermsPage />} />
        <Route element={<Layout />}>
          <Route index element={config.home} />
          {(config.nav ?? []).map((item) => (
            <Route
              key={item.path}
              path={item.path}
              element={item.adminOnly ? <AdminOnly>{item.element}</AdminOnly> : item.element}
            />
          ))}
          <Route
            path="/keys"
            element={
              <KeysOnly>
                <KeysPage />
              </KeysOnly>
            }
          />
          <Route path="/activity" element={<ActivityPage />} />
          <Route path="/account" element={<AccountPage />} />
          <Route
            path="/admin"
            element={
              <AdminOnly>
                <AdminPage />
              </AdminOnly>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Gate>
  );
}

/**
 * The whole framework UI: sign-in with 2FA and passkeys, terms, account, keys, activity and
 * admin screens, plus your own pages inside the signed-in shell.
 */
export function SwfApp({ config }: { config: SwfAppConfig }) {
  for (const item of config.nav ?? []) {
    if (item.path === "/" || FRAMEWORK_PATHS.some((p) => item.path === p || item.path.startsWith(p + "/"))) {
      throw new Error(`SwfApp: nav path "${item.path}" clashes with a framework page`);
    }
  }
  return (
    <SwfConfigContext.Provider value={config}>
      <BrowserRouter>
        <AuthProvider>
          <AppRoutes config={config} />
        </AuthProvider>
      </BrowserRouter>
    </SwfConfigContext.Provider>
  );
}
