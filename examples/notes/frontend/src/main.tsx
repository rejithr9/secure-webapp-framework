import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { SwfApp } from "@swf/web";
import "@swf/web/styles.css";
import { Home, NotesPage } from "./Notes";

// Everything else (sign-in, 2FA, passkeys, terms, account, activity, admin) comes from the framework.
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <SwfApp config={{ home: <Home />, nav: [{ path: "/notes", label: "My notes", element: <NotesPage /> }] }} />
  </StrictMode>,
);
