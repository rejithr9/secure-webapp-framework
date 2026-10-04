# @swf/web

The React front end of the [Secure Web App Framework](https://github.com/rejithr9/secure-webapp-framework):
sign-in with 2FA, passkeys and recovery codes, terms, account, keys, activity and admin screens, plus
your own pages in a shared shell.

```tsx
import { SwfApp } from "@swf/web";
import "@swf/web/styles.css";

<SwfApp config={{ home: <Dashboard />, nav: [{ path: "/projects", label: "Projects", element: <Projects /> }] }} />;
```

Peer dependencies: `react`, `react-dom` (19) and `react-router-dom` (7). Licence: MIT.
