import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { HashRouter } from "react-router-dom"

import "./index.css"
import App from "./App.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"
import { consumeAuthMiniCallback } from "@/lib/auth-redirect.ts"

const authRedirectError = consumeAuthMiniCallback()
const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, staleTime: 30_000 } },
})

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <ThemeProvider>
          <App startupError={authRedirectError} />
        </ThemeProvider>
      </HashRouter>
    </QueryClientProvider>
  </StrictMode>
)
