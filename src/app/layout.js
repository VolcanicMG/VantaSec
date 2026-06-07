import "./globals.css";

// Nonce-based CSP (see src/proxy.js) requires dynamic rendering so the
// per-request nonce can be injected into framework scripts.
export const dynamic = "force-dynamic";

/**
 * Root layout + document metadata.
 */
export const metadata = {
  title: "Vantasec — public surface scanner",
  description: "Scan a site or IP you own for open ports, TLS, DNS, and security headers.",
};

/**
 * @param {{children: React.ReactNode}} props
 * @returns {JSX.Element}
 */
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">{children}</body>
    </html>
  );
}
