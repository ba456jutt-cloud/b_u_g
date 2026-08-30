import Link from 'next/link';
import './globals.css';
import ActivitySidebarClient from '@/components/ActivitySidebarClient';

export const metadata = {
  title: 'Bug Bounty Copilot',
  description: 'AI-Powered Security Research Platform',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-white min-h-screen font-sans antialiased">
        <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>

          {/* ── Left Sidebar — Navigation ── */}
          <aside style={{
            width: '220px', flexShrink: 0,
            background: '#0a0f1e',
            borderRight: '1px solid #1e293b',
            display: 'flex', flexDirection: 'column',
          }}>
            {/* Logo */}
            <div style={{ padding: '18px 16px 14px', borderBottom: '1px solid #1e293b' }}>
              <div style={{
                fontSize: '16px', fontWeight: 800, letterSpacing: '-0.02em',
                background: 'linear-gradient(135deg, #60a5fa, #818cf8)',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
                lineHeight: 1.2,
              }}>
                Bug Bounty<br />Copilot
              </div>
              <div style={{ fontSize: '10px', color: '#334155', marginTop: '3px' }}>
                AI Security Platform
              </div>
            </div>

            {/* Nav links */}
            <nav style={{ flex: 1, padding: '12px 10px', overflowY: 'auto' }}>
              {[
                { href: '/',           label: '🏠', text: 'Dashboard' },
                { href: '/agents',     label: '🤖', text: 'Agents' },
                { href: '/analysis/new', label: '🚀', text: 'New Scan' },
                { href: '/projects',   label: '🎯', text: 'Scan History' },
                { href: '/chat',       label: '💬', text: 'Chat' },
                { href: '/knowledge',  label: '📚', text: 'Knowledge' },
                { href: '/reports',    label: '📄', text: 'Reports' },
                { href: '/settings',   label: '⚙️', text: 'Settings' },
              ].map(({ href, label, text }) => (
                <Link
                  key={href}
                  href={href}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '10px',
                    padding: '8px 12px', borderRadius: '8px',
                    color: '#64748b', textDecoration: 'none',
                    fontSize: '13px', fontWeight: 500,
                    marginBottom: '2px',
                    transition: 'all 0.15s',
                  }}
                  className="nav-link"
                >
                  <span style={{ fontSize: '14px' }}>{label}</span>
                  <span>{text}</span>
                </Link>
              ))}
            </nav>

            {/* Status indicator */}
            <div style={{ padding: '10px 14px', borderTop: '1px solid #1e293b' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{
                  width: '7px', height: '7px', borderRadius: '50%',
                  background: '#22c55e',
                  boxShadow: '0 0 6px #22c55e',
                }} />
                <span style={{ fontSize: '10px', color: '#334155' }}>
                  PKCERT Bug Bounty — Live
                </span>
              </div>
            </div>
          </aside>

          {/* ── Center — Main Content ── */}
          <main style={{ flex: 1, overflowY: 'auto', background: '#030712', padding: '28px 32px' }}>
            {children}
          </main>

          {/* ── Right Sidebar — Agent Live Activity ── */}
          <div style={{
            width: '320px', flexShrink: 0,
            display: 'flex', flexDirection: 'column',
            borderLeft: '1px solid #1e293b',
            background: '#030712',
          }}>
            <ActivitySidebarClient />
          </div>

        </div>

        {/* Global nav hover style */}
        <style>{`
          .nav-link:hover {
            background: rgba(99, 102, 241, 0.1) !important;
            color: #818cf8 !important;
          }
          ::-webkit-scrollbar { width: 5px; }
          ::-webkit-scrollbar-track { background: #030712; }
          ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
          ::-webkit-scrollbar-thumb:hover { background: #334155; }
        `}</style>
      </body>
    </html>
  );
}
