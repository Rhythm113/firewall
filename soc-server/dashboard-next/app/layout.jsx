import './globals.css';

export const metadata = {
  title: 'Nullsploit SOC Dashboard',
  description: 'WAF Control Center & Advanced Intrusion Detection Engine',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="true" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body className="antialiased bg-gray-950 text-gray-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
