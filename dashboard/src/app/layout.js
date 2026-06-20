import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  display: "swap",
});

export const metadata = {
  title: "AegisAPI — Security Operations Dashboard",
  description:
    "Real-time threat monitoring, WAF analytics, and incident response dashboard for AegisAPI Gateway.",
  keywords: [
    "WAF",
    "security",
    "API gateway",
    "rate limiting",
    "threat detection",
  ],
};

export default function RootLayout({ children }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} dark h-full`}
    >
      <body className="min-h-full bg-aegis-bg text-text-primary font-sans antialiased">
        {children}
      </body>
    </html>
  );
}
