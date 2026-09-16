import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SentinelTrap",
  description: "SentinelTrap live event feed",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="h-full flex flex-col overflow-hidden">
        <nav className="flex gap-4 border-b border-zinc-200 dark:border-zinc-800 px-6 py-2.5 text-sm">
          <Link href="/" className="text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100">
            Live feed
          </Link>
          <Link href="/triage" className="text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100">
            Triage
          </Link>
        </nav>
        {children}
      </body>
    </html>
  );
}
