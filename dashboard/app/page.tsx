import { LiveFeed } from "./components/LiveFeed";

export default function Home() {
  return (
    <main className="flex flex-1 flex-col min-h-0 max-w-5xl w-full mx-auto p-6">
      <h1 className="text-lg font-semibold mb-4">SentinelTrap — live feed</h1>
      <LiveFeed />
    </main>
  );
}
