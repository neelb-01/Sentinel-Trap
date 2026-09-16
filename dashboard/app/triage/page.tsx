import { TriageQueue } from "../components/TriageQueue";

export default function TriagePage() {
  return (
    <main className="flex flex-1 flex-col min-h-0 max-w-5xl w-full mx-auto p-6">
      <h1 className="text-lg font-semibold mb-4">SentinelTrap — triage</h1>
      <TriageQueue />
    </main>
  );
}
