import { SettingsView } from "./view"

export function generateStaticParams() {
  return ["account", "hunt", "review", "proxy", "model"].map((section) => ({ section }))
}

export default function SettingsPage() {
  return <SettingsView />
}
