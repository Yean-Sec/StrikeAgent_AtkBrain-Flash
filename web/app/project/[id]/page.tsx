import { ProjectView } from "./view"

export function generateStaticParams() {
  return [{ id: "_" }]
}

export default function ProjectPage() {
  return <ProjectView />
}
