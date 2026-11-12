import { createContext, useContext, useState, type ReactNode } from "react";
import type { RTEvent } from "../../types";

export type HuntView = {
  projectId: string;
  events: RTEvent[];
  running: boolean;
};

const HuntViewCtx = createContext<{
  view: HuntView | null;
  setView: (view: HuntView | null) => void;
}>({ view: null, setView: () => {} });

export function HuntViewProvider({ children }: { children: ReactNode }) {
  const [view, setView] = useState<HuntView | null>(null);
  return <HuntViewCtx.Provider value={{ view, setView }}>{children}</HuntViewCtx.Provider>;
}

export function useHuntView() {
  return useContext(HuntViewCtx);
}
