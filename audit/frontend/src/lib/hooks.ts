"use client";

import { useCallback, useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useTheme } from "next-themes";
import { api, clearToken, getToken } from "./api";

/** Redirects to /login?next=... when no token is stored. Returns true once a token exists. */
export function useRequireAuth() {
  const router = useRouter();
  const pathname = usePathname();
  const [ok, setOk] = useState(false);
  useEffect(() => {
    if (!getToken()) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
    } else {
      setOk(true);
    }
  }, [router, pathname]);
  return ok;
}

export function useOrg() {
  return useQuery({ queryKey: ["org"], queryFn: api.org.get });
}

/** Operator access is decided by the backend: GET /org reports whether the caller is staff. */
export function useIsOperator() {
  const q = useOrg();
  const isOperator = Boolean(q.data?.viewer_is_operator);
  return { isOperator, checked: q.isSuccess || q.isError, denied: q.isSuccess && !isOperator };
}

export async function logout() {
  try {
    if (getToken()) await api.auth.logout();
  } catch {
    // Logging out must always succeed locally even if the server call fails.
  }
  clearToken();
  if (typeof window !== "undefined") window.location.href = "/login";
}

/** localStorage-backed state that tolerates blocked storage and SSR. */
export function useStoredState<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(initial);
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(key);
      if (raw != null) setValue(JSON.parse(raw) as T);
    } catch {
      /* storage unavailable: keep the initial value */
    }
  }, [key]);
  const set = useCallback(
    (v: T) => {
      setValue(v);
      try {
        window.localStorage.setItem(key, JSON.stringify(v));
      } catch {
        /* ignore */
      }
    },
    [key]
  );
  return [value, set];
}

/** Theme switch that adds a short global color crossfade, then removes it. */
export function useThemeSwitch() {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const apply = useCallback(
    (next: string) => {
      const root = document.documentElement;
      const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (!reduced) {
        root.classList.add("theme-transition");
        window.setTimeout(() => root.classList.remove("theme-transition"), 300);
      }
      setTheme(next);
    },
    [setTheme]
  );
  const toggle = useCallback(() => apply(resolvedTheme === "dark" ? "light" : "dark"), [apply, resolvedTheme]);
  return { theme, resolvedTheme, setTheme: apply, toggle };
}

/** Debounce a fast-changing value (search inputs). */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
