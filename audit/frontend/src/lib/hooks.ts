"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { api, clearToken, getToken } from "./api";

/** Redirects to /login if no token is present. */
export function useRequireAuth() {
  const router = useRouter();
  useEffect(() => {
    if (!getToken()) router.replace("/login");
  }, [router]);
}

export function useOrg() {
  return useQuery({ queryKey: ["org"], queryFn: api.org.get });
}

export function logout() {
  clearToken();
  if (typeof window !== "undefined") window.location.href = "/login";
}
