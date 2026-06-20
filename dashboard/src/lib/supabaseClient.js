"use client";

import { createBrowserClient } from "@supabase/ssr";

/**
 * Browser-side Supabase client for real-time subscriptions and auth.
 * Uses the anon key (safe for client-side).
 */
export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL || "",
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || ""
  );
}
