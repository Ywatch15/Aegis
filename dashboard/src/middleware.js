import { createServerClient } from "@supabase/ssr";
import { NextResponse } from "next/server";

/**
 * Next.js middleware for Supabase Auth route protection + RBAC.
 * Redirects unauthenticated users to /login.
 * Admin-only routes require 'admin' role in profiles table.
 * If Supabase is not configured, allows all access (local dev mode).
 */
export async function middleware(request) {
  const { pathname } = request.nextUrl;

  // Public routes — always accessible
  const publicRoutes = ["/login", "/signup", "/auth/callback"];
  if (publicRoutes.some((route) => pathname.startsWith(route))) {
    return NextResponse.next();
  }

  // If Supabase is not configured, skip auth (local dev mode)
  if (
    !process.env.NEXT_PUBLIC_SUPABASE_URL ||
    !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  ) {
    // In local dev mode, set role header to 'admin' for full access
    const response = NextResponse.next();
    response.headers.set('x-user-role', 'admin');
    return response;
  }

  let response = NextResponse.next({
    request: { headers: request.headers },
  });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => {
            request.cookies.set(name, value);
            response.cookies.set(name, value, options);
          });
        },
      },
    }
  );

  // Refresh the session — this is required to keep auth tokens alive
  const {
    data: { user },
  } = await supabase.auth.getUser();

  // If no user and trying to access protected route → redirect to login
  if (!user) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Fetch user role from profiles table for RBAC
  let userRole = 'analyst'; // default
  try {
    const { data: profile } = await supabase
      .from('profiles')
      .select('role')
      .eq('id', user.id)
      .maybeSingle();

    if (profile?.role) {
      userRole = profile.role;
    }
  } catch {
    // If profiles table doesn't exist yet, default to analyst
  }

  // Admin-only route protection
  if (pathname.startsWith('/admin') && userRole !== 'admin') {
    // Redirect non-admin users to home page
    return NextResponse.redirect(new URL("/", request.url));
  }

  // Pass role to downstream pages via header
  response.headers.set('x-user-role', userRole);

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all routes except:
     * - _next/static (static files)
     * - _next/image (image optimization)
     * - favicon.ico (browser icon)
     * - public files (images, etc.)
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
