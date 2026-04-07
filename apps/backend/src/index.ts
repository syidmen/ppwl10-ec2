import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { swagger } from "@elysiajs/swagger";
import { cookie } from "@elysiajs/cookie";
import { prisma } from "../prisma/db";
import { createOAuthClient, getAuthUrl } from "./auth";
import { getCourses, getCourseWorks, getSubmissions } from "./classroom";
import type { ApiResponse, HealthCheck, User } from "shared";

const tokenStore = new Map<string, { access_token: string; refresh_token?: string }>();

const app = new Elysia()
  .use(
    cors({
      origin: process.env.FRONTEND_URL || "http://localhost:5173",
      credentials: true,
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  )
  .use(swagger())
  .use(cookie())

  .onRequest(({ request, set }) => {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/users")) {
      const origin = request.headers.get("origin");
      const frontendUrl = process.env.FRONTEND_URL ?? "http://localhost:5173";
      const key = url.searchParams.get("key");

      if (origin === frontendUrl) return;

      if (key !== process.env.API_KEY) {
        set.status = 401;
        return { message: "Unauthorized: Access denied without valid API Key" };
      }
    }
  })

  .get("/", (): ApiResponse<HealthCheck> => ({
    data: { status: "ok" },
    message: "server running",
  }))

  .get("/users", async () => {
    const users = await prisma.user.findMany();
    return { data: users, message: "User list retrieved" };
  })

  // --- AUTH ROUTES ---

  .get("/auth/login", ({ redirect }) => {
    const oauth2Client = createOAuthClient();
    const url = getAuthUrl(oauth2Client);
    return redirect(url);
  })

  .get("/auth/callback", async ({ query, set, cookie, redirect }) => {
    const { code } = query as { code: string };
    if (!code) {
      set.status = 400;
      return { error: "Missing authorization code" };
    }

    const oauth2Client = createOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    const sessionId = crypto.randomUUID();

    tokenStore.set(sessionId, {
      access_token: tokens.access_token!,
      refresh_token: tokens.refresh_token ?? undefined,
    });

    // Paksa set kuki
    const session = (cookie as any).session;
    session.set({
      value: sessionId,
      maxAge: 60 * 60 * 24,
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    return redirect(`${process.env.FRONTEND_URL}/classroom`);
  })

  .get("/auth/me", ({ cookie }) => {
    // Cara paling ampuh: cast ke any dulu baru ambil value-nya
    const sessionId = (cookie as any).session.value as string;
    
    if (!sessionId || !tokenStore.has(sessionId)) {
      return { loggedIn: false };
    }
    return { loggedIn: true, sessionId };
  })

  .post("/auth/logout", ({ cookie }) => {
    const session = (cookie as any).session;
    const sessionId = session.value as string;
    if (sessionId) {
      tokenStore.delete(sessionId);
      session.remove();
    }
    return { success: true };
  })

  // --- CLASSROOM ROUTES ---

  .get("/classroom/courses", async ({ cookie, set }) => {
    const sessionId = (cookie as any).session.value as string;
    const tokens = sessionId ? tokenStore.get(sessionId) : null;

    if (!tokens) {
      set.status = 401;
      return { error: "Unauthorized. Silakan login terlebih dahulu." };
    }

    const courses = await getCourses(tokens.access_token);
    return { data: courses, message: "Courses retrieved" };
  })

  .get("/classroom/courses/:courseId/submissions", async ({ params, cookie, set }) => {
    const sessionId = (cookie as any).session.value as string;
    const tokens = sessionId ? tokenStore.get(sessionId) : null;

    if (!tokens) {
      set.status = 401;
      return { error: "Unauthorized. Silakan login terlebih dahulu." };
    }

    const { courseId } = params;
    const [courseWorks, submissions] = await Promise.all([
      getCourseWorks(tokens.access_token, courseId),
      getSubmissions(tokens.access_token, courseId),
    ]);

    const submissionMap = new Map(submissions.map((s: any) => [s.courseWorkId, s]));
    const result = courseWorks.map((cw: any) => ({
      courseWork: cw,
      submission: submissionMap.get(cw.id) ?? null,
    }));

    return { data: result, message: "Course submissions retrieved" };
  });

if (process.env.NODE_ENV !== "production") {
  app.listen(3000);
}

//tes

export default app;
export type App = typeof app;