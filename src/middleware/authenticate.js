export async function authenticate(request, env) {
  const authHeader = request.headers.get("Authorization");
  let token = null;
  if (authHeader) {
    if (authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7).trim();
    } else {
      token = authHeader.trim();
    }
  }
  if (!token) {
    token = new URL(request.url).searchParams.get("token");
  }
  if (!token) {
    return {
      success: false,
      status: 401,
      message: "Authentication required."
    };
  }
  try {
    const session = await env.DB
      .prepare(`
        SELECT
          s.token,
          s.user_id,
          s.expires_at,
          s.active,
          u.*
        FROM sessions s
        INNER JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        LIMIT 1
      `)
      .bind(token)
      .first();
    if (!session) {
      return {
        success: false,
        status: 401,
        message: "Invalid session."
      };
    }
    if (!Number(session.active)) {
      return {
        success: false,
        status: 401,
        message: "Session inactive."
      };
    }
    if (Date.now() > Number(session.expires_at)) {
      await env.DB
        .prepare("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .run();
      return {
        success: false,
        status: 401,
        message: "Session expired."
      };
    }
    if (session.account_status !== "active") {
      return {
        success: false,
        status: 403,
        message: "Your account is not active."
      };
    }
    const {
      token: sessionToken,
      user_id,
      expires_at,
      active,
      ...user
    } = session;
    return {
      success: true,
      token: sessionToken,
      user
    };
  } catch (error) {
    console.error("[BiiGi Auth] Authentication error:", error);
    return {
      success: false,
      status: 500,
      message: "Authentication failed."
    };
  }
}