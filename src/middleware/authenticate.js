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
                    u.id,
                    u.full_name,
                    u.email,
                    u.phone,
                    u.city,
                    u.account_status,
                    u.created_at AS user_created_at,
                    u.updated_at
                FROM sessions s
                INNER JOIN users u
                    ON u.id = s.user_id
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
    return {
      success: true,
      token,
      user: {
        id: session.id,
        full_name: session.full_name,
        email: session.email,
        phone: session.phone,
        city: session.city,
        account_status: session.account_status,
        created_at: session.user_created_at,
        updated_at: session.updated_at
      }
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