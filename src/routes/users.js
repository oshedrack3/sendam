import { authenticate } from "../middleware/authenticate.js";

export async function handleUserRequest(request, env) {
  const auth = await authenticate(request, env);
  if (!auth.success) {
    return Response.json({
      success: false,
      message: auth.message
    }, {
      status: auth.status
    });
  }
  const url = new URL(request.url);
  const pathname = url.pathname.replace(/\/+$/, "") || "/";
  try {
    if (pathname === "/user/profile" && request.method === "GET") {
      return await getUserProfileRoute(request, env, auth);
    }
    return Response.json({
      success: false,
      message: "User route not found."
    }, {
      status: 404
    });
  } catch (error) {
    console.error("BiiGi user request error:", error);
    return Response.json({
      success: false,
      message: "An internal server error occurred."
    }, {
      status: 500
    });
  }
}
export async function getUserProfileRoute(request, env, auth) {
  const user = await env.DB
    .prepare("SELECT * FROM users WHERE id = ? LIMIT 1")
    .bind(auth.user.id)
    .first();
  if (!user) {
    return Response.json({
      success: false,
      message: "User account not found."
    }, {
      status: 404
    });
  }
  delete user.password_hash;
  return Response.json({
    success: true,
    user
  });
}