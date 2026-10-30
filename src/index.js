import { handleAuthRequest } from "./routes/auth.js";
import { handleUserRequest } from "./routes/users.js";
import { handleProviderRequest } from "./routes/providers.js";
const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST,DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
};

function json(data, options = {}) {
    return Response.json(data, {
        ...options,
        headers: {
            ...corsHeaders,
            ...(options.headers || {})
        }
    });
}

function addCors(response) {
    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(corsHeaders)) {
        headers.set(key, value);
    }
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
    });
}
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const pathname =
            url.pathname.replace(/\/+$/, "") || "/";
        try {
            if (request.method === "OPTIONS") {
                return new Response(null, {
                    status: 204,
                    headers: corsHeaders
                });
            }
            if (pathname === "/") {
                return json({
                    success: true,
                    message: "BiiGi backend is running."
                });
            }
            if (
                pathname === "/test-db" &&
                request.method === "GET"
            ) {
                const result = await env.DB
                    .prepare("SELECT 1 AS connected")
                    .first();
                return json({
                    success: true,
                    message: "BiiGi database connected successfully.",
                    database: result
                });
            }
            if (pathname.startsWith("/auth/")) {
                return addCors(
                    await handleAuthRequest(request, env)
                );
            }
            if (pathname.startsWith("/user/")) {
                return addCors(
                    await handleUserRequest(request, env)
                );
            }
            if (pathname.startsWith("/providers")) {
                const response = await handleProviderRequest(
                    request,
                    env
                );
                if (response) {
                    return addCors(response);
                }
            }
            return json({
                success: false,
                message: "Route not found."
            }, {
                status: 404
            });
        } catch (error) {
            console.error("BiiGi Worker error:", error);
            return json({
                success: false,
                message: "An internal server error occurred."
            }, {
                status: 500
            });
        }
    }
};