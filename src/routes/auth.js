import { randomUUID } from "node:crypto";

export async function handleAuthRequest(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "POST" && pathname === "/auth/register") {
        return register(request, env);
    }
    if (request.method === "POST" && pathname === "/auth/login") {
        return login(request, env);
    }
    if (request.method === "POST" && pathname === "/auth/logout") {
        return logout(request, env);
    }
    if (request.method === "GET" && pathname === "/auth/me") {
        return verifySession(request, env);
    }
    return Response.json({
        success: false,
        message: "Authentication route not found."
    }, { status: 404 });
}

async function register(request, env) {
    try {
        const body = await request.json();
        const fullName = String(body.fullName || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const phone = String(body.phone || "").trim();
        const city = String(body.city || "").trim();
        const homeAddress = String(body.homeAddress || "").trim();
        const password = String(body.password || "");
        if (!fullName || !email || !city || !homeAddress || !password) {
            return Response.json({
                success: false,
                message: "Full name, email, city, home address and password are required."
            }, { status: 400 });
        }
        if (fullName.length > 100) {
            return Response.json({
                success: false,
                message: "Full name must not exceed 100 characters."
            }, { status: 400 });
        }
        if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return Response.json({
                success: false,
                message: "Enter a valid email address."
            }, { status: 400 });
        }
        if (phone && !/^\+?[0-9\s()-]{7,20}$/.test(phone)) {
            return Response.json({
                success: false,
                message: "Enter a valid phone number."
            }, { status: 400 });
        }
        if (city.length > 100 || homeAddress.length > 300) {
            return Response.json({
                success: false,
                message: "City or home address is too long."
            }, { status: 400 });
        }
        if (password.length < 8 || password.length > 128) {
            return Response.json({
                success: false,
                message: "Password must be between 8 and 128 characters."
            }, { status: 400 });
        }
        const existingEmail = await env.DB.prepare(
            "SELECT id FROM users WHERE email = ? COLLATE NOCASE LIMIT 1"
        ).bind(email).first();
        if (existingEmail) {
            return Response.json({
                success: false,
                message: "An account with this email already exists."
            }, { status: 409 });
        }
        if (phone) {
            const existingPhone = await env.DB.prepare(
                "SELECT id FROM users WHERE phone = ? LIMIT 1"
            ).bind(phone).first();
            if (existingPhone) {
                return Response.json({
                    success: false,
                    message: "An account with this phone number already exists."
                }, { status: 409 });
            }
        }
        const id = randomUUID();
        const now = Date.now();
        const passwordHash = await hashPassword(password);
        await env.DB.prepare(`
            INSERT INTO users (
                id,
                full_name,
                email,
                phone,
                city,
                home_address,
                password_hash,
                account_status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        `).bind(
            id,
            fullName,
            email,
            phone || null,
            city,
            homeAddress,
            passwordHash,
            now,
            now
        ).run();
        return Response.json({
            success: true,
            message: "Your SendAm account has been created successfully.",
            user: {
                id,
                fullName,
                email,
                phone: phone || null,
                city,
                homeAddress,
                accountStatus: "active",
                createdAt: now
            }
        }, { status: 201 });
    } catch (error) {
        console.error("SendAm registration error:", error);
        const message = String(error?.message || "").toLowerCase();
        if (message.includes("unique constraint")) {
            return Response.json({
                success: false,
                message: "An account with these details already exists."
            }, { status: 409 });
        }
        return Response.json({
            success: false,
            message: "Unable to create your account. Please try again."
        }, { status: 500 });
    }
}
async function login(request, env) {
    try {
        const body = await request.json();

        const loginValue = String(body.login || "").trim();
        const password = String(body.password || "");
        if (!loginValue || !password) {
            return Response.json({
                success: false,
                message: "Email or phone number and password are required."
            }, { status: 400 });
        }
        const user = await env.DB.prepare(`
            SELECT
                id,
                full_name,
                email,
                phone,
                city,
                home_address,
                password_hash,
                account_status,
                created_at
            FROM users
            WHERE email = ? COLLATE NOCASE
               OR phone = ?
            LIMIT 1
        `).bind(loginValue, loginValue).first();
        if (!user) {
            return Response.json({
                success: false,
                message: "Invalid login details."
            }, { status: 401 });
        }
        if (user.account_status !== "active") {
            return Response.json({
                success: false,
                message: "Your account is currently unavailable. Please contact SendAm support."
            }, { status: 403 });
        }
        const validPassword = await verifyPassword(
            password,
            user.password_hash
        );
        if (!validPassword) {
            return Response.json({
                success: false,
                message: "Invalid login details."
            }, { status: 401 });
        }
        const token = randomUUID();
        const now = Date.now();
        const expiresAt = now + 30 * 24 * 60 * 60 * 1000;
        await env.DB.prepare(`
            INSERT INTO sessions (
                token,
                user_id,
                created_at,
                expires_at,
                active
            )
            VALUES (?, ?, ?, ?, 1)
        `).bind(
            token,
            user.id,
            now,
            expiresAt
        ).run();
        return Response.json({
            success: true,
            message: "Login successful.",
            token,
            expiresAt,
            user: safeUser(user)
        });
    } catch (error) {
        console.error("SendAm login error:", error);
        return Response.json({
            success: false,
            message: "Unable to log in. Please try again."
        }, { status: 500 });
    }
}

async function logout(request, env) {
    try {
        const token = getToken(request);

        if (!token) {
            return Response.json({
                success: false,
                message: "You are not logged in."
            }, { status: 401 });
        }
        await env.DB.prepare(`
            DELETE FROM sessions WHERE token = ?
        `).bind(token).run();
        return Response.json({
            success: true,
            message: "You have logged out successfully."
        });
    } catch (error) {
        console.error("SendAm logout error:", error);
        return Response.json({
            success: false,
            message: "Unable to log out. Please try again."
        }, { status: 500 });
    }
}

async function verifySession(request, env) {
    try {
        const token = getToken(request);

        if (!token) {
            return Response.json({
                success: false,
                message: "Authentication required."
            }, { status: 401 });
        }
        const now = Date.now();
        const user = await env.DB.prepare(`
            SELECT
                u.id,
                u.full_name,
                u.email,
                u.phone,
                u.city,
                u.home_address,
                u.account_status,
                u.created_at
            FROM sessions s
            INNER JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
              AND s.active = 1
              AND s.expires_at > ?
            LIMIT 1
        `).bind(token, now).first();
        if (!user) {
            await env.DB.prepare(`
                DELETE FROM sessions
                WHERE token = ?
            `).bind(token).run();
            return Response.json({
                success: false,
                message: "Your session has expired. Please log in again."
            }, { status: 401 });
        }
        if (user.account_status !== "active") {
            await env.DB.prepare(`
                DELETE FROM sessions
                WHERE token = ?
            `).bind(token).run();
            return Response.json({
                success: false,
                message: "Your account is currently unavailable."
            }, { status: 403 });
        }
        return Response.json({
            success: true,
            user: safeUser(user)
        });
    } catch (error) {
        console.error("SendAm session verification error:", error);
        return Response.json({
            success: false,
            message: "Unable to verify your session."
        }, { status: 500 });
    }
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
    }, key, 256);
    return `${arrayBufferToBase64(salt)}.${arrayBufferToBase64(bits)}`;
}

async function verifyPassword(password, storedHash) {
    if (!storedHash || !storedHash.includes(".")) {
        return false;
    }
    const parts = storedHash.split(".");
    if (parts.length !== 2) {
        return false;
    }
    try {
        const salt = base64ToUint8Array(parts[0]);
        const expectedHash = base64ToUint8Array(parts[1]);
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );
        const bits = await crypto.subtle.deriveBits({
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256"
        }, key, 256);
        const actualHash = new Uint8Array(bits);
        if (actualHash.length !== expectedHash.length) {
            return false;
        }
        let difference = 0;
        for (let i = 0; i < actualHash.length; i++) {
            difference |= actualHash[i] ^ expectedHash[i];
        }
        return difference === 0;
    } catch (error) {
        console.error("Password verification error:", error);
        return false;
    }
}
function getToken(request) {
    const authorization = request.headers.get("Authorization") || "";
    const match = authorization.match(/^Bearer\s+(.+)$/i);

    return match ? match[1].trim() : "";
}

function safeUser(user) {
    return {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        city: user.city,
        homeAddress: user.home_address,
        accountStatus: user.account_status,
        createdAt: user.created_at
    };
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
