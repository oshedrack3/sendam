import { authenticate } from "../middleware/authenticate.js";
export async function handleProviderRequest(
  request,
  env
) {
  const url = new URL(request.url);
  const pathname =
    url.pathname.replace(/\/+$/, "") || "/";
  if (
    request.method === "POST" &&
    pathname === "/providers/create"
  ) {
    return await createProviderRoute(
      request,
      env
    );
  }
  return null;
}
async function createProviderRoute(
  request,
  env
) {
  try {
    const auth = await authenticate(request, env);
    if (auth instanceof Response) {
      return auth;
    }
    const user = auth.user ?? auth;
    const userId = user.id;
    if (!userId) {
      return Response.json({
        success: false,
        message: "Authentication required."
      }, { status: 401 });
    }
    let data;
    try {
      data = await request.json();
    } catch {
      return Response.json({
        success: false,
        message: "Invalid JSON request body."
      }, { status: 400 });
    }
    const providerName =
      typeof data.provider_name === "string" ?
      data.provider_name.trim() :
      "";
    const providerType =
      data.provider_type ?? "individual";
    const description =
      typeof data.description === "string" ?
      data.description.trim() :
      null;
    const phone =
      typeof data.phone === "string" ?
      data.phone.trim() :
      null;
    const email =
      typeof data.email === "string" ?
      data.email.trim() :
      null;
    const city =
      typeof data.city === "string" ?
      data.city.trim() :
      "";
    const area =
      typeof data.area === "string" ?
      data.area.trim() :
      null;
    const address =
      typeof data.address === "string" ?
      data.address.trim() :
      null;
    const imageUrl =
      typeof data.image_url === "string" ?
      data.image_url.trim() :
      null;
    if (!providerName || !city) {
      return Response.json({
        success: false,
        message: "Provider name and city are required."
      }, { status: 400 });
    }
    if (!["individual", "business"].includes(providerType)) {
      return Response.json({
        success: false,
        message: "Provider type must be individual or business."
      }, { status: 400 });
    }
    const existing = await env.DB
      .prepare(
        "SELECT id FROM providers WHERE user_id = ?"
      )
      .bind(userId)
      .first();
    if (existing) {
      return Response.json({
        success: false,
        message: "You already have a provider profile."
      }, { status: 409 });
    }
    const providerId = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    await env.DB
      .prepare(`
                INSERT INTO providers (
                    id,
                    user_id,
                    provider_name,
                    provider_type,
                    description,
                    phone,
                    email,
                    city,
                    area,
                    address,
                    image_url,
                    availability_status,
                    approval_status,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    'available', 'pending', ?, ?
                )
            `)
      .bind(
        providerId,
        userId,
        providerName,
        providerType,
        description || null,
        phone || null,
        email || null,
        city,
        area || null,
        address || null,
        imageUrl || null,
        now,
        now
      )
      .run();
    const provider = await env.DB
      .prepare(`
                SELECT
                    id,
                    user_id,
                    provider_name,
                    provider_type,
                    description,
                    phone,
                    email,
                    city,
                    area,
                    address,
                    image_url,
                    availability_status,
                    approval_status,
                    created_at,
                    updated_at
                FROM providers
                WHERE id = ?
            `)
      .bind(providerId)
      .first();
    return Response.json({
      success: true,
      message: "Provider profile created successfully. Awaiting approval.",
      provider
    }, { status: 201 });
  } catch (error) {
    console.error("Create provider error:", error);
    return Response.json({
      success: false,
      message: "Failed to create provider profile."
    }, { status: 500 });
  }
}

