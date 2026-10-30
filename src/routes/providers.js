import { authenticate } from "../middleware/authenticate.js";
export async function handleProviderRequest(
  request,
  env
) {
  const url = new URL(request.url);
  const pathname =
    url.pathname.replace(/\/+$/, "") || "/";
  // Post routes
  
  if (
    request.method === "POST" &&
    pathname === "/providers/create"
  ) {
    return await createProviderRoute(
      request,
      env
    );
  }
  
  
  
  // Get routes
  if (
    request.method === "GET" &&
    pathname === "/providers"
  ) {
    return await getProvidersRoute(request, env);
  }
  
  if (
    request.method === "GET" &&
    pathname.startsWith("/providers/")
  ) {
    const providerId = pathname.slice("/providers/".length);
    
    if (!providerId || providerId.includes("/")) {
      return Response.json({
        success: false,
        message: "Invalid provider ID."
      }, { status: 400 });
    }
    
    return await getProviderRoute(providerId, env);
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
async function getProvidersRoute(request, env) {
  try {
    const url = new URL(request.url);
    const params = url.searchParams;
    
    const city = (params.get("city") || "").trim();
    const area = (params.get("area") || "").trim();
    const type = (params.get("type") || "").trim().toLowerCase();
    const availability = (params.get("availability") || "").trim().toLowerCase();
    const search = (params.get("search") || "").trim();
    
    const limit = Math.min(
      Math.max(parseInt(params.get("limit") || "20", 10) || 20, 1),
      50
    );
    
    const offset = Math.max(
      parseInt(params.get("offset") || "0", 10) || 0,
      0
    );
    
    if (type && !["individual", "business"].includes(type)) {
      return Response.json({
        success: false,
        message: "Invalid provider type."
      }, { status: 400 });
    }
    
    if (
      availability &&
      !["available", "busy", "unavailable"].includes(availability)
    ) {
      return Response.json({
        success: false,
        message: "Invalid availability status."
      }, { status: 400 });
    }
    
    const conditions = [
      "p.approval_status = 'approved'"
    ];
    
    const values = [];
    
    if (city) {
      conditions.push("LOWER(p.city) = LOWER(?)");
      values.push(city);
    }
    
    if (area) {
      conditions.push("LOWER(p.area) = LOWER(?)");
      values.push(area);
    }
    
    if (type) {
      conditions.push("p.provider_type = ?");
      values.push(type);
    }
    
    if (availability) {
      conditions.push("p.availability_status = ?");
      values.push(availability);
    }
    
    if (search) {
      const term = `%${search}%`;
      
      conditions.push(`
        (
          LOWER(p.provider_name) LIKE LOWER(?)
          OR LOWER(p.description) LIKE LOWER(?)
          OR LOWER(p.city) LIKE LOWER(?)
          OR LOWER(p.area) LIKE LOWER(?)
          OR EXISTS (
            SELECT 1
            FROM provider_services ps
            WHERE ps.provider_id = p.id
            AND (
              LOWER(ps.service_name) LIKE LOWER(?)
              OR LOWER(ps.service_category) LIKE LOWER(?)
              OR LOWER(ps.description) LIKE LOWER(?)
            )
          )
        )
      `);
      
      values.push(
        term,
        term,
        term,
        term,
        term,
        term,
        term
      );
    }
    
    const where = conditions.join(" AND ");
    
    const [count, result] = await Promise.all([
      env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM providers p
        WHERE ${where}
      `).bind(...values).first(),
      
      env.DB.prepare(`
        SELECT
          p.id,
          p.provider_name,
          p.provider_type,
          p.description,
          p.city,
          p.area,
          p.image_url,
          p.availability_status,
          p.created_at
        FROM providers p
        WHERE ${where}
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
      `).bind(...values, limit, offset).all()
    ]);
    
    const total = count?.total || 0;
    
    return Response.json({
      success: true,
      providers: result.results || [],
      pagination: {
        total,
        limit,
        offset,
        has_more: offset + limit < total
      }
    });
    
  } catch (error) {
    console.error("Get providers error:", error);
    
    return Response.json({
      success: false,
      message: "Failed to retrieve providers."
    }, { status: 500 });
  }
}
async function getProviderRoute(providerId, env) {
  try {
    const provider = await env.DB.prepare(`
      SELECT
        id,
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
        created_at
      FROM providers
      WHERE id = ?
        AND approval_status = 'approved'
    `).bind(providerId).first();
    if (!provider) {
      return Response.json({
        success: false,
        message: "Provider not found."
      }, { status: 404 });
    }
    const servicesResult = await env.DB.prepare(`
      SELECT
        id,
        service_category,
        service_name,
        description,
        created_at,
        updated_at
      FROM provider_services
      WHERE provider_id = ?
      ORDER BY created_at DESC
    `).bind(providerId).all();
    provider.services = servicesResult.results || [];
    return Response.json({
      success: true,
      provider
    });
  } catch (error) {
    console.error("Get provider error:", error);
    return Response.json({
      success: false,
      message: "Failed to retrieve provider."
    }, { status: 500 });
  }
}