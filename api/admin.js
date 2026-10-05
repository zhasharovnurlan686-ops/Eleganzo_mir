const crypto = require("crypto");

const COOKIE_NAME = "eleganzo_admin";
const TOKEN_TTL = 60 * 60 * 24 * 7; // 7 days

function env(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function b64url(input) {
  return Buffer.from(input).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function sign(payload) {
  return b64url(crypto.createHmac("sha256", env("ADMIN_PASSWORD"))
    .update(payload).digest());
}

function makeToken() {
  const payload = JSON.stringify({
    exp: Date.now() + TOKEN_TTL * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  });
  const encoded = b64url(payload);
  return `${encoded}.${sign(encoded)}`;
}

function validToken(token) {
  try {
    if (!token) return false;
    const [payload, signature] = token.split(".");
    if (!payload || !signature) return false;
    const expected = sign(payload);
    if (signature.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
      return false;
    }
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    return Number(data.exp) > Date.now();
  } catch {
    return false;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const item = header.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
}

function setCookie(res, token) {
  res.setHeader("Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${TOKEN_TTL}`);
}

function clearCookie(res) {
  res.setHeader("Set-Cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

async function github(path, options = {}) {
  const response = await fetch(`https://api.github.com/repos/${env("GITHUB_OWNER")}/${env("GITHUB_REPO")}/contents/${path}`, {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${env("GITHUB_TOKEN")}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { message: text }; }

  if (!response.ok) {
    const error = new Error(data.message || "GitHub API error");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function readProducts() {
  const branch = process.env.GITHUB_BRANCH || "main";
  const data = await github(`products.json?ref=${encodeURIComponent(branch)}`);
  const content = Buffer.from(data.content.replace(/\n/g, ""), "base64").toString("utf8");
  return { products: JSON.parse(content), sha: data.sha };
}

async function saveProducts(products, sha, message) {
  const branch = process.env.GITHUB_BRANCH || "main";
  const content = Buffer.from(JSON.stringify(products, null, 2) + "\n").toString("base64");

  return github("products.json", {
    method: "PUT",
    body: JSON.stringify({
      message,
      content,
      sha,
      branch
    })
  });
}

async function saveImage(imageData, filePath, message) {
  const branch = process.env.GITHUB_BRANCH || "main";
  const existing = await github(`${filePath}?ref=${encodeURIComponent(branch)}`).catch(err => {
    if (err.status === 404) return null;
    throw err;
  });

  const content = imageData.split(",")[1];
  return github(filePath, {
    method: "PUT",
    body: JSON.stringify({
      message,
      content,
      ...(existing ? { sha: existing.sha } : {}),
      branch
    })
  });
}

module.exports = async function handler(req, res) {
  try {
    if (req.method === "POST" && req.url.split("?")[0] === "/api/admin") {
      const body = typeof req.body === "object" ? req.body : JSON.parse(req.body || "{}");
      if (body.action === "login") {
        if (!body.password || body.password !== env("ADMIN_PASSWORD")) {
          return json(res, 401, { ok: false, error: "Неверный пароль" });
        }
        setCookie(res, makeToken());
        return json(res, 200, { ok: true });
      }
      if (body.action === "logout") {
        clearCookie(res);
        return json(res, 200, { ok: true });
      }
    }

    if (!validToken(getCookie(req, COOKIE_NAME))) {
      return json(res, 401, { ok: false, error: "Требуется вход администратора" });
    }

    const url = new URL(req.url, "https://eleganzo.local");

    if (req.method === "GET") {
      const data = await readProducts();
      return json(res, 200, { ok: true, products: data.products });
    }

    if (req.method === "POST" && url.searchParams.get("action") === "image") {
      const body = typeof req.body === "object" ? req.body : JSON.parse(req.body || "{}");
      if (!body.data || !body.fileName) {
        return json(res, 400, { ok: false, error: "Нет файла" });
      }

      if (!body.data.startsWith("data:image/")) {
        return json(res, 400, { ok: false, error: "Разрешены только изображения" });
      }

      // Защита от слишком больших загрузок.
      if (body.data.length > 7 * 1024 * 1024) {
        return json(res, 413, { ok: false, error: "Фото слишком большое. Используйте до ~5 МБ." });
      }

      const safeName = String(body.fileName)
        .toLowerCase()
        .replace(/[^a-z0-9._-]/g, "-")
        .replace(/-+/g, "-");

      const filePath = `products/${Date.now()}-${safeName}`;
      await saveImage(body.data, filePath, `admin: upload ${filePath}`);

      return json(res, 200, {
        ok: true,
        image: `/${filePath}`
      });
    }

    if (req.method === "POST" && url.searchParams.get("action") === "save") {
      const body = typeof req.body === "object" ? req.body : JSON.parse(req.body || "{}");
      if (!Array.isArray(body.products)) {
        return json(res, 400, { ok: false, error: "Неверный список товаров" });
      }

      const data = await readProducts();
      await saveProducts(data.products = body.products, data.sha, "admin: update products");

      return json(res, 200, { ok: true });
    }

    return json(res, 405, { ok: false, error: "Method not allowed" });
  } catch (error) {
    console.error(error);
    return json(res, error.status || 500, {
      ok: false,
      error: error.message || "Ошибка сервера"
    });
  }
};
