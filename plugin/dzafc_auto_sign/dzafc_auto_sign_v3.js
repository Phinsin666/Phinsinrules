/*
 * 东证小程序签到（Loon）
 *
 * 用法：
 * 1. 作为 authentication / refresh 接口的 Response Script 运行时，保存访问令牌、refreshToken 与 Cookie；
 * 2. 作为 sign/status 的 Response Script 运行时，增量更新 Header，避免覆盖已有 refreshToken 与 Cookie；
 * 3. 作为 Cron / Generic Script 运行时，使用持久化的登录态签到；若 accessToken 过期，优先尝试自动续期后重试。
 *
 * 账号信息只写入 Loon 的本地 persistentStore，不写在脚本源码中。
 */

var STORE_KEY = "dzafc.auto_sign.auth.v1";
var API_ROOT = "https://mx.dzafc.cn";
var STATUS_URL = API_ROOT + "/api/iris/v1/sign/status";
var SIGN_URL = API_ROOT + "/api/iris/v1/sign/daily";
var AUTH_PATH = "/api/pie/v1/wechat/miniapp/authentication";
var STATUS_PATH = "/api/iris/v1/sign/status";
var REFRESH_CANDIDATES = [
  API_ROOT + "/api/pie/v1/wechat/miniapp/authentication/refresh",
  API_ROOT + "/api/pie/v1/wechat/miniapp/refresh",
  API_ROOT + "/api/pie/v1/auth/refresh",
  API_ROOT + "/api/pie/v1/token/refresh"
];

var SCRIPT_ARGS = (typeof $argument !== "undefined" && $argument && typeof $argument === "object") ? $argument : {};

function logDebug(message) {
  if (SCRIPT_ARGS.debugLog) {
    console.log("[dzafc_auto_sign] " + message);
  }
}

function headerValue(headers, name) {
  headers = headers || {};
  var wanted = String(name).toLowerCase();
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i += 1) {
    if (keys[i].toLowerCase() === wanted) return headers[keys[i]];
  }
  return "";
}

function randomHex(length) {
  var chars = "0123456789abcdef";
  var result = "";
  for (var i = 0; i < length; i += 1) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function parseJSON(text) {
  try {
    return JSON.parse(text || "{}");
  } catch (error) {
    return null;
  }
}

function notify(subtitle, content) {
  $notification.post("东证小程序签到", subtitle, String(content || ""));
}

function loadAuthentication() {
  var text = $persistentStore.read(STORE_KEY);
  if (!text) return null;
  return parseJSON(text);
}

function pickNonEmpty(nextValue, prevValue, fallback) {
  if (typeof nextValue !== "undefined" && nextValue !== null && String(nextValue) !== "") {
    return String(nextValue);
  }
  if (typeof prevValue !== "undefined" && prevValue !== null && String(prevValue) !== "") {
    return String(prevValue);
  }
  return fallback || "";
}

function storeAuthentication(patch, silent) {
  var previous = loadAuthentication() || {};
  var now = Date.now();
  var merged = {
    accessToken: pickNonEmpty(patch.accessToken, previous.accessToken, ""),
    refreshToken: pickNonEmpty(patch.refreshToken, previous.refreshToken, ""),
    accountId: pickNonEmpty(patch.accountId, previous.accountId, ""),
    ownerId: pickNonEmpty(patch.ownerId, previous.ownerId, ""),
    deviceId: pickNonEmpty(patch.deviceId, previous.deviceId, ""),
    client: pickNonEmpty(patch.client, previous.client, "3"),
    clientVersion: pickNonEmpty(patch.clientVersion, previous.clientVersion, ""),
    userAgent: pickNonEmpty(patch.userAgent, previous.userAgent, "Mozilla/5.0"),
    acceptLanguage: pickNonEmpty(patch.acceptLanguage, previous.acceptLanguage, "zh-CN,zh-Hans;q=0.9"),
    cookie: pickNonEmpty(patch.cookie, previous.cookie, ""),
    refreshUrl: pickNonEmpty(patch.refreshUrl, previous.refreshUrl, ""),
    refreshMethod: pickNonEmpty(patch.refreshMethod, previous.refreshMethod, ""),
    refreshBody: pickNonEmpty(patch.refreshBody, previous.refreshBody, ""),
    capturedAt: now,
    refreshedAt: patch.refreshedAt || previous.refreshedAt || 0,
    notifiedAt: previous.notifiedAt || 0
  };

  var tokenChanged = previous.accessToken !== merged.accessToken;
  var shouldNotify = !silent && (
    !previous.accessToken ||
    tokenChanged ||
    now - Number(previous.notifiedAt || 0) > 60000
  );

  if (shouldNotify) {
    merged.notifiedAt = now;
  }

  var saved = $persistentStore.write(JSON.stringify(merged), STORE_KEY);
  logDebug("storeAuthentication saved=" + saved + " hasRefresh=" + Boolean(merged.refreshToken) + " hasCookie=" + Boolean(merged.cookie));
  if (saved && shouldNotify) {
    var extra = merged.refreshToken ? "（含 refreshToken，支持自动续期）" : "（未返回 refreshToken，仅短期 Token）";
    notify("登录凭据已获取", "凭据已保存到 Loon 本机" + extra);
  }
  return saved;
}

function extractCookieFromResponse(headers) {
  var setCookie = headerValue(headers, "set-cookie");
  if (!setCookie) return "";
  return String(setCookie)
    .split(/,(?=[^;]+?=)/)
    .map(function (part) { return part.split(";")[0].trim(); })
    .filter(Boolean)
    .join("; ");
}

function saveAuthentication() {
  var response = parseJSON($response.body);
  var data = response && response.data;

  if (!response || String(response.code) !== "0" || !data || !data.accessToken) {
    notify("登录态捕获失败", response ? (response.message || "响应中没有访问令牌") : "登录响应不是有效 JSON");
    return false;
  }

  var sourceHeaders = $request.headers || {};
  var resHeaders = $response.headers || {};
  var cookie = headerValue(sourceHeaders, "cookie") || extractCookieFromResponse(resHeaders);

  var authPatch = {
    accessToken: String(data.accessToken),
    refreshToken: String(data.refreshToken || ""),
    accountId: String(data.accountId || headerValue(sourceHeaders, "x-account-id") || ""),
    ownerId: String(data.ownerId || headerValue(sourceHeaders, "x-owner-id") || ""),
    deviceId: String(headerValue(sourceHeaders, "x-device-id") || ""),
    client: String(headerValue(sourceHeaders, "x-client") || "3"),
    clientVersion: String(headerValue(sourceHeaders, "x-client-version") || ""),
    userAgent: String(headerValue(sourceHeaders, "user-agent") || "Mozilla/5.0"),
    acceptLanguage: String(headerValue(sourceHeaders, "accept-language") || "zh-CN,zh-Hans;q=0.9"),
    cookie: cookie
  };

  if (!authPatch.accountId || !authPatch.ownerId || !authPatch.deviceId) {
    notify("登录态不完整", "缺少 accountId、ownerId 或 deviceId");
    return false;
  }

  return storeAuthentication(authPatch, false);
}

function saveRefreshContext() {
  var response = parseJSON($response.body);
  var data = response && response.data;
  if (!response || String(response.code) !== "0" || !data || !data.accessToken) {
    return false;
  }

  var sourceHeaders = $request.headers || {};
  var resHeaders = $response.headers || {};
  var cookie = headerValue(sourceHeaders, "cookie") || extractCookieFromResponse(resHeaders);
  var reqUrl = ($request.url || "").split("?")[0];

  var patch = {
    accessToken: String(data.accessToken),
    refreshToken: String(data.refreshToken || ""),
    accountId: String(data.accountId || headerValue(sourceHeaders, "x-account-id") || ""),
    ownerId: String(data.ownerId || headerValue(sourceHeaders, "x-owner-id") || ""),
    deviceId: String(headerValue(sourceHeaders, "x-device-id") || ""),
    client: String(headerValue(sourceHeaders, "x-client") || ""),
    clientVersion: String(headerValue(sourceHeaders, "x-client-version") || ""),
    userAgent: String(headerValue(sourceHeaders, "user-agent") || ""),
    acceptLanguage: String(headerValue(sourceHeaders, "accept-language") || ""),
    cookie: cookie,
    refreshUrl: reqUrl,
    refreshMethod: String($request.method || "POST").toUpperCase(),
    refreshBody: (typeof $request.body === "string" && $request.body) ? $request.body : ""
  };

  logDebug("Captured refresh endpoint: " + patch.refreshMethod + " " + patch.refreshUrl);
  return storeAuthentication(patch, true);
}

function saveAuthenticationFromRequest() {
  var headers = $request.headers || {};
  var previous = loadAuthentication() || {};
  var authPatch = {
    accessToken: String(headerValue(headers, "x-access-token") || ""),
    accountId: String(headerValue(headers, "x-account-id") || ""),
    ownerId: String(headerValue(headers, "x-owner-id") || ""),
    deviceId: String(headerValue(headers, "x-device-id") || ""),
    client: String(headerValue(headers, "x-client") || "3"),
    clientVersion: String(headerValue(headers, "x-client-version") || ""),
    userAgent: String(headerValue(headers, "user-agent") || "Mozilla/5.0"),
    acceptLanguage: String(headerValue(headers, "accept-language") || "zh-CN,zh-Hans;q=0.9"),
    cookie: String(headerValue(headers, "cookie") || "")
  };

  if (!authPatch.accessToken || !authPatch.accountId || !authPatch.ownerId || !authPatch.deviceId) {
    notify("登录态捕获失败", "签到状态请求缺少必要的认证 Header");
    return false;
  }

  // 增量合并，保留已保存的 refreshToken / refreshUrl / Cookie
  return storeAuthentication(authPatch, Boolean(previous.accessToken === authPatch.accessToken));
}

function requestHeaders(auth, withBody) {
  var headers = {
    "Accept": "application/json, text/plain, */*",
    "X-Account-Id": auth.accountId,
    "X-Owner-Id": auth.ownerId,
    "X-Device-Id": auth.deviceId,
    "X-Access-Token": auth.accessToken,
    "X-Client": auth.client || "3",
    "X-Client-Version": auth.clientVersion || "",
    "X-Trace-Id": randomHex(32),
    "User-Agent": auth.userAgent || "Mozilla/5.0",
    "Accept-Language": auth.acceptLanguage || "zh-CN,zh-Hans;q=0.9",
    "Referer": API_ROOT + "/us3/sign_in.html"
  };

  if (auth.cookie) {
    headers["Cookie"] = auth.cookie;
  }

  if (withBody) {
    headers["Content-Type"] = "application/json";
    headers["Origin"] = API_ROOT;
  }
  return headers;
}

function finish(isHTTPContext) {
  if (isHTTPContext) $done({});
  else $done();
}

function buildRefreshTargets(auth) {
  var targets = [];
  var customUrl = SCRIPT_ARGS.refreshUrl ? String(SCRIPT_ARGS.refreshUrl).trim() : "";
  if (customUrl) {
    targets.push({ url: customUrl, method: "POST", body: JSON.stringify({ refreshToken: auth.refreshToken }) });
  }
  if (auth.refreshUrl) {
    var bodyStr = JSON.stringify({ refreshToken: auth.refreshToken });
    if (auth.refreshBody) {
      var parsedBody = parseJSON(auth.refreshBody);
      if (parsedBody && typeof parsedBody === "object") {
        if ("refreshToken" in parsedBody) parsedBody.refreshToken = auth.refreshToken;
        if ("refresh_token" in parsedBody) parsedBody.refresh_token = auth.refreshToken;
        bodyStr = JSON.stringify(parsedBody);
      }
    }
    targets.push({
      url: auth.refreshUrl,
      method: auth.refreshMethod || "POST",
      body: bodyStr
    });
  }
  for (var i = 0; i < REFRESH_CANDIDATES.length; i += 1) {
    var url = REFRESH_CANDIDATES[i];
    if (url !== customUrl && url !== auth.refreshUrl) {
      targets.push({ url: url, method: "POST", body: JSON.stringify({ refreshToken: auth.refreshToken }) });
    }
  }
  return targets;
}

function refreshAuthentication(auth, callback) {
  if (!auth || !auth.refreshToken) {
    callback(false, null, "本地未保存 refreshToken");
    return;
  }

  var targets = buildRefreshTargets(auth);
  var index = 0;

  function tryNext(lastReason) {
    if (index >= targets.length) {
      callback(false, null, lastReason || "刷新接口不可用");
      return;
    }

    var target = targets[index];
    index += 1;
    var method = (target.method || "POST").toLowerCase();
    var sender = $httpClient[method] || $httpClient.post;
    logDebug("Trying refresh (" + index + "/" + targets.length + "): " + target.method + " " + target.url);

    sender({
      url: target.url,
      headers: requestHeaders(auth, method !== "get"),
      body: method === "get" ? undefined : target.body,
      timeout: 15000
    }, function (error, response, body) {
      if (error) {
        tryNext(String(error));
        return;
      }

      var statusCode = response && (response.status || response.statusCode);
      var result = parseJSON(body);
      var data = result && result.data;
      if (statusCode === 200 && result && String(result.code) === "0" && data && data.accessToken) {
        var newCookie = extractCookieFromResponse(response.headers || {});
        storeAuthentication({
          accessToken: String(data.accessToken),
          refreshToken: String(data.refreshToken || auth.refreshToken),
          cookie: newCookie,
          refreshUrl: target.url,
          refreshMethod: target.method,
          refreshedAt: Date.now()
        }, true);
        logDebug("Token refresh succeeded via " + target.url);
        callback(true, loadAuthentication(), "");
        return;
      }

      var detail = (result && (result.message || result.code)) || ("HTTP " + (statusCode || "未知"));
      tryNext(detail);
    });
  }

  tryNext("");
}

function performSign(auth, isHTTPContext) {
  $httpClient.post({
    url: SIGN_URL,
    headers: requestHeaders(auth, true),
    body: "{}",
    timeout: 15000
  }, function (error, response, body) {
    if (error) {
      notify("签到请求失败", error);
      finish(isHTTPContext);
      return;
    }

    var result = parseJSON(body);
    var statusCode = response && (response.status || response.statusCode);
    if (statusCode === 200 && result && String(result.code) === "0") {
      var points = result.data && result.data.points;
      notify("签到成功", typeof points === "undefined" ? "服务器已确认签到" : ("获得 " + points + " 积分"));
    } else {
      var detail = result && (result.message || result.code);
      notify("签到未成功", detail || ("HTTP " + (statusCode || "未知")));
    }
    finish(isHTTPContext);
  });
}

function checkAndSign(auth, isHTTPContext, allowRefresh) {
  $httpClient.get({
    url: STATUS_URL + "?_t=" + Date.now(),
    headers: requestHeaders(auth, false),
    timeout: 15000
  }, function (error, response, body) {
    if (error) {
      notify("状态查询失败", error);
      finish(isHTTPContext);
      return;
    }

    var result = parseJSON(body);
    var statusCode = response && (response.status || response.statusCode);
    if (!response || statusCode !== 200 || !result || String(result.code) !== "0" || !result.data) {
      var detail = (result && (result.message || result.code)) || ("HTTP " + (statusCode || "未知"));
      if (allowRefresh && auth.refreshToken) {
        logDebug("Status check failed (" + detail + "), attempting token refresh...");
        refreshAuthentication(auth, function (ok, refreshedAuth, refreshError) {
          if (ok && refreshedAuth) {
            checkAndSign(refreshedAuth, isHTTPContext, false);
          } else {
            notify("登录态已过期", "自动续期失败（" + refreshError + "）；请打开一次微信小程序重新获取");
            finish(isHTTPContext);
          }
        });
        return;
      }

      var hint = auth.refreshToken
        ? "；请打开一次微信小程序重新获取"
        : "；服务端未提供可用 refreshToken，需重新打开小程序获取短期 Token";
      notify("登录态已过期", detail + hint);
      finish(isHTTPContext);
      return;
    }

    if (result.data.todaySigned === true) {
      // 页面自动触发时保持安静；手动运行和 Cron 明确报告当前状态。
      if (!isHTTPContext) {
        var details = [];
        if (typeof result.data.consecutiveDays !== "undefined") {
          details.push("连续 " + result.data.consecutiveDays + " 天");
        }
        if (typeof result.data.totalPoints !== "undefined") {
          details.push("总积分 " + result.data.totalPoints);
        }
        notify("今日已签到", details.length ? details.join(" | ") : "无需重复签到");
      }
      finish(isHTTPContext);
      return;
    }

    performSign(auth, isHTTPContext);
  });
}

var isHTTPContext = typeof $request !== "undefined" && typeof $response !== "undefined";

if (isHTTPContext && $request.url.indexOf(AUTH_PATH) !== -1) {
  if (saveAuthentication()) {
    var captured = loadAuthentication();
    if (captured) checkAndSign(captured, true, false);
    else {
      notify("保存失败", "Loon 无法读取刚保存的登录态");
      finish(true);
    }
  } else {
    finish(true);
  }
} else if (isHTTPContext && $request.url.indexOf(STATUS_PATH) !== -1) {
  if (!saveAuthenticationFromRequest()) {
    finish(true);
  } else {
    var statusAuth = loadAuthentication();
    var statusResult = parseJSON($response.body);
    if (statusResult && String(statusResult.code) === "0" && statusResult.data) {
      if (statusResult.data.todaySigned === true) finish(true);
      else performSign(statusAuth, true);
    } else {
      notify("状态解析失败", statusResult ? (statusResult.message || statusResult.code) : "响应不是有效 JSON");
      finish(true);
    }
  }
} else if (isHTTPContext) {
  saveRefreshContext();
  finish(true);
} else {
  var auth = loadAuthentication();
  if (!auth || !auth.accessToken) {
    notify("尚无登录态", "Loon 本地未找到凭据，请先打开一次微信小程序");
    finish(false);
  } else {
    checkAndSign(auth, false, true);
  }
}
