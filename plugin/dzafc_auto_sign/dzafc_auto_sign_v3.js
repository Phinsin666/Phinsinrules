/*
 * 东证小程序签到（Loon）
 *
 * 用法：
 * 1. 作为 authentication 接口的 Response Script 运行时，保存短期访问令牌；
 * 2. 保存后立即检查今日状态，未签到才调用签到接口；
 * 3. 作为 Cron / Generic Script 运行时，使用最近保存的登录态补签。
 *
 * 账号信息只写入 Loon 的本地 persistentStore，不写在脚本源码中。
 */

var STORE_KEY = "dzafc.auto_sign.auth.v1";
var API_ROOT = "https://mx.dzafc.cn";
var STATUS_URL = API_ROOT + "/api/iris/v1/sign/status";
var SIGN_URL = API_ROOT + "/api/iris/v1/sign/daily";
var AUTH_PATH = "/api/pie/v1/wechat/miniapp/authentication";
var STATUS_PATH = "/api/iris/v1/sign/status";

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

function storeAuthentication(auth) {
  var previous = loadAuthentication();
  var now = Date.now();
  var shouldNotify = !previous ||
    previous.accessToken !== auth.accessToken ||
    now - Number(previous.notifiedAt || 0) > 60000;

  auth.capturedAt = now;
  auth.notifiedAt = shouldNotify ? now : Number(previous && previous.notifiedAt || 0);

  var saved = $persistentStore.write(JSON.stringify(auth), STORE_KEY);
  if (saved && shouldNotify) {
    notify("登录凭据已获取", "Token 与账号 Header 已保存到 Loon 本机");
  }
  return saved;
}

function saveAuthentication() {
  var response = parseJSON($response.body);
  var data = response && response.data;

  if (!response || String(response.code) !== "0" || !data || !data.accessToken) {
    notify("登录态捕获失败", response ? (response.message || "响应中没有访问令牌") : "登录响应不是有效 JSON");
    return false;
  }

  var sourceHeaders = $request.headers || {};
  var auth = {
    accessToken: String(data.accessToken),
    refreshToken: String(data.refreshToken || ""),
    accountId: String(data.accountId || headerValue(sourceHeaders, "x-account-id") || ""),
    ownerId: String(data.ownerId || headerValue(sourceHeaders, "x-owner-id") || ""),
    deviceId: String(headerValue(sourceHeaders, "x-device-id") || ""),
    client: String(headerValue(sourceHeaders, "x-client") || "3"),
    clientVersion: String(headerValue(sourceHeaders, "x-client-version") || ""),
    userAgent: String(headerValue(sourceHeaders, "user-agent") || "Mozilla/5.0"),
    acceptLanguage: String(headerValue(sourceHeaders, "accept-language") || "zh-CN,zh-Hans;q=0.9"),
    capturedAt: Date.now()
  };

  if (!auth.accountId || !auth.ownerId || !auth.deviceId) {
    notify("登录态不完整", "缺少 accountId、ownerId 或 deviceId");
    return false;
  }

  return storeAuthentication(auth);
}

function saveAuthenticationFromRequest() {
  var headers = $request.headers || {};
  var auth = {
    accessToken: String(headerValue(headers, "x-access-token") || ""),
    accountId: String(headerValue(headers, "x-account-id") || ""),
    ownerId: String(headerValue(headers, "x-owner-id") || ""),
    deviceId: String(headerValue(headers, "x-device-id") || ""),
    client: String(headerValue(headers, "x-client") || "3"),
    clientVersion: String(headerValue(headers, "x-client-version") || ""),
    userAgent: String(headerValue(headers, "user-agent") || "Mozilla/5.0"),
    acceptLanguage: String(headerValue(headers, "accept-language") || "zh-CN,zh-Hans;q=0.9")
  };

  if (!auth.accessToken || !auth.accountId || !auth.ownerId || !auth.deviceId) {
    notify("登录态捕获失败", "签到状态请求缺少必要的认证 Header");
    return false;
  }
  return storeAuthentication(auth);
}

function loadAuthentication() {
  var text = $persistentStore.read(STORE_KEY);
  if (!text) return null;
  return parseJSON(text);
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

function checkAndSign(auth, isHTTPContext) {
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
      var detail = result && (result.message || result.code);
      notify("登录态可能已过期", detail || ("HTTP " + (statusCode || "未知") + "；请重新获取登录态"));
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
    if (captured) checkAndSign(captured, true);
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
} else {
  var auth = loadAuthentication();
  if (!auth) {
    notify("尚无登录态", "请先打开一次微信小程序");
    finish(false);
  } else {
    checkAndSign(auth, false);
  }
}
