// Hybrid Max Deep Web Scanner
// Runtime: Node.js 18 (Vercel)
// Developer: @lakshitpatidar
// No external dependencies

function normalize(u){
  if(!u || typeof u !== "string") throw new Error("invalid url");
  if(!/^https?:\/\//i.test(u)) return "https://" + u;
  return u;
}

function entropy(s){
  if(!s || s.length === 0) return 0;
  const map = {};
  for(const c of s) map[c] = (map[c] || 0) + 1;
  const len = s.length;
  let e = 0;
  for(const k in map){
    const p = map[k] / len;
    e -= p * Math.log2(p);
  }
  return e;
}

function extractBetween(str, start, end){
  const out = [];
  let i = 0;
  while(true){
    const a = str.indexOf(start, i);
    if(a === -1) break;
    const b = str.indexOf(end, a + start.length);
    if(b === -1) break;
    out.push(str.slice(a + start.length, b));
    i = b + end.length;
  }
  return out;
}

function scanJS(code, report){
  if(!code || code.length < 40) return;

  const e = entropy(code);
  if(e > 4.2){
    report.findings.push("High-entropy obfuscated JavaScript");
    report.malware_score += 20;
    report.meta.obfuscated_scripts++;
  }

  if(/eval\s*\(|Function\s*\(|atob\s*\(|fromCharCode/.test(code)){
    report.findings.push("Dynamic code execution primitives");
    report.malware_score += 15;
  }

  if(/WebAssembly|wasm/i.test(code)){
    report.findings.push("WebAssembly payload usage");
    report.malware_score += 15;
    report.meta.wasm_detected = true;
  }

  if(/AudioContext|webkitAudioContext/i.test(code)){
    report.findings.push("Audio fingerprinting / privacy abuse");
    report.privacy_score += 10;
  }

  if(/navigator\.clipboard|clipboard/i.test(code)){
    report.findings.push("Clipboard access attempt");
    report.malware_score += 10;
  }

  if(/document\.write|innerHTML\s*=|outerHTML\s*=/.test(code)){
    report.findings.push("DOM injection patterns");
    report.malware_score += 5;
  }

  if(/crypto|mining|hashrate|miner/i.test(code)){
    report.findings.push("Possible crypto-mining logic indicators");
    report.malware_score += 15;
  }

  if(/fetch\s*\(|XMLHttpRequest|WebSocket/i.test(code)){
    report.meta.network_calls++;
  }

  if(/base64|data:application\/octet-stream/i.test(code)){
    report.findings.push("Embedded binary/base64 blob detected");
    report.malware_score += 10;
  }
}

async function scanHTML(html, report){
  if(!html) return;

  // Hidden embeds / iframes
  const iframes = extractBetween(html, "<iframe", "</iframe>");
  for(const i of iframes){
    if(/display\s*:\s*none|visibility\s*:\s*hidden/i.test(i)){
      report.findings.push("Hidden iframe/embed detected");
      report.malware_score += 15;
    }
  }

  // Inline scripts
  const inlineScripts = extractBetween(html, "<script", "</script>");
  for(const block of inlineScripts){
    const idx = block.indexOf(">");
    if(idx !== -1){
      const code = block.slice(idx + 1);
      scanJS(code, report);
    }
  }

  // External scripts
  const srcRegex = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m;
  while((m = srcRegex.exec(html))){
    report.meta.external_scripts++;
    const src = m[1];
    if(/analytics|tracker|doubleclick|facebook|pixel/i.test(src)){
      report.findings.push("Tracking script: " + src);
      report.privacy_score += 10;
    }
    if(/\.js$/i.test(src)){
      report.meta.external_js_urls.push(src);
    }
  }

  // Meta refresh redirects
  if(/http-equiv\s*=\s*["']refresh["']/i.test(html)){
    report.findings.push("Meta refresh redirect detected");
    report.malware_score += 5;
  }

  // Auto-download hints
  if(/download\s*=|Content-Disposition/i.test(html)){
    report.findings.push("Auto-download trigger indicators");
    report.malware_score += 5;
  }
}

async function fetchText(url){
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 9000);
  try{
    const r = await fetch(url, { redirect: "follow", signal: controller.signal });
    const text = await r.text();
    clearTimeout(t);
    return { ok: true, status: r.status, text };
  }catch(e){
    clearTimeout(t);
    return { ok: false, error: "fetch_failed" };
  }
}

async function scanSingleURL(input){
  const target = normalize(input);
  const report = {
    target,
    scan_mode: "HYBRID_STATIC_HEURISTIC",
    threat_level: "LOW",
    score: 0,
    malware_score: 0,
    privacy_score: 0,
    findings: [],
    meta: {
      external_scripts: 0,
      obfuscated_scripts: 0,
      wasm_detected: false,
      network_calls: 0,
      external_js_urls: []
    },
    developer: "@lakshitpatidar"
  };

  const res = await fetchText(target);
  if(!res.ok){
    return { error: "Target unreachable", target };
  }

  report.http_status = res.status;
  await scanHTML(res.text, report);

  // Final scoring
  report.score = report.malware_score + report.privacy_score;
  if(report.score >= 80) report.threat_level = "CRITICAL";
  else if(report.score >= 60) report.threat_level = "HIGH";
  else if(report.score >= 30) report.threat_level = "MEDIUM";

  return report;
}

async function scanRawJS(jsUrl){
  const target = normalize(jsUrl);
  const report = {
    target,
    scan_mode: "RAW_JS_ANALYSIS",
    threat_level: "LOW",
    score: 0,
    malware_score: 0,
    privacy_score: 0,
    findings: [],
    meta: {
      obfuscated_scripts: 0,
      wasm_detected: false,
      network_calls: 0
    },
    developer: "@lakshitpatidar"
  };

  const res = await fetchText(target);
  if(!res.ok){
    return { error: "JS file unreachable", target };
  }

  scanJS(res.text, report);

  report.score = report.malware_score + report.privacy_score;
  if(report.score >= 80) report.threat_level = "CRITICAL";
  else if(report.score >= 60) report.threat_level = "HIGH";
  else if(report.score >= 30) report.threat_level = "MEDIUM";

  return report;
}

export default async function handler(req, res){
  // GET → Info JSON
  if(req.method === "GET"){
    return res.json({
      api: "Hybrid Max Deep Web Scanner",
      version: "3.0",
      usage: "POST { url | urls | js_url } to same endpoint",
      developer: "@lakshitpatidar",
      status: "online"
    });
  }

  // POST → Scan
  let body = req.body || {};
  try{
    if(body.url){
      const out = await scanSingleURL(body.url);
      return res.json(out);
    }

    if(Array.isArray(body.urls)){
      const results = [];
      for(const u of body.urls){
        try{
          results.push(await scanSingleURL(u));
        }catch(e){
          results.push({ target: u, error: "scan_failed" });
        }
      }
      return res.json({
        batch: true,
        count: results.length,
        results,
        developer: "@lakshitpatidar"
      });
    }

    if(body.js_url){
      const out = await scanRawJS(body.js_url);
      return res.json(out);
    }

    return res.status(400).json({
      error: "Invalid request",
      usage: "POST { url | urls | js_url }",
      developer: "@lakshitpatidar"
    });
  }catch(e){
    return res.status(500).json({
      error: "Internal error",
      developer: "@lakshitpatidar"
    });
  }
}
