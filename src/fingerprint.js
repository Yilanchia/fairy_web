import { headerGet } from "./util.js";

const HEADER_TECH = [
  [/(^|\s)nginx(?:\/|$)/i, "nginx"],
  [/(^|\s)apache(?:\/|$)/i, "Apache"],
  [/microsoft-iis/i, "IIS"],
  [/cloudflare/i, "Cloudflare"],
  [/envoy/i, "Envoy"],
  [/express/i, "Express"],
  [/caddy/i, "Caddy"],
  [/openresty/i, "OpenResty"],
  [/tomcat/i, "Tomcat"],
  [/jetty/i, "Jetty"],
  [/kestrel/i, "Kestrel"],
];

const COOKIE_TECH = [
  [/^PHPSESSID$/i, "PHP"],
  [/^JSESSIONID$/i, "Java"],
  [/^ASP\.NET_SessionId$/i, "ASP.NET"],
  [/^connect\.sid$/i, "Express"],
  [/^laravel_session$/i, "Laravel"],
  [/^csrftoken$/i, "Django"],
  [/^XSRF-TOKEN$/i, "Laravel"],
  [/^CFID$|^CFTOKEN$/i, "ColdFusion"],
  [/^wordpress_/i, "WordPress"],
];

const BODY_TECH = [
  [/wp-content|wp-includes/i, "WordPress"],
  [/__NEXT_DATA__|\/_next\//i, "Next.js"],
  [/__NUXT__|\/_nuxt\//i, "Nuxt"],
  [/data-reactroot|react-dom(?:\.production)?\.min\.js/i, "React"],
  [/data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js/i, "Vue"],
  [/ng-version=["']([\d.]+)|ng-app=/i, "Angular"],
  [/csrfmiddlewaretoken/i, "Django"],
  [/whitelabel error page|spring-security/i, "Spring"],
  [/__VIEWSTATE|X-AspNet-Version/i, "ASP.NET"],
  [/swagger-ui|SwaggerUIBundle/i, "Swagger UI"],
  [/grafana/i, "Grafana"],
  [/jenkins/i, "Jenkins"],
];

export function fingerprint(page) {
  const tech = [];
  const seen = new Set();
  const add = (name, version, evidence) => {
    const key = `${name}@${version || ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    tech.push({ tech: name, version: version || null, evidence });
  };

  const server = headerGet(page.headers, "server");
  if (server) {
    const version = /[\d]+(?:\.[\d]+)+/.exec(server)?.[0] || null;
    for (const [rx, name] of HEADER_TECH) {
      if (rx.test(server)) {
        add(name, version, `Server: ${server}`);
        break;
      }
    }
    if (!tech.length) add(server.split(/[\s/(]/)[0], version, `Server: ${server}`);
  }

  const poweredBy = headerGet(page.headers, "x-powered-by");
  if (poweredBy) add(poweredBy.split("/")[0] || "unknown", /[\d.]+/.exec(poweredBy)?.[0] || null, `X-Powered-By: ${poweredBy}`);

  const via = headerGet(page.headers, "via");
  if (via) add("proxy", null, `Via: ${via}`);

  for (const cookie of page.headers.filter((h) => h.name.toLowerCase() === "set-cookie")) {
    const name = String(cookie.value).split("=")[0];
    for (const [rx, techName] of COOKIE_TECH) {
      if (rx.test(name)) add(techName, null, `Set-Cookie: ${name}`);
    }
  }

  const body = page.body || "";
  for (const [rx, name] of BODY_TECH) {
    const match = rx.exec(body);
    if (match) add(name, match[1] && /^[\d.]+$/.test(match[1]) ? match[1] : null, `body matched ${name}`);
  }

  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(body);
  if (generator) add(generator[1].split(/[\s/]/)[0], /[\d.]+/.exec(generator[1])?.[0] || null, `meta generator: ${generator[1]}`);

  const jQuery = /jquery[.-]?v?([\d.]+)(?:\.min)?\.js/i.exec(body);
  if (jQuery) add("jQuery", jQuery[1], "script src");

  return tech;
}
