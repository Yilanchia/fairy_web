import http from "node:http";

// 自建靶场:只监听 127.0.0.1,故意带一批典型配置问题,用来验证检测链路。
export function startLab() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
    const path = url.pathname;

    const html = (title, body, extra = {}) => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", ...extra });
      res.end(`<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`);
    };

    if (path === "/") {
      html(
        "Fairy Lab",
        `<a href="/search?q=hello">search</a>
         <a href="/redirect?next=/home">redirect</a>
         <a href="/login">login</a>
         <a href="/api/data">api</a>
         <a href="/cors">cors</a>
         <a href="/admin">admin</a>
         <script src="/static/app.js"></script>`,
        { server: "FairyLab/1.0" },
      );
      return;
    }
    if (path === "/search") {
      html("Search", `<div>you searched: ${url.searchParams.get("q") || ""}</div>`);
      return;
    }
    if (path === "/redirect") {
      res.writeHead(302, { location: url.searchParams.get("next") || "/" });
      res.end();
      return;
    }
    if (path === "/login") {
      html("Login", "<form method=post action=/login><input name=user><input name=pass type=password></form>", {
        "set-cookie": ["sid=abc123; Path=/", "theme=dark; Path=/; Max-Age=3600"],
      });
      return;
    }
    if (path === "/cors") {
      html("CORS", "<p>cors</p>", {
        "access-control-allow-origin": req.headers.origin || "*",
        "access-control-allow-credentials": "true",
      });
      return;
    }
    if (path === "/api/data") {
      res.writeHead(200, {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      });
      res.end('{"ok":true}');
      return;
    }
    if (path === "/.git/HEAD") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ref: refs/heads/main\n");
      return;
    }
    if (path === "/admin") {
      res.writeHead(403, { "content-type": "text/html" });
      res.end("<html>forbidden</html>");
      return;
    }
    if (path === "/static/app.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end('fetch("/api/secret")');
      return;
    }
    res.writeHead(404, { "content-type": "text/html" });
    res.end("<html>not found</html>");
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        url: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}
