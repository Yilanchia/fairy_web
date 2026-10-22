import http from "node:http";

function cookieValue(req, name) {
  const raw = String(req.headers.cookie || "");
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

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
         <a href="/downloads/app.apk">app.apk</a>
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
      if (req.method === "POST") {
        let raw = "";
        req.on("data", (chunk) => {
          raw += chunk;
        });
        req.on("end", () => {
          const form = new URLSearchParams(raw);
          const user = form.get("username") || form.get("user");
          const pass = form.get("password") || form.get("pass");
          if (pass === "secret" && (user === "alice" || user === "bob")) {
            res.writeHead(302, { location: "/account", "set-cookie": `sid=${user}; Path=/; HttpOnly` });
            res.end();
          } else {
            res.writeHead(401, { "content-type": "text/html" });
            res.end("<html>invalid credentials</html>");
          }
        });
        return;
      }
      html(
        "Login",
        '<form method="post" action="/login"><input name="username"><input name="password" type="password"><input type="hidden" name="csrf" value="csrf-token"></form>',
        { "set-cookie": ["theme=dark; Path=/; Max-Age=3600"] },
      );
      return;
    }
    if (path === "/account") {
      const sid = cookieValue(req, "sid");
      if (!sid) {
        res.writeHead(401, { "content-type": "text/html" });
        res.end("<html>login required</html>");
        return;
      }
      html(`${sid} account`, `<div>${sid} account</div>`);
      return;
    }
    if (path === "/api/orders/1") {
      const sid = cookieValue(req, "sid");
      if (!sid) return json(res, 401, { error: "login required" });
      if (sid === "alice") return json(res, 200, { owner: "alice", marker: "ALICE-ORDER-1" });
      return json(res, 403, { error: "forbidden" });
    }
    if (path === "/api/orders/2") {
      const sid = cookieValue(req, "sid");
      if (!sid) return json(res, 401, { error: "login required" });
      // 故意留一个 BOLA:任何登录用户都能读 bob 的订单。
      return json(res, 200, { owner: "bob", marker: "BOB-ORDER-2" });
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
    if (path === "/spa") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><html><head><title>Loading</title></head><body>
        <div id="app">loading</div>
        <script>
          setTimeout(function () {
            document.title = 'SPA Ready';
            document.getElementById('app').textContent = 'ready';
            var a = document.createElement('a');
            a.href = '/dynamic';
            a.textContent = 'dynamic';
            document.body.appendChild(a);
            fetch('/api/data').catch(function () {});
          }, 50);
        </script>
      </body></html>`);
      return;
    }
    if (path === "/fetch-out") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><html><head><title>Out</title></head><body>
        <script>fetch('http://example.invalid/steal').catch(function () {});</script>
      </body></html>`);
      return;
    }
    if (path === "/downloads/app.apk") {
      const body = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(64, 0x41)]);
      res.writeHead(200, {
        "content-type": "application/vnd.android.package-archive",
        "content-length": body.length,
      });
      res.end(body);
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
