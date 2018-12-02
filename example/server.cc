//
//  sample.cc
//
//  Copyright (c) 2012 Yuji Hirose. All rights reserved.
//  The Boost Software License 1.0
//

#include <httplib.h>
#include <cstdio>
#include <chrono>
#include "utils.h"

#define SERVER_CERT_FILE "./cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./key.pem"

using namespace httplib;
using namespace hogason;

std::string dump_headers(const Headers& headers)
{
    std::string s;
    char buf[BUFSIZ];

    for (auto it = headers.begin(); it != headers.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
       s += buf;
    }

    return s;
}

std::string log(const Request& req, const Response& res)
{
    std::string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s %s", req.method.c_str(), req.version.c_str(), req.path.c_str());
    s += buf;

    std::string query;
    for (auto it = req.params.begin(); it != req.params.end(); ++it) {
       const auto& x = *it;
       snprintf(buf, sizeof(buf), "%c%s=%s",
           (it == req.params.begin()) ? '?' : '&', x.first.c_str(), x.second.c_str());
       query += buf;
    }
    snprintf(buf, sizeof(buf), "%s\n", query.c_str());
    s += buf;

    s += dump_headers(req.headers);

    s += "--------------------------------\n";

    snprintf(buf, sizeof(buf), "%d %s\n", res.status, res.version.c_str());
    s += buf;
    s += dump_headers(res.headers);
    s += "\n";

    if (!res.body.empty()) {
        s += res.body;
    }

    s += "\n";

    return s;
}

int main(void)
{
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
#else
    Server svr;
#endif

    if (!svr.is_valid()) {
        printf("server has an error...\n");
        return -1;
    }

	svr.Get("/", [=](const Request& req, Response& res) {
		auto cookie_str = req.get_header_value("Cookie");
		if (cookie_str.empty()) {
			res.set_redirect("/login.html");
			return;
		}

		Cookie cookie(cookie_str);
		try
		{
			auto session_id = cookie.getValue(Cookie::KEY_SESSION_ID);
			// invalidate expires
			SessionHolder::getInstance().getSession(session_id);
			std::string file_buf;
			detail::read_file("www/yap/index.html", file_buf);

			std::vector<char> buf(file_buf.size() + 20);
			snprintf(&buf[0], buf.size(), file_buf.c_str(), session_id.c_str());
			res.set_content(buf.data(), "text/html");
		}
		catch (std::runtime_error& /*ex*/)
		{
			// session over time
			cookie.setExpires(system_clock::now() - hours(1));
			res.set_header("Set-Cookie", cookie.to_string().c_str());
			res.set_redirect("/login.html");
			return;
		}

	});

	svr.Post("/index", [](const Request& req, Response& res) {
		auto username = req.get_param_value("userName");
		auto password = req.get_param_value("password");
		if (username.empty() || password.empty()) {
			res.set_redirect("/login.html");
			return;
		}
		// TODO validate info & generate session id

		Cookie cookie({ { Cookie::KEY_SESSION_ID, username } });
		SessionHolder::getInstance().setSession(username, cookie);
		res.set_redirect("/");
		res.set_header("Set-Cookie", cookie.to_string().c_str());
	});

	svr.Get("/index", [](const Request& /*req*/, Response& res) {
		res.set_content("Hello World!\n", "text/plain");
	});

    svr.Get("/dump", [](const Request& req, Response& res) {
        res.set_content(dump_headers(req.headers), "text/plain");
    });

    svr.Get("/stop", [&](const Request& /*req*/, Response& /*res*/) {
        svr.stop();
    });

    svr.set_error_handler([](const Request& /*req*/, Response& res) {
        const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
        char buf[BUFSIZ];
        snprintf(buf, sizeof(buf), fmt, res.status);
        res.set_content(buf, "text/html");
    });

    svr.set_logger([](const Request& req, const Response& res) {
        printf("%s", log(req, res).c_str());
    });
	
	std::thread sessionKeeper([&svr]() {
		SessionHolder& holder = SessionHolder::getInstance();
		do
		{
			auto cur_t = std::chrono::system_clock::now();
			auto session_ids = holder.getSessionIdSet();
			for (const auto& id : session_ids) {
				auto& session = holder.getSession(id);
				if (session.create_t + SessionHolder::expires < cur_t) {
					holder.removeSession(id);
				}
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}
		while (svr.is_running());
	});

	svr.set_base_dir("www");
    svr.listen("localhost", 8080);
	sessionKeeper.join();

    return 0;
}

// vim: et ts=4 sw=4 cin cino={1s ff=unix
