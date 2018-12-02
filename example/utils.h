#ifndef HOGASON_UTILS_H
#define HOGASON_UTILS_H

#include <map>
#include <mutex>
#include <regex>
#include <ctime>
#include <iomanip>
#include <string>
#include <sstream>

namespace hogason
{
using namespace std::chrono;

namespace internal
{

/**
 * @brief: expires format -- DAY, DD MMM YYYY HH:MM:SS GMT
 * @param (in) tp: time point to format
 * @return std::string : format string
 */
inline std::string getGMTTimeString(const system_clock::time_point& tp)
{
	auto t = system_clock::to_time_t(tp);
	auto tm = *std::gmtime(&t);

	std::stringstream ss;
	ss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
	return ss.str();
}

}
class Cookie
{
	using data_type = std::multimap<std::string, std::string>;
public:
	Cookie(std::initializer_list<data_type::value_type> list) noexcept : data_(list) {}
	Cookie(const std::string& raw_str) noexcept;

	std::string	to_string() const;
	std::string getValue(std::string key) const;
	void setExpires(const system_clock::time_point& tp);

	static const std::string KEY_SESSION_ID;
private:
	data_type data_;
};

// Thread safe container
class SessionHolder
{
	struct session
	{
		system_clock::time_point create_t;
		Cookie cookie;
	};
	using SessionId = std::string;
	using data_type = std::multimap<SessionId, session>;

	SessionHolder() = default;
public:
	static SessionHolder& getInstance() {
		return sessions_;
	}

	session& getSession(const SessionId& id);
	void setSession(const SessionId& id, const Cookie& cookie);
	void removeSession(const SessionId& id);
	std::vector<SessionId> getSessionIdSet();

public:
	static system_clock::duration expires;

private:
	std::mutex lock_;
	data_type data_;

	// singleton
	static SessionHolder sessions_;
};

// Cookie Implementation
const std::string Cookie::KEY_SESSION_ID = "sessionId";

inline Cookie::Cookie(const std::string& raw_str) noexcept
{
	std::regex pattern("([^=]+)=([^;]+);?\\s*");
	std::smatch results;
	auto iterStart = std::cbegin(raw_str);
	auto iterEnd = std::cend(raw_str);

	while (regex_search(iterStart, iterEnd, results, pattern)) {
		data_.emplace(results[1], results[2]);
		iterStart = results[0].second;
	}
}

inline std::string Cookie::to_string() const
{
	std::string ret;
	for (const auto& entry : data_) {
		if (entry.first == "Expires")
			continue;

		ret += entry.first;
		ret += "=";
		ret += entry.second;
		ret += "; ";
	}
	ret.append("Path=/; ");

	auto it = data_.find("Expires");
	if (it != data_.end()) {
		ret += it->first;
		ret += "=";
		ret += it->second;
		ret += "; ";
	}

	ret.append("HttpOnly");
	return ret;
}

inline std::string Cookie::getValue(std::string key) const
{
	auto it = data_.find(key);
	if (it != data_.end()) {
		return it->second;
	}
	throw std::runtime_error("no such cookie valus");
}

inline void Cookie::setExpires(const system_clock::time_point& tp)
{
	data_.emplace("Expires", internal::getGMTTimeString(tp));
}

// SessionHolder Implementation
system_clock::duration SessionHolder::expires = minutes(1);
SessionHolder SessionHolder::sessions_;

inline SessionHolder::session& SessionHolder::getSession(const SessionId& id)
{
	std::lock_guard<std::mutex> lock(lock_);
	auto it = data_.find(id);
	if (it != data_.end()) {
		return it->second;
	}
	throw std::runtime_error("no such session");
}

inline void SessionHolder::setSession(const SessionId& id, const Cookie& cookie)
{
	std::lock_guard<std::mutex> lock(lock_);
	session se{ system_clock::now(), cookie };
	data_.emplace(id, se);
}

inline void SessionHolder::removeSession(const SessionId& id)
{
	std::lock_guard<std::mutex> lock(lock_);
	data_.erase(id);
}

inline std::vector<SessionHolder::SessionId> SessionHolder::getSessionIdSet()
{
	std::vector<SessionId> res;
	{
		std::lock_guard<std::mutex> lock(lock_);
		for (const auto& item : data_)
		{
			res.push_back(item.first);
		}
	}
	return res;
}
}

#endif // HOGASON_UTILS_H