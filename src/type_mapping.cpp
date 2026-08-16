#include "data360/type_mapping.hpp"

#include <algorithm>
#include <cctype>
#include <regex>

namespace data360 {

TypeMapping MapData360Type(const std::string &data360_type) {
	std::string normalized = data360_type;
	std::transform(normalized.begin(), normalized.end(), normalized.begin(),
	               [](unsigned char character) { return static_cast<char>(std::toupper(character)); });
	std::smatch decimal;
	if (std::regex_match(normalized, decimal, std::regex("DECIMAL\\(([0-9]+),([0-9]+)\\)"))) {
		try {
			const auto precision = std::stoul(decimal[1].str());
			const auto scale = std::stoul(decimal[2].str());
			if (precision == 0 || precision > 38 || scale > precision) {
				return {"VARCHAR", "u", true};
			}
		} catch (const std::exception &) {
			return {"VARCHAR", "u", true};
		}
		return {normalized, "d:" + decimal[1].str() + "," + decimal[2].str(), false};
	}
	if (normalized == "TIMESTAMP_WITH_TIME_ZONE" || normalized == "TIMESTAMP_TZ") {
		return {"TIMESTAMPTZ", "tsu:UTC", false};
	}
	if (normalized == "TIMESTAMP" || normalized == "DATETIME") {
		return {"TIMESTAMP", "tsu:", false};
	}
	if (normalized == "BOOLEAN") {
		return {"BOOLEAN", "b", false};
	}
	if (normalized == "INTEGER" || normalized == "INT") {
		return {"INTEGER", "i", false};
	}
	if (normalized == "BIGINT" || normalized == "LONG") {
		return {"BIGINT", "l", false};
	}
	if (normalized == "DOUBLE" || normalized == "NUMBER") {
		return {"DOUBLE", "g", false};
	}
	if (normalized == "DATE") {
		return {"DATE", "tdD", false};
	}
	if (normalized == "VARCHAR" || normalized == "TEXT" || normalized == "STRING") {
		return {"VARCHAR", "u", false};
	}
	return {"VARCHAR", "u", true};
}

} // namespace data360
