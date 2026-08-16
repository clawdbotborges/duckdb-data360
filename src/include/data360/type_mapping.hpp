#pragma once

#include <string>

namespace data360 {

struct TypeMapping {
	std::string duckdb_type;
	std::string arrow_format;
	bool lossy;
};

TypeMapping MapData360Type(const std::string &data360_type);

} // namespace data360
