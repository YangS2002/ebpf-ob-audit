// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef SIMPLE_YAML_H
#define SIMPLE_YAML_H

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

class SimpleYaml {
public:
	bool load(const char *path)
	{
		FILE *file = fopen(path, "r");
		if (!file)
			return false;

		char line[1024];
		std::vector<std::string> stack;
		while (fgets(line, sizeof(line), file)) {
			std::string text = strip_comment(line);
			trim_in_place(text);
			if (text.empty())
				continue;

			size_t indent = leading_spaces(line) / 2;
			size_t pos = text.find(':');
			if (pos == std::string::npos)
				continue;

			std::string key = text.substr(0, pos);
			std::string value = text.substr(pos + 1);
			trim_in_place(key);
			trim_in_place(value);
			if (key.empty())
				continue;

			if (stack.size() > indent)
				stack.resize(indent);
			if (value.empty()) {
				if (stack.size() == indent)
					stack.push_back(key);
				else
					stack[indent] = key;
				continue;
			}

			unquote_in_place(value);
			items_.push_back(Item{join_path(stack, key), value});
		}
		fclose(file);
		return true;
	}

	std::string get_string(const std::string &path, const std::string &default_value = "") const
	{
		for (const auto &item : items_) {
			if (item.path == path)
				return item.value;
		}
		return default_value;
	}

	bool get_bool(const std::string &path, bool default_value = false) const
	{
		std::string value = get_string(path, default_value ? "true" : "false");
		return value == "true" || value == "1" || value == "yes";
	}

	unsigned int get_u32(const std::string &path, unsigned int default_value = 0) const
	{
		std::string value = get_string(path, "");
		return value.empty() ? default_value : static_cast<unsigned int>(strtoul(value.c_str(), nullptr, 10));
	}

	unsigned long long get_u64(const std::string &path, unsigned long long default_value = 0) const
	{
		std::string value = get_string(path, "");
		return value.empty() ? default_value : strtoull(value.c_str(), nullptr, 10);
	}

private:
	struct Item {
		std::string path;
		std::string value;
	};

	static size_t leading_spaces(const char *line)
	{
		size_t count = 0;
		while (line[count] == ' ')
			count++;
		return count;
	}

	static void trim_in_place(std::string &value)
	{
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
			value.erase(value.begin());
		while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
			value.pop_back();
	}

	static void unquote_in_place(std::string &value)
	{
		if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') ||
					      (value.front() == '\'' && value.back() == '\'')))
			value = value.substr(1, value.size() - 2);
	}

	static std::string strip_comment(const char *line)
	{
		std::string out;
		bool in_single = false;
		bool in_double = false;
		for (const char *p = line; *p; ++p) {
			char c = *p;
			if (c == '\'' && !in_double)
				in_single = !in_single;
			else if (c == '"' && !in_single)
				in_double = !in_double;
			else if (c == '#' && !in_single && !in_double)
				break;
			out.push_back(c);
		}
		return out;
	}

	static std::string join_path(const std::vector<std::string> &stack, const std::string &key)
	{
		std::string path;
		for (const auto &item : stack) {
			if (!path.empty())
				path += ".";
			path += item;
		}
		if (!path.empty())
			path += ".";
		path += key;
		return path;
	}

	std::vector<Item> items_;
};

#endif /* SIMPLE_YAML_H */
