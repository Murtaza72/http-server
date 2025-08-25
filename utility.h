/*
 * MTTP Server - Basic HTTP server implementation for eduction purpose
 * Copyright (C) 2025 Murtaza Tuta
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef UTILITY_H
#define UTILITY_H

#include <sys/stat.h>

#include <string>
#include <vector>

std::string to_lower(std::string text)
{
    for (size_t i = 0, len = text.length(); i < len; ++i)
    {
        text.at(i) = static_cast<char>(tolower(text.at(i)));
    }
    return text;
}

std::vector<std::string> split(const std::string s, const std::string delimiter)
{
    std::vector<std::string> tokens;
    tokens.reserve(15);
    size_t pos_end, pos_start = 0;
    std::string token;
    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos)
    {
        token = s.substr(pos_start, pos_end - pos_start);
        tokens.push_back(token);
        pos_start = pos_end + delimiter.length();
    }
    tokens.push_back(s.substr(pos_start));

    return tokens;
}

int is_directory(std::string path)
{
    struct stat path_stat;
    stat(path.c_str(), &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

int from_hex(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'z')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 10;

    return 0;
}

#endif