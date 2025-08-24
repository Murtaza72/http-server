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