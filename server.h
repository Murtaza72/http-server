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

#ifndef SERVER_H
#define SERVER_H

#include <map>
#include <string>
#include <vector>

enum state
{
    request_line,
    headers,
    body,
    error
};

enum HTTP_method
{
    GET = 1,
    HEAD,
    POST,
    PUT,
    PATCH,
    UNKNOWN
};

struct _request_line
{
    HTTP_method method;
    std::string path;
    std::string protocol = "HTTP/1.1";
};

struct _status_line
{
    std::string protocol = "HTTP/1.1";
    int status_code;
    std::string status_desc;
};

struct HTTP_request
{
    struct _request_line request_line;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HTTP_response
{
    struct _status_line status_line;
    std::map<std::string, std::string> headers;
    std::string body;
};

std::string decode_uri(const std::string& uri);

std::string normalize_path(const std::string& urlPath, const std::string& root);

std::string remove_params(const std::string& uri);

std::string normalize_uri(const std::string& uri, const std::string& root);

bool is_valid_uri(const std::string& uri, const std::string& root, std::string& valid_uri);

void get_status_desc(HTTP_response& rec);

std::string get_content_type(const std::string& path);

void get_file_contents(HTTP_request& req, HTTP_response& res);

std::string parse_req(char* raw_buffer, const std::string& root);

#endif
