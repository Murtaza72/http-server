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

#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "server.h"
#include "utility.h"

#define BUFFER_SIZE 1024 * 10
#define BACKLOG 10

std::string decode_uri(const std::string& uri)
{
    // decoding of special characters such as %20, %2C... etc
    // ignore query parameters
    std::string decoded = "";

    for (size_t i = 0, len = uri.length(); i < len; ++i)
    {
        if (uri[i] == '%' && isxdigit(uri[i + 1]) && isxdigit(uri[i + 1]))
        {
            decoded += static_cast<char>(from_hex(uri[i + 1]) * 16 + from_hex(uri[i + 2]));
            i += 2;
        }
        else if (uri[i] == '+')
        {
            decoded += ' ';
        }
        else
        {
            decoded += uri[i];
        }
    }

    return decoded;
}

std::string normalize_path(const std::string& urlPath, const std::string& root)
{
    // removes the malicious directory traverals and ignores ./ and stray /
    // path: /.//../.././../././file.html/  -> root + /file.html
    // path: /foo/bar/../file.html          -> root + /foo/file.html
    // path: /foo/bar/./file.html           -> root + /foo/bar/file.html
    // path: /foo/bar/////file.html         -> root + /foo/bar/file.html

    std::vector<std::string> parts;
    parts.reserve(15);
    std::stringstream ss(urlPath);
    std::string item;

    while (std::getline(ss, item, '/'))
    {
        if (item.empty() || item == ".")
        {
            continue;
        }
        else if (item == "..")
        {
            if (!parts.empty())
                parts.pop_back();
        }
        else
        {
            parts.push_back(item);
        }
    }

    std::string normalized = root;
    for (std::string& p : parts)
    {
        normalized += '/' + p;
    }

    return normalized;
}

std::string remove_params(const std::string& uri)
{
    size_t pos;
    std::string path = uri;
    if ((pos = path.find("?")) != std::string::npos)
    {
        path.erase(pos, path.length() - pos);
    }

    return path;
}

std::string normalize_uri(const std::string& uri, const std::string& root)
{
    std::string decoded = decode_uri(uri);
    std::string normalized = normalize_path(remove_params(decoded), root);

    return normalized;
}

bool has_invalid_characters(std::string uri)
{
    for (char c : uri)
    {
        if (c <= 0x1F || c >= 0x7F || c == ' ')
        {
            return true;
        }
    }
    return false;
}

bool is_valid_uri(const std::string& uri, const std::string& root, std::string& valid_uri)
{
    // uri should start with /
    if (uri[0] != '/')
        return false;

    // spaces should be encoded
    if (has_invalid_characters(uri))
        return false;

    std::string normalized_uri = normalize_uri(uri, root);
    valid_uri = normalized_uri;

    return true;
}

std::string get_content_type(const std::string& path)
{
    if (path.find(".html") != std::string::npos || path.find(".htm") != std::string::npos)
    {
        return "text/html";
    }

    if (path.find(".txt") != std::string::npos)
    {
        return "text/plain";
    }

    if (path.find(".jpg") != std::string::npos || path.find(".jpeg") != std::string::npos)
    {
        return "image/jpeg";
    }

    if (path.find(".png") != std::string::npos)
    {
        return "image/png";
    }

    if (path.find(".pdf") != std::string::npos)
    {
        return "application/pdf";
    }

    // browsers downloads the file by default
    return "application/octet-stream";
}

void get_status_desc(HTTP_response& res)
{
    switch (res.status_line.status_code)
    {
    case 200:
        res.status_line.status_desc = "OK";
        break;
    case 400:
        res.status_line.status_desc = "Bad Request";
        break;
    case 403:
        res.status_line.status_desc = "Forbidden";
        break;
    case 404:
        res.status_line.status_desc = "Not Found";
        break;
    case 501:
        res.status_line.status_desc = "Not Implemented";
        break;

    default:
        res.status_line.status_code = 500;
        res.status_line.status_desc = "Internal Server Error";
        break;
    }
}

std::string send_response(HTTP_response& res, const std::string& path)
{
    get_status_desc(res);

    std::string response_string;
    response_string.reserve(BUFFER_SIZE);

    response_string = res.status_line.protocol + " " + std::to_string(res.status_line.status_code) + " " +
                      res.status_line.status_desc + "\r\n";

    std::string content_type = get_content_type(path);
    res.headers.insert({"content-type", content_type});
    res.headers.insert({"server", "MTTPServer/0.1"});
    res.headers.insert({"connection", "close"});
    res.headers.insert({"content-length", std::to_string(res.body.size())});

    if (res.body == "")
    {
        res.body += "<html>\n<body style='background-color:#FF0000;'>\n";
        res.body +=
            "<h1>" + std::to_string(res.status_line.status_code) + " " + res.status_line.status_desc + "</h1>\n";
        res.body += "<hr>\n";
        res.body += "<p>Served By: <strong>" + res.headers.at("server") + "</strong></p>\n";
        res.body += "</body>\n</html>\n";

        res.headers.at("content-type") = "text/html";
        res.headers.at("content-length") = std::to_string(res.body.length());
    }

    for (const auto& k : res.headers)
    {
        response_string += k.first + ": " + k.second + "\r\n";
    }
    response_string += "\r\n";  // end of headers

    // body
    response_string += res.body;

    return response_string;
}

void get_file_contents(HTTP_request& req, HTTP_response& res)
{
    if (access(req.request_line.path.c_str(), R_OK) == 0)
    {
        // check if the path is a directory
        // if true, add /index.html to the path
        if (is_directory(req.request_line.path))
        {
            req.request_line.path += "/index.html";
        }

        std::ifstream file(req.request_line.path);
        std::string str;
        std::string file_contents;
        while (std::getline(file, str))
        {
            file_contents += str + '\n';
        }

        res.status_line.status_code = 200;
        res.body = file_contents;
    }
    else if (errno == EACCES)
    {
        // errno is global variable set by the syscalls
        // server doesn't have permission to read
        res.status_line.status_code = 403;
    }
    else if (errno == ENOENT)
    {
        res.status_line.status_code = 404;
    }
}

std::string parse_req(std::string buffer, const std::string& root)
{
    HTTP_request request;
    state current_state = state::error;
    std::vector<std::string> request_tokens = split(buffer, "\r\n");

    HTTP_response response;

    std::cout << "----------\n" << buffer << std::endl;

    for (size_t i = 0, size = request_tokens.size(); i < size; ++i)
    {
        if (request_tokens.at(i).find("HTTP/") != std::string::npos)
        {
            current_state = state::request_line;

            std::vector<std::string> request_line = split(request_tokens.at(i), " ");

            if (request_line.at(0) != "GET")
            {
                current_state = state::error;
                response.status_line.status_code = 501;
                break;
            }

            std::string valid_uri;
            if (!is_valid_uri(request_line.at(1), root, valid_uri) || request_line.at(2) != "HTTP/1.1")
            {
                current_state = state::error;
                response.status_line.status_code = 400;
                break;
            }

            request.request_line.method = HTTP_method::GET;
            request.request_line.path = valid_uri;
        }

        else if (request_tokens.at(i) == "")
        {
            // ignore body
        }

        // if any other protocol other than HTTP is called
        // server shouldn't go in an infinite loop
        else if (request_tokens.at(i).find(": ") != std::string::npos)
        {
            current_state = state::headers;

            size_t pos = 0;
            while ((pos = request_tokens.at(i).find(": ")) != std::string::npos)
            {
                std::string field = request_tokens.at(i).substr(0, pos);
                std::string value = request_tokens.at(i).substr(pos + 2, request_tokens.at(i).length());
                request.headers.insert({to_lower(field), value});
                i++;
            }
            i--;
        }
        else
        {
            current_state = state::error;
            response.status_line.status_code = 400;
            break;
        }
    }

    if (current_state != state::error)
    {
        get_file_contents(request, response);
        return send_response(response, request.request_line.path);
    }

    return send_response(response, "/");
}

void handle_client(int fd, std::string root)
{
    char buffer[BUFFER_SIZE] = {0};
    recv(fd, buffer, BUFFER_SIZE, 0);

    std::string response = parse_req(buffer, root);

    send(fd, response.c_str(), sizeof(char) * response.length(), 0);

    close(fd);
    exit(0);
}

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        std::cerr << "Usage: " << argv[0] << " <IP> <PORT> <ROOT_DIR>" << std::endl;
        exit(1);
    }

    std::string ip = argv[1];
    int port = std::stoi(argv[2]);
    std::string root = argv[3];

    if (port < 1 || port > 65535)
    {
        std::cerr << "PORT should be in range 1 to 65535." << std::endl;
        exit(1);
    }

    std::cout << "Server started..." << std::endl;

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1)
    {
        std::cerr << "ERROR: Failed to intialize socket" << std::endl;
        exit(1);
    }

    // Allows to immediately restart the server without waiting awhile
    int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
    {
        std::cerr << "ERROR: Invalid IP address" << std::endl;
        exit(1);
    }

    if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        std::cerr << "ERROR: Failed to bind" << std::endl;
        exit(1);
    }

    if (listen(socket_fd, BACKLOG) == -1)
    {
        std::cerr << "ERROR: Failed to listen" << std::endl;
        exit(1);
    }

    // prevents zombies
    signal(SIGCHLD, SIG_IGN);

    socklen_t addr_size = sizeof(addr);

    while (1)
    {
        int client_fd = accept(socket_fd, (struct sockaddr*)&addr, &addr_size);
        if (client_fd == -1)
        {
            std::cerr << "ERROR: Failed to accept" << std::endl;
            exit(1);
        }

        pid_t pid = fork();

        if (pid == 0)
        {
            // child handles the req
            close(socket_fd);
            handle_client(client_fd, root);
        }
        else if (pid < 0)
        {
            std::cerr << "ERROR: fork returned -1" << std::endl;
            close(client_fd);
            exit(1);
        }
        else
        {
            close(client_fd);
        }
    }

    return 0;
}
