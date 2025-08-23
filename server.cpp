#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define BUFFER_SIZE 1024 * 10
#define PORT 8080
#define ADDR INADDR_ANY
#define BACKLOG 10
#define ROOT "root"

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

struct request_line
{
    HTTP_method method;
    std::string path;
    std::string protocol;
};

struct HTTP_request
{
    struct request_line request_line;
    std::map<std::string, std::string> headers;
    std::string body;
};

std::string to_lower(std::string text)
{
    for (int i = 0; i < text.length(); i++)
    {
        text.at(i) = tolower(text.at(i));
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

bool is_valid_method(std::string method)
{
    // only GET method is valid for now
    return method == "GET";
}

bool is_valid_http_version(std::string http_version) { return http_version == "HTTP/1.1"; }

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

std::string decode_uri(std::string uri)
{
    // decoding of special characters such as %20, %2C... etc
    // ignore query parameters
    std::string decoded = "";

    for (int i = 0; i < uri.length(); i++)
    {
        if (uri[i] == '%' && isxdigit(uri[i + 1]) && isxdigit(uri[i + 1]))
        {
            decoded += from_hex(uri[i + 1]) * 16 + from_hex(uri[i + 2]);
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

std::string normalize_path(std::string urlPath, std::string root)
{
    // removes the malicious directory traverals and ignores ./ and stray /
    // path: /.//../.././../././file.html/  -> root + /file.html
    // path: /foo/bar/../file.html          -> root + /foo/file.html
    // path: /foo/bar/./file.html           -> root + /foo/bar/file.html
    // path: /foo/bar/////file.html         -> root + /foo/bar/file.html

    std::vector<std::string> parts;
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
        normalized += "/" + p;
    }

    return normalized;
}

std::string remove_params(std::string uri)
{
    int pos;
    if ((pos = uri.find("?")) != std::string::npos)
    {
        uri = uri.substr(0, pos);
    }

    return uri;
}

std::string normalize_uri(std::string uri, std::string root)
{
    std::string decoded = decode_uri(uri);
    std::string normalized = normalize_path(remove_params(decoded), root);

    return normalized;
}

bool is_valid_uri(std::string uri, std::string root, std::string& valid_uri)
{
    // TODO: Implement logic to check if the uri is valid
    std::string normalized_uri = normalize_uri(uri, root);
    valid_uri = normalized_uri;

    return true;
}

std::string attach_response_headers(std::string body)
{
    std::string headers = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: " +
                          std::to_string(body.length()) +
                          "\r\n"
                          "\r\n";

    return headers + body;
}

std::string response_not_implemented() { return "HTTP/1.1 501 Not Implemented\r\n"; }

std::string response_bad_request() { return "HTTP/1.1 400 Bad Request\r\n"; }

std::string response_not_found() { return "HTTP/1.1 404 Not Found\r\n"; }

std::string response_forbidden() { return "HTTP/1.1 403 Forbidden \r\n"; }

int is_directory(std::string path)
{
    struct stat path_stat;
    stat(path.c_str(), &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

std::string parse_req(char* raw_buffer, std::string root)
{
    std::string buffer(raw_buffer);

    HTTP_request request;
    state current_state = state::error;
    std::vector<std::string> request_tokens = split(buffer, "\r\n");

    std::string response;

    std::cout << "----------\n" << buffer << std::endl;

    for (int i = 0; i < request_tokens.size(); i++)
    {
        if (request_tokens.at(i).find("HTTP/") != std::string::npos)
        {
            current_state = state::request_line;

            std::vector<std::string> request_line = split(request_tokens.at(i), " ");

            if (!is_valid_method(request_line.at(0)))
            {
                current_state = state::error;
                response = response_not_implemented();
                break;
            }

            std::string valid_uri;
            if (!is_valid_uri(request_line.at(1), root, valid_uri) || !is_valid_http_version(request_line.at(2)))
            {
                current_state = state::error;
                response = response_bad_request();
                break;
            }

            request.request_line.method = HTTP_method::GET;
            request.request_line.path = valid_uri;
            request.request_line.protocol = "HTTP/1.1";
        }

        else if (request_tokens.at(i) == "")
        {
            current_state = state::body;
            i++;

            while (i < request_tokens.size())
            {
                request.body += request_tokens.at(i);
                i++;
            }
        }

        else
        {
            current_state = state::headers;

            int pos = 0;
            while ((pos = request_tokens.at(i).find(": ")) != std::string::npos)
            {
                std::string field = request_tokens.at(i).substr(0, pos);
                std::string value = request_tokens.at(i).substr(pos + 2, request_tokens.at(i).length());
                request.headers.insert({to_lower(field), value});
                i++;
            }
            i--;
        }
    }

    if (current_state != state::error)
    {
        if (access(request.request_line.path.c_str(), R_OK) == 0)
        {
            // check if the path is a directory
            // if true, add /index.html to the path
            if (is_directory(request.request_line.path))
            {
                request.request_line.path += "/index.html";
            }

            std::ifstream file(request.request_line.path);
            std::string str;
            std::string file_contents;
            while (std::getline(file, str))
            {
                file_contents += str + '\n';
            }

            response = attach_response_headers(file_contents);
        }
        else if (errno == EACCES)
        {
            // errno is global variable set by the syscalls
            // server doesn't have permission to read
            response = response_forbidden();
        }
        else if (errno == ENOENT)
        {
            response = response_not_found();
        }
    }

    return response;
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
        std::cerr << "inet_pton" << std::endl;
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

    socklen_t addr_size = sizeof(addr);
    char buffer[BUFFER_SIZE] = {0};

    while (1)
    {
        int client_fd = accept(socket_fd, (struct sockaddr*)&addr, &addr_size);
        if (client_fd == -1)
        {
            std::cerr << "ERROR: Failed to accept" << std::endl;
            exit(1);
        }

        std::memset(&buffer, 0, sizeof(buffer));
        int len = recv(client_fd, buffer, BUFFER_SIZE, 0);

        std::string response = parse_req(buffer, root);

        send(client_fd, response.c_str(), sizeof(char) * response.length(), 0);

        close(client_fd);
    }

    close(socket_fd);

    return 0;
}
