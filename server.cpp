/*

Credit: u/Drach88
https://www.reddit.com/r/C_Programming/comments/kbfa6t/comment/gfh8kid/

In terms of HTTP, the only resource you need is the HTTP standard itself. https://tools.ietf.org/html/rfc1945

For now, you're only going to concern yourself with:

What constitutes a properly-formatted request.

The conditions that would result in following properly-formatted responses: 200 OK, 400 Bad Request, 403 Forbidden,
404 Not Found, 500 Internal Service Error, and 501 Not Implemented (These are the codes you're going to implement)

For now, ignore everything related to headers other than noting that headers exist.

In terms of the sockets stuff, use Beej's guide. https://beej.us/guide/bgnet/. At its simplest, your program needs to:

    1. Create a socket

    2. Bind the socket to an address

    3. Listen on the address

    4. Block on Accept until a connection is made

    5. Read on the connected socket

    6. Figure out how to respond

    7. Write back on the connected socket

    8. Close the connection

    9. Go back to blocking on Accept

That out of the way, here's a quick checklist to give your project a little structure:

    1. Write a program that accepts a connection on a port (specify the port number as a command line argument), and
    immediately sends back a dummy HTTP 1.0 "200 OK" response, along with a dummy minimal HTML-encoded message before
    closing the connection. For the entire project, you're going to respond with HTTP 1.0 responses regardless of what
    version of the request you receive. Test this using netcat, then try it using a web browser.

    2. Modify your program to parse the request. You can ignore all of the headers for now. For now, you're only
    responding to validly formatted GET requests. Send the dummy message back for any validly formatted GET requests. If
    the request is improperly formatted, respond 400. For any other valid requests apart from GET requests, respond with
    501.


    -----------------------------------------------------------------------------------------------------------------


    3. Modify your program to take another command line argument for the "root" directory. Make a directory somewhere,
    and put a dummy HTML file called index.html and another dummy HTML file called whatever you want. Add a dummy image
    file as well. When your server starts up, verify that the folder exists and that your program has permissions to
    view the contents. Modify your program to parse the path from valid GET requests. Upon parsing the path, check the
    root folder to see if a file matches that filename. If so, respond 200, read the file and write the file to the
    client socket. If the path is "/" (ie. the root directory) serve index.html. If the requested file does not exist,
    respond 404 not found. Make sure your solution works for text files as well as binaries (ie. images).

    4. Add a couple of folders to your root folder, and add dummy html files (and dummy index.html files) to them. Add a
    few levels of nested folders. Modify your program to improve the path-parsing logic to handle folders, and handle
    responses appropriately.

    5. Modify the permissions on a few dummy folders and files to make their read permissions forbidden to your server
    program. Implement the 403 response appropriately. Scrutinize the URI standard, and modify your path-parsing to
    strip out (and handle) any troublesome characters. Modify your path-parsing to handle (ignore) query strings and
    fragments. (? and #). Modify your path-parsing to ensure it does not allow malicious folder navigation using "..".

There's plenty more you can do from there, but that breaks down the project into bite-sized pieces to get you to a
bare-minimum HTTP server.

*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define BUFFER_SIZE 1024 * 4
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

std::string normalize_uri(std::string uri)
{
    std::string decoded = decode_uri(uri);
    std::string normalized = normalize_path(decoded, ROOT);

    return normalized;
}

bool is_valid_uri(std::string uri, std::string& valid_uri)
{
    // TODO: Implement logic to check if the uri is valid
    std::string normalized_uri = normalize_uri(uri);
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

std::string parse_req(char* raw_buffer)
{
    std::string buffer(raw_buffer);

    HTTP_request request;
    state current_state = state::error;
    std::vector<std::string> request_tokens = split(buffer, "\r\n");

    for (int i = 0; i < request_tokens.size(); i++)
    {
        if (request_tokens.at(i).find("HTTP/") != std::string::npos)
        {
            current_state = state::request_line;

            std::vector<std::string> request_line = split(request_tokens.at(i), " ");

            // if (!is_valid_method(request_line.at(0)))
            // return response_not_implemented();

            std::string valid_uri;
            if (!is_valid_uri(request_line.at(1), valid_uri) || !is_valid_http_version(request_line.at(2)))
                return response_bad_request();

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

            for (auto& p : request.headers)
            {
                std::cout << p.first << ": " << p.second << std::endl;
            }
        }
    }

    std::cout << std::endl << "Path = " << request.request_line.path << std::endl << std::endl;

    std::string response;

    // dir and file logic here, access path using struct request
    /*
    char fname[] = "root/murtaza/index.html";
    if (access(fname, F_OK) == 0)
    {
        std::cout << fname << " exists!" << std::endl;
    }
    else
    {
        std::cout << fname << " does not exist!" << std::endl;
    }
    */

    // valid request
    response = attach_response_headers("<h1>Hello From Murtaza's Server</h1>\n");

    return response;
}

int main()
{
    std::cout << "Server started..." << std::endl;

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1)
    {
        std::cerr << "Failed to intialize socket" << std::endl;
        exit(1);
    }

    // Allows to immediately restart the server without waiting awhile
    int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = ADDR;

    if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        std::cerr << "Failed to bind" << std::endl;
        exit(1);
    }

    if (listen(socket_fd, BACKLOG) == -1)
    {
        std::cerr << "Failed to listen" << std::endl;
        exit(1);
    }

    socklen_t addr_size = sizeof(addr);
    char buffer[BUFFER_SIZE] = {0};

    while (1)
    {
        int client_fd = accept(socket_fd, (struct sockaddr*)&addr, &addr_size);
        if (client_fd == -1)
        {
            std::cerr << "Failed to accept" << std::endl;
            exit(1);
        }

        std::memset(&buffer, 0, sizeof(buffer));
        int len = recv(client_fd, buffer, BUFFER_SIZE, 0);
        std::cout << buffer << std::endl;

        std::string response = parse_req(buffer);

        send(client_fd, response.c_str(), sizeof(char) * response.length(), 0);

        close(client_fd);
    }

    close(socket_fd);

    return 0;
}
