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
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <iostream>

constexpr int BUFFER_SIZE = 1000;
constexpr int PORT = 8080;
constexpr int ADDR = INADDR_ANY;
constexpr int BACKLOG = 10;

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

bool valid_method(std::string method)
{
    // only GET methods are valid for now
    return method == "GET";
}

bool valid_http_version(std::string http_version) { return http_version == "HTTP/1.1"; }

// stub
std::string normalize_uri(std::string uri)
{
    // if uri like: /.//../.././../././file.html/ is given
    // handle the decoding of special characters such as %20, %2C... etc
    // return only /file.html removing the malicious directory traverals, ignoring query parameters and stray /

    return uri;
}

bool valid_uri(std::string uri)
{
    std::string normalized_uri = normalize_uri(uri);
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

std::string parse_req(char* raw_buffer)
{
    std::string buffer(raw_buffer);
    std::vector<std::string> request = split(buffer, "\r\n");
    std::vector<std::string> status_line = split(request[0], " ");

    std::string response;

    if (!valid_method(status_line[0]))
    {
        response = "HTTP/1.1 501 Not Implemented\r\n\r\n";
        return response;
    }
    else if (!valid_uri(status_line[1]) || !valid_http_version(status_line[2]))
    {
        response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        return response;
    }

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
