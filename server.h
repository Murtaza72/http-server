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

std::string decode_uri(std::string uri);

std::string normalize_path(std::string urlPath, std::string root);

std::string remove_params(std::string uri);

std::string normalize_uri(std::string uri, std::string root);

bool is_valid_uri(std::string uri, std::string root, std::string& valid_uri);

void get_status_desc(HTTP_response& rec);

std::string get_content_type(std::string path);

void get_file_contents(HTTP_request& req, HTTP_response& res);

std::string parse_req(char* raw_buffer, std::string root);

#endif
