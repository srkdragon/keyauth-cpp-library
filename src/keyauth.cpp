#include "keyauth/keyauth.hpp"

#include "curl/curl.h"
#include "libsodium/sodium.h"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sddl.h>
#include <sstream>
#include <vector>

// Global variables for signature verification
static std::string g_signature;
static std::string g_timestamp;
static const std::string API_PUBLIC_KEY =
    "5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b";

namespace KeyAuth
{

// Helper function for CURL write callback
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Helper function for CURL header callback
static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata)
{
    size_t totalSize = size * nitems;
    std::string header(buffer, totalSize);

    std::string lowercase = header;
    std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(), ::tolower);

    if (lowercase.find("x-signature-ed25519: ") == 0)
    {
        g_signature = header.substr(header.find(": ") + 2);
        g_signature.erase(g_signature.find_last_not_of("\r\n") + 1);
    }

    if (lowercase.find("x-signature-timestamp: ") == 0)
    {
        g_timestamp = header.substr(header.find(": ") + 2);
        g_timestamp.erase(g_timestamp.find_last_not_of("\r\n") + 1);
    }

    return totalSize;
}

// Helper function to decode hex string
static std::string hexDecode(const std::string& hex)
{
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

// Verify Ed25519 signature
static bool verifySignature(const std::string& signature, const std::string& timestamp,
                            const std::string& body)
{
    try
    {
        std::string message = timestamp + body;

        std::string sigBytes = hexDecode(signature);
        std::string keyBytes = hexDecode(API_PUBLIC_KEY);

        if (sigBytes.length() != crypto_sign_BYTES ||
            keyBytes.length() != crypto_sign_PUBLICKEYBYTES)
        {
            return false;
        }

        int result = crypto_sign_verify_detached(
            (const unsigned char*)sigBytes.c_str(), (const unsigned char*)message.c_str(),
            message.length(), (const unsigned char*)keyBytes.c_str());

        return result == 0;
    }
    catch (...)
    {
        return false;
    }
}

// Get HWID (User SID)
static std::string get_hwid()
{
    std::string result = "none";
    HANDLE hToken = nullptr;
    DWORD dwLength = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            std::vector<BYTE> buffer(dwLength);
            if (GetTokenInformation(hToken, TokenUser, buffer.data(), dwLength, &dwLength))
            {
                PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
                LPSTR rawSidString = nullptr;
                if (ConvertSidToStringSidA(pTokenUser->User.Sid, &rawSidString))
                {
                    result = std::string(rawSidString);
                    LocalFree(rawSidString);
                }
            }
        }
        CloseHandle(hToken);
    }

    return result;
}

// Load user data from JSON
static void loadUserData(UserData& user_data, const nlohmann::json& data)
{
    user_data.username = data.value("username", "");
    user_data.ip = data.value("ip", "");
    user_data.hwid = data.value("hwid", "");
    user_data.createdate = data.value("createdate", "");
    user_data.lastlogin = data.value("lastlogin", "");

    user_data.subscriptions.clear();
    if (data.contains("subscriptions") && data["subscriptions"].is_array())
    {
        for (const auto& sub : data["subscriptions"])
        {
            Subscription subscription;
            subscription.name = sub.value("subscription", "");
            subscription.expiry = sub.value("expiry", "");
            user_data.subscriptions.push_back(subscription);
        }
    }
}

// Load app data from JSON
static void loadAppData(AppData& app_data, const nlohmann::json& data)
{
    app_data.numUsers = data.value("numUsers", "");
    app_data.numOnlineUsers = data.value("numOnlineUsers", "");
    app_data.numKeys = data.value("numKeys", "");
    app_data.version = data.value("version", "");
    app_data.customerPanelLink = data.value("customerPanelLink", "");
    app_data.downloadLink = data.value("downloadLink", "");
}

// Load response data from JSON
static void loadResponseData(ResponseData& response, const nlohmann::json& data)
{
    response.success = data.value("success", false);
    response.message = data.value("message", "");
}

// Load channel data from JSON
static void loadChannelData(ResponseData& response, const nlohmann::json& data)
{
    response.success = data.value("success", false);
    response.message = data.value("message", "");
    response.channeldata.clear();

    if (data.contains("messages") && data["messages"].is_array())
    {
        for (const auto& msg : data["messages"])
        {
            ChannelMessage message;
            message.author = msg.value("author", "");
            message.message = msg.value("message", "");
            message.timestamp = std::to_string(msg.value("timestamp", 0));
            response.channeldata.push_back(message);
        }
    }
}

// Constructor
API::API(std::string name, std::string ownerid, std::string version, std::string url)
    : name(name), ownerid(ownerid), version(version), url(url)
{
    if (sodium_init() < 0)
        throw std::runtime_error("Failed to initialize libsodium");
}

// Make HTTP request
std::string API::makeRequest(const std::string& data)
{
    CURL* curl = curl_easy_init();
    if (!curl)
        throw std::runtime_error("Failed to initialize CURL");

    std::string response;
    g_signature.clear();
    g_timestamp.clear();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, nullptr);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));

    // Verify signature
    if (!verifySignature(g_signature, g_timestamp, response))
        throw std::runtime_error("Signature verification failed");

    return response;
}

// Check if initialized
void API::checkInit()
{
    if (!initialized)
        throw std::runtime_error("API not initialized. Call init() first.");
}

// Initialize the API
void API::init()
{
    CURL* curl = curl_easy_init();
    std::string data = "type=init&ver=" + version +
                       "&name=" + std::string(curl_easy_escape(curl, name.c_str(), 0)) +
                       "&ownerid=" + ownerid;
    curl_easy_cleanup(curl);

    std::string response = makeRequest(data);

    if (response == "KeyAuth_Invalid")
        throw std::runtime_error("Application not found");

    nlohmann::json json = nlohmann::json::parse(response);

    if (json.value("ownerid", "") != ownerid)
        throw std::runtime_error("Owner ID mismatch");

    loadResponseData(this->response, json);

    if (json.value("success", false))
    {
        sessionid = json.value("sessionid", "");
        initialized = true;

        if (json.contains("appinfo"))
            loadAppData(this->app_data, json["appinfo"]);
    }
    else
    {
        throw std::runtime_error("Init failed: " + response);
    }
}

// Login
void API::login(std::string username, std::string password, std::string code)
{
    checkInit();

    std::string hwid = get_hwid();
    std::string data = "type=login&username=" + username + "&pass=" + password + "&code=" + code +
                       "&hwid=" + hwid + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    if (json.value("ownerid", "") != ownerid)
        throw std::runtime_error("Owner ID mismatch");

    loadResponseData(this->response, json);

    if (json.value("success", false) && json.contains("info"))
        loadUserData(this->user_data, json["info"]);
}

// Register
void API::regstr(std::string username, std::string password, std::string key, std::string email)
{
    checkInit();

    std::string hwid = get_hwid();
    std::string data = "type=register&username=" + username + "&pass=" + password + "&key=" + key +
                       "&email=" + email + "&hwid=" + hwid + "&sessionid=" + sessionid +
                       "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    if (json.value("ownerid", "") != ownerid)
        throw std::runtime_error("Owner ID mismatch");

    loadResponseData(this->response, json);

    if (json.value("success", false) && json.contains("info"))
        loadUserData(this->user_data, json["info"]);
}

// License
void API::license(std::string key, std::string code)
{
    checkInit();

    std::string hwid = get_hwid();
    std::string data = "type=license&key=" + key + "&code=" + code + "&hwid=" + hwid +
                       "&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    if (json.value("ownerid", "") != ownerid)
        throw std::runtime_error("Owner ID mismatch");

    loadResponseData(this->response, json);

    if (json.value("success", false) && json.contains("info"))
        loadUserData(this->user_data, json["info"]);
}

// Upgrade
void API::upgrade(std::string username, std::string key)
{
    checkInit();

    std::string data = "type=upgrade&username=" + username + "&key=" + key +
                       "&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    if (json.value("ownerid", "") != ownerid)
        throw std::runtime_error("Owner ID mismatch");

    loadResponseData(this->response, json);
}

// Check session
void API::check()
{
    checkInit();

    std::string data =
        "type=check&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);
}

// Change username
void API::changeUsername(std::string newusername)
{
    checkInit();

    std::string data = "type=changeUsername&newUsername=" + newusername +
                       "&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    if (json.value("ownerid", "") != ownerid)
        throw std::runtime_error("Owner ID mismatch");

    loadResponseData(this->response, json);
}

// Logout
void API::logout()
{
    checkInit();

    std::string data =
        "type=logout&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);
}

// Forgot password
void API::forgot(std::string username, std::string email)
{
    checkInit();

    std::string data = "type=forgot&username=" + username + "&email=" + email +
                       "&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);
}

// Get variable
std::string API::var(std::string varid)
{
    checkInit();

    std::string data = "type=var&varid=" + varid + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    if (json.value("success", false))
        return json.value("message", "");

    return "";
}

// Get user variable
std::string API::getvar(std::string var)
{
    checkInit();

    std::string data = "type=getvar&var=" + var + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    if (json.value("success", false))
        return json.value("response", "");

    return "";
}

// Set user variable
void API::setvar(std::string var, std::string data_value)
{
    checkInit();

    std::string data = "type=setvar&var=" + var + "&data=" + data_value +
                       "&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);
}

// Log
void API::log(std::string msg)
{
    checkInit();

    std::string data = "type=log&message=" + msg + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);
}

// Ban
void API::ban(std::string reason)
{
    checkInit();

    std::string data = "type=ban&reason=" + reason + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);
}

// Download file
std::vector<unsigned char> API::download(std::string fileid)
{
    checkInit();

    std::string data = "type=file&fileid=" + fileid + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    std::vector<unsigned char> result;
    if (json.value("success", false) && json.contains("contents"))
    {
        std::string contents = json["contents"];
        result.assign(contents.begin(), contents.end());
    }

    return result;
}

// Webhook
std::string API::webhook(std::string id, std::string params, std::string body,
                         std::string contenttype)
{
    checkInit();

    std::string data = "type=webhook&webid=" + id + "&params=" + params + "&body=" + body +
                       "&conttype=" + contenttype + "&sessionid=" + sessionid + "&name=" + name +
                       "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    if (json.value("success", false))
        return json.value("response", "");

    return "";
}

// Chat get
void API::chatget(std::string channel)
{
    checkInit();

    std::string data = "type=chatget&channel=" + channel + "&sessionid=" + sessionid +
                       "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadChannelData(this->response, json);
}

// Chat send
bool API::chatsend(std::string message, std::string channel)
{
    checkInit();

    std::string data = "type=chatsend&message=" + message + "&channel=" + channel +
                       "&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    return json.value("success", false);
}

// Fetch online users
std::string API::fetchonline()
{
    checkInit();

    std::string data =
        "type=fetchOnline&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    if (json.value("success", false) && json.contains("users"))
        return json["users"].dump();

    return "";
}

// Fetch stats
void API::fetchstats()
{
    checkInit();

    std::string data =
        "type=fetchStats&sessionid=" + sessionid + "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    if (json.value("success", false) && json.contains("appinfo"))
        loadAppData(this->app_data, json["appinfo"]);
}

// Check blacklist
bool API::checkblack()
{
    checkInit();

    std::string data = "type=checkblacklist&hwid=" + get_hwid() + "&sessionid=" + sessionid +
                       "&name=" + name + "&ownerid=" + ownerid;

    std::string resp = makeRequest(data);
    nlohmann::json json = nlohmann::json::parse(resp);

    loadResponseData(this->response, json);

    return json.value("success", false);
}

} // namespace KeyAuth
