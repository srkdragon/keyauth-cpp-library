#pragma once

#include <string>
#include <vector>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#endif

namespace KeyAuth
{

struct Subscription
{
    std::string name;
    std::string expiry;
};

struct UserData
{
    std::string username;
    std::string ip;
    std::string hwid;
    std::string createdate;
    std::string lastlogin;
    std::vector<Subscription> subscriptions;
};

struct AppData
{
    std::string numUsers;
    std::string numOnlineUsers;
    std::string numKeys;
    std::string version;
    std::string customerPanelLink;
    std::string downloadLink;
};

struct ChannelMessage
{
    std::string author;
    std::string message;
    std::string timestamp;
};

struct ResponseData
{
    bool success = false;
    std::string message;
    std::vector<ChannelMessage> channeldata;
};

class API
{
  public:
    // Constructor
    API(std::string name, std::string ownerid, std::string version, std::string url);

    // Core API methods
    void init();
    void login(std::string username, std::string password, std::string code = "");
    void regstr(std::string username, std::string password, std::string key,
                std::string email = "");
    void license(std::string key, std::string code = "");
    void upgrade(std::string username, std::string key);
    void check();

    // User management
    void changeUsername(std::string newusername);
    void logout();
    void forgot(std::string username, std::string email);

    // Application features
    std::string var(std::string varid);
    std::string getvar(std::string var);
    void setvar(std::string var, std::string data);
    void log(std::string msg);
    void ban(std::string reason = "");
    std::vector<unsigned char> download(std::string fileid);
    std::string webhook(std::string id, std::string params, std::string body = "",
                        std::string contenttype = "");

    // Chat features
    void chatget(std::string channel);
    bool chatsend(std::string message, std::string channel);

    // Stats
    std::string fetchonline();
    void fetchstats();
    bool checkblack();

    // Public data members
    UserData user_data;
    AppData app_data;
    ResponseData response;

  private:
    std::string name;
    std::string ownerid;
    std::string version;
    std::string url;
    std::string sessionid;
    std::string enckey;
    bool initialized = false;

    // Helper methods
    std::string makeRequest(const std::string& data);
    void checkInit();
};

} // namespace KeyAuth
