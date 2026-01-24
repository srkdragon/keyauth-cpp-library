#include "keyauth/keyauth.hpp"

#include <iostream>

int main()
{
    try
    {
        // Initialize KeyAuth API
        // Replace these with your actual credentials from keyauth.cc
        KeyAuth::API api("Surakarndragon's Application", // Your application name
                         "mCoqYG4Adm",                   // Your owner ID (10 characters)
                         "1.0",                          // Your application version
                         "https://keyauth.win/api/1.3/"  // KeyAuth API endpoint
        );

        std::cout << "Initializing..." << std::endl;
        api.init();

        if (!api.response.success)
        {
            std::cout << "Failed to initialize: " << api.response.message << std::endl;
            return 1;
        }

        std::cout << "Initialized successfully!" << std::endl;
        std::cout << "App Version: " << api.app_data.version << std::endl;
        std::cout << "Total Users: " << api.app_data.numUsers << std::endl;

        // Example: Login
        std::string key;
        std::cout << "\nEnter license key: ";
        std::cin >> key;

        api.license(key);

        if (api.response.success)
        {
            std::cout << "\nLogin successful!" << std::endl;
            std::cout << "Username: " << api.user_data.username << std::endl;
            std::cout << "IP: " << api.user_data.ip << std::endl;
            std::cout << "HWID: " << api.user_data.hwid << std::endl;
            std::cout << "Created: " << api.user_data.createdate << std::endl;
            std::cout << "Last Login: " << api.user_data.lastlogin << std::endl;

            std::cout << "\nSubscriptions:" << std::endl;
            for (const auto& sub : api.user_data.subscriptions)
                std::cout << "  - " << sub.name << " (Expires: " << sub.expiry << ")" << std::endl;
        }
        else
        {
            std::cout << "Login failed: " << api.response.message << std::endl;
        }

        // Example: Get a variable
        std::string myVar = api.var("variable_id");
        std::cout << "Variable value: " << myVar << std::endl;

        // Example: Log something
        api.log("User logged in successfully");
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
