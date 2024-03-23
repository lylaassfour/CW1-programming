#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <vector>

using namespace std;

const int MAX_PASSWORDS = 100;
const int KEY = 3; // Caesar cipher key

// Encryption a string using Caesar cipher
string encrypt(const string &text, int key) {
    string result = "";

    for (char c : text) {
        if (isalpha(c)) {
            char shifted = (islower(c)) ? 'a' + (c - 'a' + key) % 26 : 'A' + (c - 'A' + key) % 26;
            result += shifted;
        } else {
            result += c;
        }
    }

    return result;
}

// Decrypt a string using Caesar cipher
string decrypt(const string &text, int key) {
    return encrypt(text, 26 - key); // Decryption is just encryption with the inverse key
}

struct PasswordEntry {
    string username;
    string encryptedPassword;
};

class PasswordManager {
private:
    PasswordEntry passwords[MAX_PASSWORDS];
    int numPasswords;
    bool loggedIn;
    string currentUsername;

public:
    PasswordManager() {
        numPasswords = 0;
        loggedIn = false;
    }

    void addPassword(const string &username, const string &password) {
        if (numPasswords < MAX_PASSWORDS) {
            bool usernameExists = false;
            for (int i = 0; i < numPasswords; ++i) {
                if (passwords[i].username == username) {
                    usernameExists = true;
                    break;
                }
            }
            
            if (!usernameExists) {
                passwords[numPasswords].username = username;
                passwords[numPasswords].encryptedPassword = encrypt(password, KEY);
                numPasswords++;
                cout << "Password added successfully." << endl;

                // Write the encrypted password to a text file
                ofstream outFile("passwords.txt", ios::app); // Open file in append mode
                if (outFile.is_open()) {
                    outFile << username << ":" << passwords[numPasswords - 1].encryptedPassword << endl;
                    outFile.close();
                    cout << "Encrypted password written to passwords.txt." << endl;
                } else {
                    cerr << "Error: Unable to open passwords.txt for writing." << endl;
                }
            } else {
                cout << "Username already exists. Please choose a different username." << endl;
            }
        } else {
            cout << "Password storage limit reached." << endl;
        }
    }

    string getPassword(const string &username) {
        for (int i = 0; i < numPasswords; ++i) {
            if (passwords[i].username == username) {
                return decrypt(passwords[i].encryptedPassword, KEY);
            }
        }
        return "Password not found.";
    }

    string generateRandomPassword(int length) {
        const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|;:,.<>?";
        const int charsetLength = charset.length();

        string password;
        for (int i = 0; i < length; ++i) {
            password += charset[rand() % charsetLength];
        }
        return password;
    }

    bool isLoggedIn() {
        return loggedIn;
    }

    void setLoggedIn(bool status) {
        loggedIn = status;
    }
    void changePassword(const string &username, const string &newPassword) {
        // Implementation to change password...
    }

    void deleteAccount(const string &username) {
        // Implementation to delete account...
    }
    
    string getCurrentUsername() {
        return currentUsername;
    }

    void setCurrentUsername(const string &username) {
        currentUsername = username;
    }

    bool isAuthorized(const string &username, const string &password) {
        ifstream passwordFile("passwords.txt");
        if (passwordFile.is_open()) {
            string line;
            while (getline(passwordFile, line)) {
                size_t pos = line.find(':');
                if (pos != string::npos && line.substr(0, pos) == username) {
                    string storedPassword = decrypt(line.substr(pos + 1), KEY);
                    if (password == storedPassword) {
                        passwordFile.close();
                        return true;
                    }
                }
            }
            passwordFile.close();
        }
        return false;
    }
    string retrievePassword(const string &username) {
        for (int i = 0; i < numPasswords; ++i) {
            if (passwords[i].username == username) {
                // Return decrypted password
                return decrypt(passwords[i].encryptedPassword, KEY);
            }
        }
        // Username not found
        return "Username not found.";
    }
};

int main() {
    srand(static_cast<unsigned int>(time(0))); // Seed for random number generation

    cout << "Welcome to my application!" << endl;

    PasswordManager manager;

    char choice;
    cout << "Choose an option:" << endl;
    cout << "1. Sign Up" << endl;
    cout << "2. Log In" << endl;
    cout << "Enter choice: ";
    cin >> choice;

    string username;
    string password;

    if (choice == '1') {
        cout << "Enter your username: ";
        cin >> username;
        cout << "Choose an option:" << endl;
        cout << "1. Create your own password" << endl;
        cout << "2. Generate a password" << endl;
        cout << "Enter choice: ";
        cin >> choice;
        if (choice == '1') {
            cout << "Enter your password: ";
            cin >> password;
            manager.addPassword(username, password);
        } else if (choice == '2') {
            password = manager.generateRandomPassword(12);
            cout << "Generated password: " << password << endl;
            manager.addPassword(username, password);
        } else {
            cout << "Invalid choice. Exiting..." << endl;
            return 1;
        }
    } else if (choice == '2') {
        cout << "Enter your username: ";
        cin >> username;
        cout << "Enter your password: ";
        cin >> password;
        if (manager.isAuthorized(username, password)) {
            manager.setLoggedIn(true);
            manager.setCurrentUsername(username);
        } else {
            cout << "User not found or password is incorrect." << endl;
            return 1;
        }
    } else {
        cout << "Invalid choice. Exiting..." << endl;
        return 1;
    }
if (manager.isLoggedIn()) {
    cout << "Login successful. Welcome, " << manager.getCurrentUsername() << "!" << endl;

    // Prompt user for further actions
    cout << "Choose an option:" << endl;
    cout << "1. Change Password" << endl;
    cout << "2. Delete Account" << endl;
    cout << "3. Retrieve Password" << endl;
    cout << "Enter choice: ";
    cin >> choice;

    if (choice == '1') {
        string newPassword;
        cout << "Enter your new password: ";
        cin >> newPassword;
    
        manager.changePassword(manager.getCurrentUsername(), newPassword);
    } else if (choice == '2') {
        manager.deleteAccount(manager.getCurrentUsername());
        manager.setLoggedIn(false); // Log out after deleting account
        cout << "Account deleted. Goodbye!" << endl;
        return 0;
    } else if (choice == '3') {
        string retrievedPassword = manager.getPassword(manager.getCurrentUsername());
        if (retrievedPassword != "Password not found.") {
            cout << "Retrieved password: " << retrievedPassword << endl;
        } else {
            cout << "Password not found." << endl;
        }
    } else {
        cout << "Invalid choice." << endl;
    }
}
}
}
}
