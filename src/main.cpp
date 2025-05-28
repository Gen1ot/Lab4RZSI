#include "../include/Singlton.h"


int main() {
    std::string path, mypass;
    int choice;
    
    std::cout << "1. Encrypt folder\n2. Decrypt folder\nWhat you choose? ";
    std::cin >> choice;
    std::cin.ignore();
    
    std::cout << "Enter the path: ";
    std::getline(std::cin, path);
    
    std::cout << "Give me your password, pls: ";
    std::getline(std::cin, mypass);
    
    switch (choice) {
        case 1:
            Singlton::Instance().EncryptFolder(path, mypass);
            break;
        case 2:
            Singlton::Instance().DecryptFolder(path, mypass);
            break;
        default:
            std::cerr << "Oh! This is incorrect choice!" << std::endl;
            return 1;
    }
    
    return 0;
}
