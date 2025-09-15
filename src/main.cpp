#include "IOHandler.h"
#include <iostream>

int main() {
    IOHandler& handler = IOHandler::getInstance();
    std::cout << "IOHandler instance created" << std::endl;
    
    return 0;
}
