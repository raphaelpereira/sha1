/*
    demo_sha1.cpp - demo program of
 
    ============
    SHA-1 in C++
    ============
 
    100% Public Domain.
 
    Original C Code
        -- Steve Reid <steve@edmweb.com>
    Small changes to fit into bglibs
        -- Bruce Guenter <bruce@untroubled.org>
    Translation to simpler C++ Code
        -- Volker Grabsch <vog@notjusthosting.com>
*/

#include "sha1.hpp"
#include <string>
#include <iostream>
#include <vector>
#include <cstdio>
using std::string;
using std::cout;
using std::endl;

int main(int argc, const char *argv[])
{
    const std::vector<uint8_t> input = {'a','b','c'};

    SHA1 checksum;
    checksum.update(input);
    const std::vector<uint8_t> hash = checksum.final();

    cout << "The SHA-1 of \"abc\" is: ";
    for (int i=0; i<hash.size(); i++)
        std::printf("%02x", hash[i]);

    cout << endl;

    return 0;
}
