/*
    sha1.hpp - header of

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
    Safety fixes
        -- Eugene Hopkinson <slowriot at voxelstorm dot com>
*/

#ifndef SHA1_HPP
#define SHA1_HPP


#include <cstdint>
#include <vector>


class SHA1
{
public:
    SHA1();
    void update(std::vector<uint8_t> s);
    std::vector<uint8_t> final();
    void reset();

private:
    uint32_t digest[5];
    std::vector<uint8_t> buffer;
    uint64_t transforms;

    void reset(uint32_t digest[], std::vector<uint8_t> &buffer, uint64_t &transforms);
    uint32_t rol(const uint32_t value, const std::size_t bits);
    uint32_t blk(const uint32_t block[], const std::size_t i);
    void R0(const uint32_t block[], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const std::size_t i);
    void R1(uint32_t block[], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const std::size_t i);
    void R2(uint32_t block[], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const std::size_t i);
    void R3(uint32_t block[], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const std::size_t i);
    void R4(uint32_t block[], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const std::size_t i);
    void transform(uint32_t digest[], uint32_t block[], uint64_t &transforms);
    void buffer_to_block(const std::vector<uint8_t> &buffer, uint32_t block[]);
};


#endif /* SHA1_HPP */
