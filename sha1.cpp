/*
    sha1.cpp - source code of

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

#include "sha1.hpp"
#include <sstream>
#include <iomanip>


static const size_t BLOCK_INTS = 16;  /* number of 32bit integers per SHA1 block */
static const size_t BLOCK_BYTES = BLOCK_INTS * 4;


void SHA1::reset(uint32_t digest[], std::vector<uint8_t> &buffer, uint64_t &transforms)
{
    /* SHA1 initialization constants */
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    /* Reset counters */
    std::vector<uint8_t>().swap(buffer);
    transforms = 0;
}


uint32_t SHA1::rol(const uint32_t value, const size_t bits)
{
    return (value << bits) | (value >> (32 - bits));
}


uint32_t SHA1::blk(const uint32_t block[BLOCK_INTS], const size_t i)
{
    return rol(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i], 1);
}


/*
 * (R0+R1), R2, R3, R4 are the different operations used in SHA1
 */

void SHA1::R0(const uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    z += ((w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
    w = rol(w, 30);
}


void SHA1::R1(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += ((w&(x^y))^y) + block[i] + 0x5a827999 + rol(v, 5);
    w = rol(w, 30);
}


void SHA1::R2(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += (w^x^y) + block[i] + 0x6ed9eba1 + rol(v, 5);
    w = rol(w, 30);
}


void SHA1::R3(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += (((w|x)&y)|(w&x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
    w = rol(w, 30);
}


void SHA1::R4(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t &w, const uint32_t x, const uint32_t y, uint32_t &z, const size_t i)
{
    block[i] = blk(block, i);
    z += (w^x^y) + block[i] + 0xca62c1d6 + rol(v, 5);
    w = rol(w, 30);
}


/*
 * Hash a single 512-bit block. This is the core of the algorithm.
 */

void SHA1::transform(uint32_t digest[], uint32_t block[BLOCK_INTS], uint64_t &transforms)
{
    /* Copy digest[] to working vars */
    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    uint32_t * p[5] = {&a, &b, &c, &d, &e};
    auto rolBlk = [&]() {
        uint32_t * pr = p[4];
        p[4] = p[3];
        p[3] = p[2];
        p[2] = p[1];
        p[1] = p[0];
        p[0] = pr;
    };

    for (int i=0; i<16; i++) {
        R0(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=0; i<4; i++) {
        R1(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=4; i<16; i++) {
        R2(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=0; i<8; i++) {
        R2(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=8; i<16; i++) {
        R3(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=0; i<12; i++) {
        R3(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=12; i<16; i++) {
        R4(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    for (int i=0; i<16; i++) {
        R4(block, *(p[0]), *(p[1]), *(p[2]), *(p[3]), *(p[4]), i);
        rolBlk();
    }

    /* Add the working vars back into digest[] */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;

    /* Count the number of transformations */
    transforms++;
}


void SHA1::buffer_to_block(const std::vector<uint8_t> &buffer, uint32_t block[BLOCK_INTS])
{
    /* Convert the std::string (byte buffer) to a uint32_t array (MSB) */
    for (size_t i = 0; i < BLOCK_INTS; i++)
    {
        block[i] = (buffer[4*i+3] & 0xff)
                   | (buffer[4*i+2] & 0xff)<<8
                   | (buffer[4*i+1] & 0xff)<<16
                   | (buffer[4*i+0] & 0xff)<<24;
    }
}


SHA1::SHA1()
{
    reset();
}


void SHA1::update(std::vector<uint8_t> data)
{
    std::vector<uint8_t>::iterator idx = data.begin();
    while (true)
    {
        int remains = std::min(static_cast<size_t>(std::distance(idx, data.end())),BLOCK_BYTES);
        std::copy(idx, idx+remains, std::back_inserter(buffer));
        if (buffer.size() != BLOCK_BYTES)
            return;
        uint32_t block[BLOCK_INTS];
        buffer_to_block(buffer, block);
        transform(digest, block, transforms);
        buffer.clear();
        idx += BLOCK_BYTES;
    }
}


/*
 * Add padding and return the message digest.
 */

std::vector<uint8_t> SHA1::final()
{
    /* Total number of hashed bits */
    uint64_t total_bits = (transforms*BLOCK_BYTES + buffer.size()) * 8;

    /* Padding */
    buffer.push_back(0x80);
    size_t orig_size = buffer.size();
    while (buffer.size() < BLOCK_BYTES)
    {
        buffer.push_back(0x00);
    }

    uint32_t block[BLOCK_INTS];
    buffer_to_block(buffer, block);

    if (orig_size > BLOCK_BYTES - 8)
    {
        transform(digest, block, transforms);
        for (size_t i = 0; i < BLOCK_INTS - 2; i++)
        {
            block[i] = 0;
        }
    }

    /* Append total_bits, split this uint64_t into two uint32_t */
    block[BLOCK_INTS - 1] = total_bits;
    block[BLOCK_INTS - 2] = (total_bits >> 32);
    transform(digest, block, transforms);

    /* Return digest */
    std::vector<uint8_t> result;
    for (int i=0; i<5; i++) {
        uint32_t swapped = __builtin_bswap32(digest[i]);
        const uint8_t * ptr = reinterpret_cast<uint8_t *>(&swapped);
        std::copy(ptr,ptr+sizeof(uint32_t),std::back_inserter(result));
    }
    reset();
    return result;
}

void SHA1::reset()
{
    reset(digest,buffer,transforms);
}

