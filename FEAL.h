#ifndef CRYPTO2_GIT_FEAL_H
#define CRYPTO2_GIT_FEAL_H

#ifndef FEAL_H_
#define FEAL_H_

#include <stdlib.h>
#include <stdint.h>

typedef uint64_t uint64;
typedef uint32_t uint32;
typedef uint8_t uint8;

void FEAL_key_schedule(unsigned int N, uint32 keyL, uint32 keyR, uint32 *K);
void FEAL_encryption(unsigned int N, uint32 M0, uint32 M1, uint32 *C0,
                     uint32 *C1, uint32 *K);
void FEAL_decryption(unsigned int N, uint32 C0, uint32 C1, uint32 *M0,
                     uint32 *M1, uint32 *K);

#endif /* FEAL_H_ */

#endif //CRYPTO2_GIT_FEAL_H
