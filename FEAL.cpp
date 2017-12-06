#include "FEAL.h"

/**
 * S-function as described in Fast Data Encipherment Algorithm FEAL by Shimizu/Miyaguchi
 */
uint8 Sd(uint8 d, uint8 x, uint8 y) {
    uint8 sum = (x + y + d) % 256;

    uint8 result = (sum << 2) | (sum >> 6);

    return result;
}

/**
 * f-function as described in Fast Data Encipherment Algorithm FEAL by Shimizu/Miyaguchi
 *
 * Used for encryption and decryption.
 */
void f(uint8 *A, uint8 *Y, uint8 *U) {
    uint8 t1 = (A[0] ^ A[1]) ^Y[0];
    uint8 t2 = (A[2] ^ A[3]) ^Y[1];

    U[1] = Sd(1, t1, t2);
    U[2] = Sd(0, t2, U[1]);
    U[0] = Sd(0, A[0], U[1]);
    U[3] = Sd(1, A[3], U[2]);
}

/**
 * fK-function as described in Fast Data Encipherment Algorithm FEAL by Shimizu/Miyaguchi
 *
 * Used for subkey generation.
 */
void fK(uint8 *A, uint8 *B, uint8 *U) {
    uint8 t1 = A[0] ^A[1];
    uint8 t2 = A[2] ^A[3];

    U[1] = Sd(1, t1, t2 ^ B[0]);
    U[2] = Sd(0, t2, U[1] ^ B[1]);
    U[0] = Sd(0, A[0], U[1] ^ B[2]);
    U[3] = Sd(1, A[3], U[2] ^ B[3]);
}

/**
 * Generates the keyschedule for N rounds. Generates N + 8 keys
 */
void FEAL_key_schedule(unsigned int N, uint32 keyL, uint32 keyR, uint32 *K) {
    int i, j, i2;

    uint8 U[4], U0[4], U1[4], U2[4], V[4];

    for (i = 0; i < 4; i++)
        U2[i] = 0;
    U1[0] = keyL >> 24;
    U1[1] = keyL >> 16;
    U1[2] = keyL >> 8;
    U1[3] = keyL & 255;
    U0[0] = keyR >> 24;
    U0[1] = keyR >> 16;
    U0[2] = keyR >> 8;
    U0[3] = keyR & 255;
    for (i = 1; i <= (N / 2) + 4; i++) {
        for (j = 0; j < 4; j++)
            V[j] = U0[j] ^ U2[j];
        fK(U1, V, U);
        i2 = 2 * i;
        K[i2 - 2] = (U[0] << 8) | U[1];
        K[i2 - 1] = (U[2] << 8) | U[3];
        for (j = 0; j < 4; j++)
            U2[j] = U1[j];
        for (j = 0; j < 4; j++)
            U1[j] = U0[j];
        for (j = 0; j < 4; j++)
            U0[j] = U[j];
    }
}

/**
 * Encrypts plaintextparts M0 and M1 with given keyschedule K for N rounds.
 */
void FEAL_encryption(unsigned int N, uint32 M0, uint32 M1, uint32 *C0,
                     uint32 *C1, uint32 *K) {
    int i, j;
    uint32 L, L_END, ML, MR, R, R_END;
    uint8 L0[4], L1[4], R0[4], R1[4], Y[2];

    uint8 U[4];

    //Prerun
    ML = M0, MR = M1;
    L = ML ^ ((K[N] << 16) | K[N + 1]);
    R = MR ^ ((K[N + 2] << 16) | K[N + 3]);
    R ^= L;

    //Split message into 8-bit parts
    L0[0] = L >> 24;
    L0[1] = L >> 16;
    L0[2] = L >> 8;
    L0[3] = L & 255;
    R0[0] = R >> 24;
    R0[1] = R >> 16;
    R0[2] = R >> 8;
    R0[3] = R & 255;

    //Perform rounds
    for (i = 0; i < N; i++) {
        for (j = 0; j < 4; j++)
            L1[j] = R0[j];
        Y[0] = K[i] >> 8;
        Y[1] = K[i] & 255;
        f(R0, Y, U);
        for (j = 0; j < 4; j++) {
            R1[j] = (L0[j] ^ U[j]) & 255;
            L0[j] = L1[j];
            R0[j] = R1[j];
        }
    }

    //Merge to 32-bit
    L_END = L1[0] << 24;
    L_END |= L1[1] << 16;
    L_END |= L1[2] << 8;
    L_END |= L1[3] & 255;
    R_END = R1[0] << 24;
    R_END |= R1[1] << 16;
    R_END |= R1[2] << 8;
    R_END |= R1[3] & 255;

    //Afterrun
    L_END ^= R_END;
    L_END ^= (K[N + 6] << 16) | K[N + 7];
    R_END ^= (K[N + 4] << 16) | K[N + 5];

    //write result
    *C0 = R_END;
    *C1 = L_END;
}

/**
 * Decrypts ciphertextparts C0 and C1 with given keyschedule K for N rounds.
 */
void FEAL_decryption(unsigned int N, uint32 C0, uint32 C1, uint32 *M0,
                     uint32 *M1, uint32 *K) {
    int i, j;
    uint32 L, L_END, ML, MR, R, R_END;
    uint8 L0[4], L1[4], R0[4], R1[4], Y[2];

    uint8 U[4];

    //prerun
    ML = C0, MR = C1;
    L = ML ^ ((K[N + 4] << 16) | K[N + 5]);
    R = MR ^ ((K[N + 6] << 16) | K[N + 7]);
    R ^= L;

    //Split cipher into 8-bit parts
    L0[0] = L >> 24;
    L0[1] = L >> 16;
    L0[2] = L >> 8;
    L0[3] = L & 255;
    R0[0] = R >> 24;
    R0[1] = R >> 16;
    R0[2] = R >> 8;
    R0[3] = R & 255;

    //Perform rounds
    for (i = N - 1; i >= 0; i--) {
        for (j = 0; j < 4; j++)
            L1[j] = R0[j];
        Y[0] = K[i] >> 8;
        Y[1] = K[i] & 255;
        f(R0, Y, U);
        for (j = 0; j < 4; j++) {
            R1[j] = (L0[j] ^ U[j]) & 255;
            L0[j] = L1[j];
            R0[j] = R1[j];
        }
    }

    //Merge to 32-bit
    L_END = L1[0] << 24;
    L_END |= L1[1] << 16;
    L_END |= L1[2] << 8;
    L_END |= L1[3] & 255;
    R_END = R1[0] << 24;
    R_END |= R1[1] << 16;
    R_END |= R1[2] << 8;
    R_END |= R1[3] & 255;

    //Afterrun
    L_END ^= R_END;
    R_END ^= (K[N] << 16) | K[N + 1];
    L_END ^= (K[N + 2] << 16) | K[N + 3];

    //write result
    *M0 = R_END;
    *M1 = L_END;
}