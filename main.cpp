#include "FEAL.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int i;
    unsigned int N = 8;

    /*
    if (sizeof(uint32) != 4) {
        printf("uint32 size expected: 4 Byte\nuint32 has size %lu Byte\n",
                sizeof(uint32));
        exit(EXIT_FAILURE);
    }
    if (sizeof(uint8) != 1) {
        printf("uint8 size expected: 1 Byte\nuint8 has size %lu Byte\n",
                sizeof(uint8));
        exit(EXIT_FAILURE);
    }
     */

    int opt;
    int decrypt = 0, verbose = 0, text = 0;
    char *inputFilePath = 0, *outputFilePath = 0;

    uint64 key = 0x0123456789ABCDEF;
    uint32 keyL = 0x01234567, keyR = 0x89ABCDEF;
    char *ptr;

    //command-line parsing
    while ((opt = getopt(argc, argv, "n:tdi:o:k:v")) != -1) {
        switch (opt) {
            case 'n':
                N = atoi(optarg);
                break;
            case 'd':
                decrypt = 1;
                break;
            case 'i':
                inputFilePath = optarg;
                break;
            case 'o':
                outputFilePath = optarg;
                break;
            case 'k':
                key = strtoull(optarg, &ptr, 16);
                keyL = key >> 32;
                keyR = key & 0xFFFFFFFF;
                break;
            case 'v':
                printf("Activating verbose mode\n");
                verbose = 1;
                break;
            case 't':
                printf("Using text-mode\n");
                text = 1;
                break;
            default:
                printf(
                        "Usage: %s -n NUMBEROFROUNDS -k 64bitKEY -o OUTPUT -i INPUT [-d]\n",
                        argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    //only allowed for N mod 2 == 0
    if (N % 2 == 1) {
        printf("Number of rounds has to be even!\n");
        exit(EXIT_FAILURE);
    }

    if (!inputFilePath | !outputFilePath) {
        printf("No input- or outputfile given!\n");
    }

    //calculate key-schedule
    uint32 K[N + 8];
    printf("Using FEAL-%d\n", N);
    printf("Starting FEAL_key_schedule with:\n");
    printf("key: %08X %08X \n", keyL, keyR);
    FEAL_key_schedule(N, keyL, keyR, K);

    //log all subkeys if verbose-mode
    if (verbose) {
        printf("Keyschedule generated:\n");
        for (i = 0; i < N + 8; i++)
            printf("K[%d]: %04X\n", i, K[i]);
    }

    unsigned int inputLength = 0;
    FILE *inputFile;
    printf("Opening file from %s\n", inputFilePath);

    if (!text) {
        //open as binary
        inputFile = fopen(inputFilePath, "rb");
        //get filelength
        fseek(inputFile, 0L, SEEK_END);
        int filesize = ftell(inputFile);
        rewind(inputFile);
        printf("Size: %d Byte\n", filesize);
        inputLength = filesize / 8;
    } else {
        //open as text
        inputFile = fopen(inputFilePath, "r");
        //get filelength
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), inputFile)) {
            inputLength++;
        }
        rewind(inputFile);
        printf("Lines: %d\n", inputLength);
    }

    if (!inputFile) {
        printf("Could not open inputFile\n");
        return EXIT_FAILURE;
    }

    printf("Reading %d 64Bit-blocks\n", inputLength);

    //open outputfile
    FILE *outputFile;
    printf("Writing file to %s\n", outputFilePath);
    if (!text) {
        outputFile = fopen(outputFilePath, "wb");
    } else {
        outputFile = fopen(outputFilePath, "w");
    }
    if (!outputFile) {
        printf("Could not open outputFile\n");
        return EXIT_FAILURE;
    }

    uint64 input;
    uint32 in0, in1;
    uint32 out0, out1;
    uint64 output;
    char inputLine[256];
    //for each inputblock
    for (i = 0; i < inputLength; i++) {
        //read block
        if (!text) {
            fread(&input, sizeof(uint64), 1, inputFile);
        } else {
            fgets(inputLine, sizeof(inputLine), inputFile);
            input = strtoull(inputLine, 0, 16);
        }
        //split for algorithm
        in0 = input >> 32;
        in1 = input & 0xFFFFFFFF;
        //log if verbose
        if (verbose)
            printf("in: %04X %04X\n", in0, in1);
        //decrypt or encrypt
        if (decrypt) {
            FEAL_decryption(N, in0, in1, &out0, &out1, K);
        } else {
            FEAL_encryption(N, in0, in1, &out0, &out1, K);
        }
        //log if verbose
        if (verbose)
            printf("out: %04X %04X\n", out0, out1);
        //merge for output
        output = (uint64) out0 << 32 | out1;
        //write to file
        if (!text) {
            fwrite(&output, sizeof(uint64), 1, outputFile);
        } else {
            fprintf(outputFile, "%016llX\n", output);
        }
    }

    fclose(inputFile);
    fclose(outputFile);

    printf("DONE\n");

    return EXIT_SUCCESS;
}