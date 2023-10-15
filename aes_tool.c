#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <openssl/aes.h>
#include <stdint.h>

#define AES_CHUNK_BITS    (128)
#define AES_CHUNK_BYTES   (16)
#define AES_MAX_KEY_LEN   (32)         // aes128 192 256, max is 256/8 = 32

static void help(int argc, char **argv)
{
    (void)argc;
    char *app = basename(argv[0]);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s <plain file> <encrypt file> <key> -e\n", app);
    fprintf(stderr, "    %s <encrypt file> <plain file> <key> -d\n\n", app);

    fprintf(stderr, "Exmaple:\n");
    fprintf(stderr, "    %s test.txt test.enc 123456 -e\n", app);
    fprintf(stderr, "    %s test.enc test.dec 123456 -d\n", app);
    fprintf(stderr, "    md5sum test.*\n");
}

static void hexdump(char *tag, uint8_t *buf, int len)
{
    if (tag)
        printf("%s ", tag);
    for(int i=0; i<len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("len=%d\n", len);
}

int main(int argc, char **argv)
{
    if (argc != 5 || (argc == 2 && !strcmp(argv[1], "-h"))) {
        help(argc, argv);
        exit(1);
    }

    if (strcmp(argv[4], "-e") == 0) {
        FILE *fp_plain = NULL;
        FILE *fp_encrypt = NULL;
        unsigned char plain_data[AES_CHUNK_BYTES], encrypt_data[AES_CHUNK_BYTES];
        unsigned char user_key[AES_MAX_KEY_LEN+1] = {0};
        AES_KEY key;
        int ret;

        strncpy((char *)user_key, argv[3], AES_MAX_KEY_LEN);
        AES_set_encrypt_key(user_key, AES_CHUNK_BITS, &key);

        fp_plain = fopen(argv[1], "rb");
        if (fp_plain == NULL) {
            perror("fopen plain file");
            exit(1);
        }

        fp_encrypt = fopen(argv[2], "wb");
        if (fp_encrypt == NULL) {
            perror("fopen encrypt file");
            exit(1);
        }

        while ((ret = fread(plain_data, 1, AES_CHUNK_BYTES, fp_plain))) {
            hexdump("plain", plain_data, ret);
            AES_encrypt(plain_data, encrypt_data, &key);
            memset(plain_data, 0, AES_CHUNK_BYTES);

            hexdump("encry", encrypt_data, AES_CHUNK_BYTES);
            fwrite(encrypt_data, 1, AES_CHUNK_BYTES, fp_encrypt);
            if (ret < AES_CHUNK_BYTES)
                break;
        }

        fwrite(&ret, 1, 1, fp_encrypt);
        fclose(fp_plain);
        fclose(fp_encrypt);
    } else if(strcmp(argv[4],"-d") == 0) {
        FILE *fp_plain = NULL;
        FILE *fp_encrypt = NULL;
        unsigned char plain_data[AES_CHUNK_BYTES], encrypt_data[AES_CHUNK_BYTES+2];
        unsigned char user_key[AES_MAX_KEY_LEN+1] = {0};
        AES_KEY key;
        int ret;

        strncpy((char *)user_key, argv[3], AES_MAX_KEY_LEN);
        //printf("key:%s\n", user_key);
        AES_set_decrypt_key(user_key, AES_CHUNK_BITS, &key);

        fp_encrypt = fopen(argv[1], "rb");
        if (fp_encrypt == NULL) {
            perror("fopen encrypt file");
            exit(1);
        }

        fp_plain = fopen(argv[2], "wb");
        if (fp_plain == NULL) {
            perror("fopen plain file");
            exit(1);
        }

        // read 2 more byte to identify if it's last chunk
        while ((ret = fread(encrypt_data, 1, AES_CHUNK_BYTES+2, fp_encrypt))) {
            AES_decrypt(encrypt_data, plain_data, &key);

            hexdump("plain", plain_data, ret < AES_CHUNK_BYTES+2 ? encrypt_data[AES_CHUNK_BYTES] : AES_CHUNK_BYTES);
            hexdump("encry", encrypt_data, AES_CHUNK_BYTES);

            if(ret < AES_CHUNK_BYTES+2) {
                fwrite(plain_data, 1, encrypt_data[AES_CHUNK_BYTES] ? encrypt_data[AES_CHUNK_BYTES] : AES_CHUNK_BYTES, fp_plain);
                break;
            }
            fwrite(plain_data, 1, AES_CHUNK_BYTES, fp_plain);
            fseek(fp_encrypt, -2, SEEK_CUR);
        }

        fclose(fp_plain);
        fclose(fp_encrypt);
    }
}