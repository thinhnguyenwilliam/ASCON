#include <stdio.h>
#include <conio.h>
#include <stdint.h>
#include <string.h>
#include "ascon.h"

const uint8_t Key[KEY_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
const uint8_t Nonce[NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
const char associated_data[] = "Hello, world!";
const char plain_data[] = "A message in here!";

int main() {
    //Initialization
    uint8_t IV[IV_LEN];
    uint8_t S[S_LEN];
    // Tạo IV dựa trên thông số k, r, a, và b cho Ascon-128
    Init_IV(IV, 128, 12, 8, 6);
    // Tạo S từ IV, Key, và Nonce
    Init_S(S, IV, Key, Nonce);
    permutation(S, 8);
    for (size_t i = 0; i < KEY_LEN; i++) {
        S[S_LEN - KEY_LEN + i] ^= Key[i];
    }

    //Processing Associated Data Ascon
    process_associated_data(S, associated_data, sizeof(associated_data), 6, 12);

    //Processing Plaintext Ascon
    size_t ciphertext_length = calculate_ciphertext_length(sizeof(plain_data), 12);
    uint8_t C[ciphertext_length];
    encrypt_plaintext(S, plain_data, sizeof(plain_data), C, 6, 12);

    //Finalization
    uint8_t calculated_tag[TAG_LEN];
    Init_tag(S, Key, calculated_tag, 8, 12);

    return 0;
}




/*
    // In ra IV và S được tạo ra
    printf("IV: ");
    for (int i = 0; i < IV_LEN; i++) {
        printf("%02x", IV[i]); // In ra mỗi byte của IV dưới dạng HEX
    }
    printf("\n");

    printf("S: ");
    for (int i = 0; i < S_LEN; i++) {
        printf("%02x", S[i]); // In ra mỗi byte của S dưới dạng HEX
    }
    printf("\n");

    // In ra trạng thái S sau khi áp dụng hoán vị p
    for (int i = 0; i < 40; i++) {
        printf("%02x ", S[i]); // In ra từng byte của trạng thái S dưới dạng thập lục phân
    }
    printf("\n");
*/