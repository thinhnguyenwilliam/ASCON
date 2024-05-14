#include <stdint.h>

#define KEY_LEN 16U             // Length of key is 128 bits (16 bytes)
#define NONCE_LEN 16U           // Length of nonce is 128 bits (16 bytes)
#define IV_LEN 8U               // Length of IV is 320-128*2 = 64 bits (8 bytes)
#define S_LEN 40U               // Length of State is 320 bits (40 bytes)
#define REG_SIZE 8U             // Size of Register is 64 bits (8 bytes) (320/5 = 64 bits)
#define TAG_LEN 16U

const uint64_t round_constants[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};
const uint8_t s_box[32] = {0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2, 0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c,
                            0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18, 0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17};



void Init_IV(uint8_t *IV, uint8_t k, uint8_t r, uint8_t a, uint8_t b) {
    // Create a IV with k, r, a and b
    if (k == 128 && r == 12 && a == 8 && b == 6) {
        // IV for Ascon-128
        memset(IV, 0x00, IV_LEN);
        IV[0] = 0x80;
        IV[1] = 0x40;
        IV[2] = 0x0c;
        IV[3] = 0x06;
    } else if (k == 128 && r == 12 && a == 8 && b == 8) {
        // IV for Ascon-128a
        memset(IV, 0x00, IV_LEN);
        IV[0] = 0x80;
        IV[1] = 0x80;
        IV[2] = 0x0c;
        IV[3] = 0x08;
    } else if (k == 80) {
        // IV for Ascon-80pq
        memset(IV, 0x00, IV_LEN);
        IV[0] = 0xa0;
        IV[1] = 0x40;
        IV[2] = 0x0c;
        IV[3] = 0x06;
    } else {
        printf("Unsupported parameters for IV.\n");
    }
}

void Init_S(uint8_t *S, uint8_t *IV, const uint8_t *Key, const uint8_t *Nonce) {
    // S = IV || K || N
    memcpy(S, IV, IV_LEN);
    memcpy(S + IV_LEN, Key, KEY_LEN);
    memcpy(S + IV_LEN + KEY_LEN, Nonce, IV_LEN);
}

// Hàm pC - Addition of Constants
void pC(uint64_t* x2, const uint64_t round_constant) {
    *x2 ^= round_constant;
}

// Hàm pS - Substitution Layer
void pS(uint8_t *S) {
    for (int i = 0; i < S_LEN; i++) {
        S[i] = s_box[S[i]]; // Áp dụng S-box cho mỗi bit-slice
    }
}

// Hàm tuyến tính cho diffusion layer
uint64_t linear_function(uint64_t x, int i) {
    switch (i)
    {
    case 0:
        return x ^ (x >> 19) ^ (x >> 28);
        break;
    case 1:
        return x ^ (x >> 61) ^ (x >> 39);
        break;
    case 2:
        return x ^ (x >> 1) ^ (x >> 6);
        break;
    case 3:
        return x ^ (x >> 10) ^ (x >> 17);
        break;
    case 4:
        return x ^ (x >> 7) ^ (x >> 41);
        break;
    default:
        break;
    }
}

// Hàm pL - Linear Diffusion Layer
void pL(uint8_t *S) {
    for (int i = 0; i < 5; i++) {
        uint64_t *xi = (uint64_t *)(S + i * REG_SIZE); // Lấy địa chỉ của từ xi
        *xi = linear_function(*xi, i); // Áp dụng hàm tuyến tính cho từ xi
    }
}

// Hàm hoán vị permutation
void permutation(uint8_t *S, const int num_rounds) {
    for (int i = 0; i < num_rounds; i++) {
        // Bước pC - thêm hằng số vòng vào từ x2
        pC((uint64_t *)(S + 2 * REG_SIZE), round_constants[i]);
        
        // Bước pS - cập nhật trạng thái với S-box
        pS(S);
        
        // Bước pL - cung cấp sự phân tán tuyến tính cho mỗi từ xi
        pL(S);
    }
}

// Hàm để thêm phần đuôi cho dữ liệu kết nối A
void pad_associated_data(const uint8_t *A, int A_length, uint8_t *padded_A, int block_size) {
    int padding_length = block_size - (A_length % block_size);
    memcpy(padded_A, A, A_length); // Sao chép dữ liệu gốc vào padded_A
    padded_A[A_length] = 0x80; // Gắn bit 1 vào vị trí kế cuối của dữ liệu gốc
    memset(padded_A + A_length + 1, 0, padding_length - 1); // Đặt các bit còn lại thành 0
}

// Hàm xử lý dữ liệu kết nối
void process_associated_data(uint8_t *S, const uint8_t *A, int A_length, int num_rounds, int block_size) {
    
    int Padded_A_LEN = (A_length + (block_size - (A_length % block_size)));
    uint8_t padded_A[Padded_A_LEN];

    if(A_length > 0){
        pad_associated_data(A, A_length, padded_A, block_size);
    }
    
    int num_blocks = (A_length > 0) ? (A_length + block_size - 1) / block_size : 0;
    
    // Xử lý từng khối dữ liệu
    for (size_t i = 0; i < num_blocks; i++) {
        // Lấy khối dữ liệu thứ i từ padded_A
        const uint8_t *Ai = (A_length > 0) ? (padded_A + i * block_size) : NULL;

        // XOR khối dữ liệu Ai với r byte đầu của trạng thái S
        for (int j = 0; j < block_size; j++) {
            S[j] ^= Ai[j];
        }

        // Áp dụng hoán vị pb lên trạng thái S
        permutation(S, num_rounds);
    }
    
    // XOR với hằng số domain separation
    S[S_LEN - 1] ^= 0x01; // Bit 0 đặc biệt domain separation
}

// Hàm để tính độ dài của ciphertext
size_t calculate_ciphertext_length(size_t plaintext_length, size_t block_size) {
    size_t num_blocks = (plaintext_length + block_size - 1) / block_size;
    size_t last_block_length = plaintext_length % block_size;
    return (num_blocks - 1) * block_size + last_block_length;
}

// Hàm mã hóa plaintext thành ciphertext
void encrypt_plaintext(uint8_t *S, const uint8_t *P, size_t P_length, uint8_t *C, int num_rounds, int block_size) {
    // Số lượng khối dữ liệu plaintext
    size_t num_blocks = (P_length + block_size - 1) / block_size;

    // Khởi tạo biến lưu trữ độ dài của ciphertext
    size_t ciphertext_length = calculate_ciphertext_length(P_length, block_size);

    // Xử lý từng khối dữ liệu
    for (size_t i = 0; i < num_blocks; i++) {
        // Lấy khối dữ liệu thứ i từ P
        const uint8_t *Pi = P + i * block_size;

        // XOR khối dữ liệu Pi với r byte đầu của trạng thái S
        size_t block_len = (i < num_blocks - 1) ? block_size : (P_length % block_size);
        for (size_t j = 0; j < block_len; j++) {
            S[j] ^= Pi[j];
        }

        // Lấy r-bit đầu tiên của trạng thái S để tạo thành ciphertext
        memcpy(C + i * block_size, S, block_size);

        // Áp dụng hoán vị pb lên trạng thái S
        if(i < num_blocks - 1){
            permutation(S, num_rounds);
        }
    }

    // Truncate last ciphertext block if necessary
    if (ciphertext_length > P_length) {
        size_t last_block_length = P_length % block_size;
        C[ciphertext_length] &= (0xFF >> (block_size - last_block_length));
    }
}

// Hàm để tạo tag cho plaintext và key đã mã hóa
void Init_tag(uint8_t *S, const uint8_t *Key, uint8_t *tag, int num_rounds, int r) {
    // XOR internal state với key 0^r||K||0^(360-r-k)
    for (size_t i = r; i < (KEY_LEN + r); i++) {
        S[i] ^= Key[i];
    }

    // Áp dụng hoán vị pa lên trạng thái S
    permutation(S, num_rounds);

    //XOR S and Key
    for (size_t i = S_LEN - TAG_LEN; i < S_LEN; i++) {
        S[i] ^= Key[i];
    }

    // Sao chép 128 bits cuối cùng của trạng thái S vào tag
    memcpy(tag, S + S_LEN - TAG_LEN, TAG_LEN);
}

// Hàm để xác minh tag của plaintext đã mã hóa
int verify_tag(uint8_t *S, const uint8_t *Key, const uint8_t *received_tag, int num_rounds, int r) {
    uint8_t calculated_tag[TAG_LEN];

    // Tạo tag từ trạng thái S và key K
    Init_tag(S, Key, calculated_tag, num_rounds, r);

    // So sánh calculated_tag với received_tag
    return memcmp(calculated_tag, received_tag, TAG_LEN) == 0;
}

