#include <cstring>
#include <cstddef>

extern "C" {

static char current_key = 0;

void set_key(char key) {
    current_key = key;
}

void caesar(void* src, void* dst, int len) {
    unsigned char* s = (unsigned char*)src;
    unsigned char* d = (unsigned char*)dst;
    for (int i = 0; i < len; i++)
        d[i] = s[i] ^ (unsigned char)current_key;
}

// RC4: внутреннее состояние (S, i, j) живёт только здесь — снаружи недоступно
void rc4_encrypt(const unsigned char* key_data, size_t key_len,
                 const unsigned char* src, unsigned char* dst, size_t len) {
    unsigned char S[256];
    // KSA (Key Scheduling Algorithm)
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    unsigned char j = 0;
    for (int i = 0; i < 256; i++) {
        j += S[i] + key_data[i % key_len];
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    // PRGA (Pseudo-Random Generation Algorithm)
    unsigned char ii = 0, jj = 0;
    for (size_t k = 0; k < len; k++) {
        ii++;
        jj += S[ii];
        unsigned char tmp = S[ii]; S[ii] = S[jj]; S[jj] = tmp;
        dst[k] = src[k] ^ S[(S[ii] + S[jj]) & 0xFF];
    }
    // Затираем состояние — безопасность
    memset(S, 0, sizeof(S));
}

} // extern "C"