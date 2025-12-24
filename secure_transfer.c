#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================= RSA IMPLEMENTATION ================= */
long long gcd(long long a, long long b) {
    return b == 0 ? a : gcd(b, a % b);
}

long long modexp(long long base, long long exp, long long mod) {
    long long result = 1;
    while (exp > 0) {
        result = (result * base) % mod;
        exp--;
    }
    return result;
}

void generate_rsa_keys(long long *e, long long *d, long long *n) {
    long long p = 61, q = 53;
    *n = p * q;
    long long phi = (p - 1) * (q - 1);

    *e = 17;
    while (gcd(*e, phi) != 1)
        (*e)++;

    *d = 1;
    while (((*d) * (*e)) % phi != 1)
        (*d)++;
}

long long rsa_encrypt(long long msg, long long e, long long n) {
    return modexp(msg, e, n);
}

long long rsa_decrypt(long long cipher, long long d, long long n) {
    return modexp(cipher, d, n);
}

/* ================= AES-LIKE ENCRYPTION ================= */
void aes_encrypt(char *data, int key) {
    for (int i = 0; data[i] != '\0'; i++) {
        data[i] = (data[i] + key + i) % 256;
    }
}

void aes_decrypt(char *data, int key) {
    for (int i = 0; data[i] != '\0'; i++) {
        data[i] = (data[i] - key - i + 256) % 256;
    }
}

/* ================= MESSAGE ENCRYPTION ================= */
void encrypt_message() {
    char msg[500];
    printf("Enter confidential message:\n");
    getchar();
    fgets(msg, sizeof(msg), stdin);

    int aes_key = 9;
    long long e, d, n;
    generate_rsa_keys(&e, &d, &n);

    long long encrypted_key = rsa_encrypt(aes_key, e, n);
    aes_encrypt(msg, aes_key);

    FILE *fp = fopen("message_enc.txt", "w");
    fprintf(fp, "%lld\n%s", encrypted_key, msg);
    fclose(fp);

    printf("\n✔ Message encrypted successfully\n");
}

void decrypt_message() {
    FILE *fp = fopen("message_enc.txt", "r");
    if (!fp) {
        printf("Encrypted message not found\n");
        return;
    }

    long long enc_key;
    char msg[500];
    fscanf(fp, "%lld\n", &enc_key);
    fgets(msg, sizeof(msg), fp);
    fclose(fp);

    long long e, d, n;
    generate_rsa_keys(&e, &d, &n);
    int aes_key = rsa_decrypt(enc_key, d, n);

    aes_decrypt(msg, aes_key);

    fp = fopen("message_dec.txt", "w");
    fprintf(fp, "%s", msg);
    fclose(fp);

    printf("\n✔ Message decrypted successfully\n");
}

/* ================= FILE ENCRYPTION ================= */
void encrypt_file() {
    FILE *in = fopen("input.txt", "r");
    FILE *out = fopen("file_enc.txt", "w");

    if (!in || !out) {
        printf("File error\n");
        return;
    }

    char data[500];
    fgets(data, sizeof(data), in);

    int aes_key = 11;
    long long e, d, n;
    generate_rsa_keys(&e, &d, &n);

    long long encrypted_key = rsa_encrypt(aes_key, e, n);
    aes_encrypt(data, aes_key);

    fprintf(out, "%lld\n%s", encrypted_key, data);

    fclose(in);
    fclose(out);

    printf("\n✔ File encrypted successfully\n");
}

void decrypt_file() {
    FILE *in = fopen("file_enc.txt", "r");
    FILE *out = fopen("file_dec.txt", "w");

    if (!in || !out) {
        printf("File error\n");
        return;
    }

    long long enc_key;
    char data[500];
    fscanf(in, "%lld\n", &enc_key);
    fgets(data, sizeof(data), in);

    long long e, d, n;
    generate_rsa_keys(&e, &d, &n);
    int aes_key = rsa_decrypt(enc_key, d, n);

    aes_decrypt(data, aes_key);
    fprintf(out, "%s", data);

    fclose(in);
    fclose(out);

    printf("\n✔ File decrypted successfully\n");
}

/* ================= MAIN APPLICATION ================= */
int main() {
    int choice;

    while (1) {
        printf("\n========================================\n");
        printf(" Secure File & Message Transfer Tool\n");
        printf(" AES / RSA Based (Advanced C Project)\n");
        printf("========================================\n");
        printf("1. Encrypt Message\n");
        printf("2. Decrypt Message\n");
        printf("3. Encrypt File\n");
        printf("4. Decrypt File\n");
        printf("5. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: encrypt_message(); break;
            case 2: decrypt_message(); break;
            case 3: encrypt_file(); break;
            case 4: decrypt_file(); break;
            case 5: exit(0);
            default: printf("Invalid choice\n");
        }
    }
}
