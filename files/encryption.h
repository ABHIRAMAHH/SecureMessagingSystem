#ifndef ENCRYPTION_H
#define ENCRYPTION_H

void generate_keys();
char* encrypt_message(const char* message, const char* public_key_file);
char* decrypt_message(const char* encrypted_message, const char* private_key_file);

#endif // ENCRYPTION_H