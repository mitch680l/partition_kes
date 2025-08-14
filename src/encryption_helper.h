int open_persistent_key();

int decrypt_config_field_data(const char *encrypted_data, size_t encrypted_len,
                              const char *iv,
                              const char *additional_data, size_t additional_len,
                              char *output_buf, size_t *output_len);
int encrypt_config_field_data(const char *plaintext_data, size_t plaintext_len,
                              char *iv_out,
                              const char *additional_data, size_t additional_len,
                              char *encrypted_out, size_t *encrypted_len);
int create_encrypted_entry_with_aad(const char *plaintext_aad, const char *plaintext, uint8_t *entry_buf);