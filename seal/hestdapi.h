#pragma once

#include <string>

namespace seal
{
    namespace HEStdAPI
    {
        class HE_Plaintext
        {
        public:
            HE_Plaintext() = default;

            ~HE_Plaintext() = default;

            HE_Plaintext(const HE_Plaintext &copy) = default;

            HE_Plaintext(HE_Plaintext &&copy) = default;

            HE_Plaintext &operator =(const HE_Plaintext &in) = default;

            HE_Plaintext &operator =(HE_Plaintext &&in) = default;

        private:
            // Library specific data structures
        };

        class HE_Ciphertext
        {
        public:
            HE_Ciphertext() = default;

            ~HE_Ciphertext() = default;

            HE_Ciphertext(const HE_Ciphertext &copy) = default;

            HE_Ciphertext(HE_Ciphertext &&copy) = default;

            HE_Ciphertext &operator =(const HE_Ciphertext &in) = default;

            HE_Ciphertext &operator =(HE_Ciphertext &&in) = default;

            std::string get_key_id() const;

        private:
            // Library specific data structures
        };

        class HE_Context
        {
        public:
            HE_Context() = default;
/*
{
    library_id: "SEAL v2.3",
    library_descriptor: ...,
    param_id: "custom/hestd128_cyclotomic_8192_SEAL_1",
    library_dep:
        {
            plain_modulus: ...
            use_memory_pool: true
            coeff_modulus: [ 0x123451, 0x132412341 ]
        }
}
*/
            void load_profile(std::string filename);

            std::string param_id() const;

            // PKE/SKE
            std::string keygen_sk();
            bool keygen_pk(std::string key_id);
            std::string keygen_sk_pk();

            void serialize_sk_to_file(std::string key_id, std::string filename) const;
            void serialize_sk_to_str(std::string key_id, std::string &out) const;
            void deserialize_sk_from_file(std::string filename);
            void deserialize_sk_from_str(std::string in);

            void serialize_pk_to_file(std::string key_id, std::string filename) const;
            void serialize_pk_to_str(std::string key_id, std::string &out) const;
            void deserialize_pk_from_file(std::string filename);
            void deserialize_pk_from_str(std::string in);

            void serialize_ciphertext_to_file(const HE_Ciphertext &in, std::string filename) const;
            void serialize_ciphertext_to_str(const HE_Ciphertext &in, std::string &out) const;
            void deserialize_ciphertext_from_file(std::string filename, HE_Ciphertext &out) const;
            void deserialize_ciphertext_from_str(std::string in, HE_Ciphertext &out) const;
            HE_Ciphertext deserialize_ciphertext_from_file(std::string filename) const;
            HE_Ciphertext deserialize_ciphertext_from_str(std::string in) const;

            void serialize_plaintext_to_file(const HE_Plaintext &in, std::string filename) const;
            void serialize_plaintext_to_str(const HE_Plaintext &in, std::string &out) const;
            void deserialize_plaintext_from_file(std::string filename, HE_Plaintext &out) const;
            void deserialize_plaintext_from_str(std::string in, HE_Plaintext &out) const;
            HE_Plaintext deserialize_plaintext_from_file(std::string filename) const;
            HE_Plaintext deserialize_plaintext_from_str(std::string in) const;

            bool sk_loaded() const;
            bool pk_loaded() const;

            void encrypt(const HE_Plaintext &in, HE_Ciphertext &out) const;
            HE_Ciphertext encrypt(const HE_Plaintext &in) const;

            void decrypt(const HE_Ciphertext &in, HE_Plaintext &out) const;
            HE_Plaintext decrypt(const HE_Ciphertext &in) const;

            // Homomorphic operations
            void eval_add(const HE_Ciphertext &in1, const HE_Ciphertext &in2, HE_Ciphertext &out) const;
            void eval_add(const HE_Ciphertext &in1, const HE_Plaintext &in2, HE_Ciphertext &out) const;
            void eval_add(const HE_Plaintext &in1, const HE_Ciphertext &in2, HE_Ciphertext &out) const;
            HE_Ciphertext eval_add(const HE_Ciphertext &in1, const HE_Ciphertext &in2) const;
            HE_Ciphertext eval_add(const HE_Ciphertext &in1, const HE_Plaintext &in2) const;
            HE_Ciphertext eval_add(const HE_Plaintext &in1, const HE_Ciphertext &in2) const;

            void eval_sub(const HE_Ciphertext &in1, const HE_Ciphertext &in2, HE_Ciphertext &out) const;
            void eval_sub(const HE_Ciphertext &in1, const HE_Plaintext &in2, HE_Ciphertext &out) const;
            void eval_sub(const HE_Plaintext &in1, const HE_Ciphertext &in2, HE_Ciphertext &out) const;
            HE_Ciphertext eval_sub(const HE_Ciphertext &in1, const HE_Ciphertext &in2) const;
            HE_Ciphertext eval_sub(const HE_Ciphertext &in1, const HE_Plaintext &in2) const;
            HE_Ciphertext eval_sub(const HE_Plaintext &in1, const HE_Ciphertext &in2) const;

            void eval_negate(const HE_Ciphertext &in, HE_Ciphertext &out) const;
            HE_Ciphertext eval_negate(const HE_Ciphertext &in) const;

            void eval_mult(const HE_Ciphertext &in1, const HE_Ciphertext &in2, HE_Ciphertext &out) const;
            void eval_mult(const HE_Ciphertext &in1, const HE_Plaintext &in2, HE_Ciphertext &out) const;
            void eval_mult(const HE_Plaintext &in1, const HE_Ciphertext &in2, HE_Ciphertext &out) const;
            HE_Ciphertext eval_mult(const HE_Ciphertext &in1, const HE_Ciphertext &in2) const;
            HE_Ciphertext eval_mult(const HE_Ciphertext &in1, const HE_Plaintext &in2) const;
            HE_Ciphertext eval_mult(const HE_Plaintext &in1, const HE_Ciphertext &in2) const;

            void serialize_context_to_file(std::string filename) const;
            void serialize_context_to_str(std::string &out) const;
            void deserialize_context_from_file(std::string filename);
            void deserialize_context_from_str(std::string in);

        private:
            // Library specific data structures
        };
    }
}