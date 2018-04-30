#pragma once

#include <string>
#include <memory>

#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"

namespace seal
{
    namespace HEStdAPI
    {
        class Plaintext
        {
        public:
            Plaintext() = default;

            ~Plaintext() = default;

            Plaintext(const Plaintext &copy) = default;

            Plaintext(Plaintext &&copy) = default;

            Plaintext &operator =(const Plaintext &in) = default;

            Plaintext &operator =(Plaintext &&in) = default;

        private:
            std::unique_ptr<seal::Plaintext> plaintext_;
        };

        class Ciphertext
        {
        public:
            Ciphertext() = default;

            ~Ciphertext() = default;

            Ciphertext(const Ciphertext &copy) = default;

            Ciphertext(Ciphertext &&copy) = default;

            Ciphertext &operator =(const Ciphertext &in) = default;

            Ciphertext &operator =(Ciphertext &&in) = default;

            std::string get_key_id() const;

        private:
            std::unique_ptr<seal::Ciphertext> ciphertext_;
        };

        class HEContext
        {
        public:
            HEContext() = default;

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
            void serialize_pk_to_file(std::string key_id, std::string filename) const;
            void serialize_sk_to_str(std::string key_id, std::string &out) const;
            void serialize_pk_to_str(std::string key_id, std::string &out) const;
            void deserialize_sk_from_file(std::string filename);
            void deserialize_pk_from_file(std::string filename);
            void deserialize_sk_from_str(std::string in);
            void deserialize_pk_from_str(std::string in);

            bool sk_loaded() const;
            bool pk_loaded() const;

            void encrypt(const Plaintext &in, Ciphertext &out) const;
            Ciphertext encrypt(const Plaintext &in) const;

            void decrypt(const Ciphertext &in, Plaintext &out) const;
            Plaintext decrypt(const Ciphertext &in) const;

            // Homomorphic operations
            bool keygen_multk(std::string key_id);

            void serialize_multk_to_file(std::string filename) const;
            void serialize_multk_to_str(std::string &out) const;
            void deserialize_multk_from_file(std::string filename);
            void deserialize_multk_from_str(std::string in);

            void eval_add(const Ciphertext &in1, const Ciphertext &in2, Ciphertext &out) const;
            void eval_add(const Ciphertext &in1, const Plaintext &in2, Ciphertext &out) const;
            void eval_add(const Plaintext &in1, const Ciphertext &in2, Ciphertext &out) const;
            Ciphertext eval_add(const Ciphertext &in1, const Ciphertext &in2) const;
            Ciphertext eval_add(const Ciphertext &in1, const Plaintext &in2) const;
            Ciphertext eval_add(const Plaintext &in1, const Ciphertext &in2) const;

            void eval_sub(const Ciphertext &in1, const Ciphertext &in2, Ciphertext &out) const;
            void eval_sub(const Ciphertext &in1, const Plaintext &in2, Ciphertext &out) const;
            void eval_sub(const Plaintext &in1, const Ciphertext &in2, Ciphertext &out) const;
            Ciphertext eval_sub(const Ciphertext &in1, const Ciphertext &in2) const;
            Ciphertext eval_sub(const Ciphertext &in1, const Plaintext &in2) const;
            Ciphertext eval_sub(const Plaintext &in1, const Ciphertext &in2) const;

            void eval_negate(const Ciphertext &in, Ciphertext &out) const;
            Ciphertext eval_negate(const Ciphertext &in) const;

            void eval_mult(const Ciphertext &in1, const Ciphertext &in2, Ciphertext &out) const;
            void eval_mult(const Ciphertext &in1, const Plaintext &in2, Ciphertext &out) const;
            void eval_mult(const Plaintext &in1, const Ciphertext &in2, Ciphertext &out) const;
            Ciphertext eval_mult(const Ciphertext &in1, const Ciphertext &in2) const;
            Ciphertext eval_mult(const Ciphertext &in1, const Plaintext &in2) const;
            Ciphertext eval_mult(const Plaintext &in1, const Ciphertext &in2) const;

        private:
            std::unique_ptr<EncryptionParameters> parms_;

            std::unique_ptr<SEALContext> context_;

            std::unique_ptr<KeyGenerator> keygen_;

            std::unique_ptr<SecretKey> secret_key_;

            std::unique_ptr<PublicKey> public_key_;

            std::unique_ptr<Encryptor> encryptor_;
        };
    }
}