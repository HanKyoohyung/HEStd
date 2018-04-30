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

            void keygen_sk();
            void keygen_sk_pk();

            void serialize_sk_to_file(std::string filename) const;
            void serialize_pk_to_file(std::string filename) const;
            void serialize_sk_to_str(std::string &out) const;
            void serialize_pk_to_str(std::string &out) const;
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