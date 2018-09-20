#pragma once

#include <memory>
#include <fstream>
#include <unordered_map>
#include <utility>
#include <random>
#include <string>

// SEAL includes
#include "seal/context.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/evaluator.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"

namespace hestdapi
{
    using KeyIDType = std::uint64_t;

    class HEStdContext
    {
        friend std::shared_ptr<HEStdContext> 
		    CreateContextFromProfile(std::ifstream, std::string);

    public:
        /**
        Context class instances should be created using readContext and 
        createContextFromProfile functions.
        */
        HEStdContext() = delete;
        HEStdContext(const HEStdContext &) = delete;
        HEStdContext(HEStdContext &&) = default;
        HEStdContext &operator =(const HEStdContext &) = delete;
        HEStdContext &operator =(HEStdContext &&) = default;

        /*
        Non-standard constructor
        */
        HEStdContext(const seal::EncryptionParameters &parms) :
            context_(seal::SEALContext::Create(parms)),
            evaluator_(new seal::Evaluator{ context_ })
        {
            if (parms.scheme() != seal::scheme_type::BFV)
            {
                throw std::invalid_argument("non-standard scheme");
            }
            if (!context_->parameters_set())
            {
                throw std::invalid_argument("invalid parameters");
            }
        }

        /**
        Generate public and secret key according to configuration profile.
        */
        KeyIDType keyGen() 
        {
            seal::KeyGenerator keygen(context_);
            auto key_pair = std::make_pair(
                std::shared_ptr<seal::SecretKey>(new seal::SecretKey), 
                std::shared_ptr<seal::PublicKey>(new seal::PublicKey));
            *key_pair.first = keygen.secret_key();
            *key_pair.second = keygen.public_key();
            
            std::random_device rd;
            KeyIDType key_id = (static_cast<KeyIDType>(rd()) << 32) +
                static_cast<KeyIDType>(rd());

            if (!key_map_.emplace(key_id, key_pair).second)
            {
                throw std::runtime_error("failed to insert key");
            }
        }

        /**
        Read and write secret key.
        */
        KeyIDType readSK(std::ifstream stream)
        {
            auto key_pair = std::make_pair(
                std::shared_ptr<seal::SecretKey>(new seal::SecretKey),
                std::shared_ptr<seal::PublicKey>(nullptr));

            KeyIDType key_id;
            stream.read(reinterpret_cast<char*>(&key_id), sizeof(key_id));
            key_pair.first->load(stream);

            auto key_pair_iter = key_map_.find(key_id);
            if (key_pair_iter == key_map_.end())
            {
                if (!key_map_.emplace(key_id, key_pair).second)
                {
                    throw std::runtime_error("failed to insert key");
                }
            }
            else
            {
                throw std::runtime_error("key for this keyID is already loaded");
            }
            return key_id;
        }

        void writeSK(KeyIDType keyID, std::ofstream stream)
        {
            auto key_pair_iter = key_map_.find(keyID);
            if (key_pair_iter == key_map_.end())
            {
                throw std::invalid_argument("failed to find key");
            }
            if (!key_pair_iter->second.first)
            {
                throw std::invalid_argument("secret key does not exist for this keyID");
            }
            stream.write(reinterpret_cast<const char*>(&keyID), sizeof(keyID));
            key_pair_iter->second.first->save(stream);
        }

        KeyIDType readPK(std::ifstream stream);

        void writePK(KeyIDType keyID, std::ofstream stream)
        {
            auto key_pair_iter = key_map_.find(keyID);
            if (key_pair_iter == key_map_.end())
            {
                throw std::invalid_argument("failed to find key");
            }
            if (!key_pair_iter->second.second)
            {
                throw std::invalid_argument("public key does not exist for this keyID");
            }
            stream.write(reinterpret_cast<const char*>(&keyID), sizeof(keyID));
            key_pair_iter->second.second->save(stream);
        }

        /**
        Read and write ciphertext.
        */
        bool readCiphertext(std::ifstream stream, 
            std::shared_ptr<seal::Ciphertext> ctxt);
        bool writeCiphertext(std::shared_ptr<const seal::Ciphertext> ctxt,
            std::ofstream stream);

        /**
        Read and write plaintext.
        */
        bool readPlaintext(std::ifstream stream,
            std::shared_ptr<seal::Plaintext> ptxt);
        bool writePlaintext(std::shared_ptr<const seal::Plaintext> ptxt,
            std::ofstream stream);

        /**
        Encryption and decryption.
        */
        void encrypt(KeyIDType keyID,
            std::shared_ptr<const seal::Plaintext> ptxtIn,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void decrypt(KeyIDType keyID, 
		    std::shared_ptr<const seal::Ciphertext> ctxtIn,
            std::shared_ptr<seal::Plaintext> ptxtOut);

        /**
        Homomorphic computations.
        */
        void evalAdd(std::shared_ptr<const seal::Ciphertext> ctxtIn1,
            std::shared_ptr<const seal::Ciphertext> ctxtIn2,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void evalAdd(std::shared_ptr<const seal::Ciphertext> ctxtIn1,
            std::shared_ptr<const seal::Plaintext> ptxtIn2,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void evalSub(std::shared_ptr<const seal::Ciphertext> ctxtIn1,
            std::shared_ptr<const seal::Ciphertext> ctxtIn2,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void evalSub(std::shared_ptr<const seal::Ciphertext> ctxtIn1,
            std::shared_ptr<const seal::Plaintext> ptxtIn2,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void evalNeg(std::shared_ptr<const seal::Ciphertext> ctxtIn,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void evalMul(std::shared_ptr<const seal::Ciphertext> ctxtIn1,
            std::shared_ptr<const seal::Ciphertext> ctxtIn2,
            std::shared_ptr<seal::Ciphertext> ctxtOut);
        void evalMul(std::shared_ptr<const seal::Ciphertext> ctxtIn1,
            std::shared_ptr<const seal::Plaintext> ptxtIn2,
            std::shared_ptr<seal::Ciphertext> ctxtOut);

    private:
        std::shared_ptr<seal::SEALContext> context_{ nullptr };
        std::shared_ptr<seal::RelinKeys> relin_keys_{ nullptr };
        std::unordered_map<KeyIDType,
            std::pair<std::shared_ptr<seal::SecretKey>, 
            std::shared_ptr<seal::PublicKey> > > key_map_{};
        std::shared_ptr<seal::Evaluator> evaluator_{ nullptr };
        std::shared_ptr<seal::Encryptor> encryptor_{ nullptr };
        std::shared_ptr<seal::Decryptor> decryptor_{ nullptr };
    };
    
    std::shared_ptr<HEStdContext> 
	    CreateContextFromProfile(std::ifstream stream, std::string profileID);
}