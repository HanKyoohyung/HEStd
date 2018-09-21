#pragma once

#include <memory>
#include <fstream>
#include <utility>
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

namespace hestd
{
    class HEStdContext
    {
    public:
        using Plaintext = std::shared_ptr<seal::Plaintext>;
        using Ciphertext = std::shared_ptr<seal::Ciphertext>;
        using ConstPlaintext = const std::shared_ptr<const seal::Plaintext>;
        using ConstCiphertext = const std::shared_ptr<const seal::Ciphertext>;

        /**
        Creating a context from configuration profile
        */
        HEStdContext(std::ifstream &stream, std::string profile_id);

        HEStdContext(const HEStdContext &) = delete;
        HEStdContext(HEStdContext &&) = default;
        HEStdContext &operator =(const HEStdContext &) = delete;
        HEStdContext &operator =(HEStdContext &&) = default;

        /*
        Non-standard constructor
        */
        HEStdContext(const seal::EncryptionParameters &parms) :
            context_(seal::SEALContext::Create(parms)),
            evaluator_(new seal::Evaluator(context_))
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
        void keyGen()
        {
            seal::KeyGenerator keygen(context_);
            sk_.reset(new seal::SecretKey);
            pk_.reset(new seal::PublicKey);
            *sk_ = keygen.secret_key();
            *pk_ = keygen.public_key();
            encryptor_.reset(new seal::Encryptor(context_, *pk_));
            decryptor_.reset(new seal::Decryptor(context_, *sk_));
        }

        /**
        Read and write secret key.
        */
        void readSK(std::ifstream &stream)
        {
            sk_->load(stream);
            decryptor_.reset(new seal::Decryptor(context_, *sk_));
        }

        void writeSK(std::ofstream &stream)
        {
            sk_->save(stream);
        }

        void readPK(std::ifstream &stream)
        {
            pk_->load(stream);
            encryptor_.reset(new seal::Encryptor(context_, *pk_));
        }

        void writePK(std::ofstream &stream)
        {
            pk_->save(stream);
        }

        /**
        Read and write ciphertext.
        */
        void readCiphertext(std::ifstream &stream, Ciphertext ctxt)
        {
            ctxt->load(stream);
        }

        void writeCiphertext(ConstCiphertext ctxt, std::ofstream &stream)
        {
            ctxt->save(stream);
        }

        /**
        Read and write plaintext.
        */
        void readPlaintext(std::ifstream &stream, Plaintext ptxt)
        {
            ptxt->load(stream);
        }

        void writePlaintext(ConstPlaintext ptxt, std::ofstream stream)
        {
            ptxt->save(stream);
        }

        /**
        Encryption and decryption.
        */
        void encrypt(ConstPlaintext ptxtIn, Ciphertext ctxtOut)
        {
            encryptor_->encrypt(*ptxtIn, *ctxtOut);
        }

        void decrypt(ConstCiphertext ctxtIn, Plaintext ptxtOut)
        {
            decryptor_->decrypt(*ctxtIn, *ptxtOut);
        }

        /**
        Homomorphic computations.
        */
        void evalAdd(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->add(*ctxtIn1, *ctxtIn2, *ctxtOut);
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2)
        {
            evaluator_->add(*ctxtIn1, *ctxtIn2);
        }

        void evalAdd(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->add_plain(*ctxtIn1, *ptxtIn2, *ctxtOut);
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2)
        {
            evaluator_->add_plain(*ctxtIn1, *ptxtIn2);
        }

        void evalSub(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->sub(*ctxtIn1, *ctxtIn2, *ctxtOut);
        }

        void evalSubInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2)
        {
            evaluator_->sub(*ctxtIn1, *ctxtIn2);
        }

        void evalSub(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->sub_plain(*ctxtIn1, *ptxtIn2, *ctxtOut);

        }

        void evalSubInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2)
        {
            evaluator_->sub_plain(*ctxtIn1, *ptxtIn2);
        }

        void evalNeg(ConstCiphertext ctxtIn, Ciphertext ctxtOut)
        {
            evaluator_->negate(*ctxtIn, *ctxtOut);
        }

        void evalNegInplace(Ciphertext ctxtIn)
        {
            evaluator_->negate(*ctxtIn);
        }

        void evalMul(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->multiply(*ctxtIn1, *ctxtIn2, *ctxtOut);

        }

        void evalMulInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2)
        {
            evaluator_->multiply(*ctxtIn1, *ctxtIn2);
        }

        void evalMul(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut)
        {
            evaluator_->multiply_plain(*ctxtIn1, *ptxtIn2, *ctxtOut);
        }

        void evalMulInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2)
        {
            evaluator_->multiply_plain(*ctxtIn1, *ptxtIn2);
        }

    private:
        std::shared_ptr<seal::SEALContext> context_{ nullptr };
        std::shared_ptr<seal::RelinKeys> rlk_{ nullptr };
        std::shared_ptr<seal::SecretKey> sk_{ nullptr };
        std::shared_ptr<seal::PublicKey> pk_{ nullptr };
        std::shared_ptr<seal::Evaluator> evaluator_{ nullptr };
        std::shared_ptr<seal::Encryptor> encryptor_{ nullptr };
        std::shared_ptr<seal::Decryptor> decryptor_{ nullptr };
    };
}