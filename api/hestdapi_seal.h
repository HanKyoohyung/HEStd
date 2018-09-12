#pragma once

#include <memory>
#include <fstream>

// SEAL includes
#include "seal/context.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/evaluator.h"

namespace hestdapi
{
    using KeyIDType = std::uint64_t;

    class HEStdContext
    {
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

        // Generate public and secret key
        KeyIDType keyGen();

        // Generate only secret key
        KeyIDType keyGenSK();

        // Generate public key from secret key
        void keyGenPK(KeyIDType keyID);

        // Read and write secret key
        KeyIDType readSK(std::ifstream stream);
        void writeSK(KeyIDType keyID, std::ofstream stream);
        KeyIDType readPK(std::ifstream stream);
        void writePK(KeyIDType keyID, std::ofstream stream);

        // Read and write ciphertext
        bool readCiphertext(std::ifstream stream, 
            std::shared_ptr<seal::Ciphertext> ctxt);
        bool writeCiphertext(std::shared_ptr<seal::Ciphertext> ctxt, 
            std::ofstream stream);

        // Read and write plaintext
        bool readPlaintext(std::ifstream stream,
            std::shared_ptr<seal::Plaintext> ptxt);
        bool writePlaintext(std::shared_ptr<seal::Plaintext> ptxt,
            std::ofstream stream);

        // Encryption and decryption
        void encrypt(KeyIDType keyID,
            std::shared_ptr<seal::Plaintext> ptxt_in,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void decrypt(std::shared_ptr<seal::Ciphertext> ctxt_in,
            std::shared_ptr<seal::Plaintext> ptxt_out);

        // Homomorphic computations
        void evalAdd(std::shared_ptr<seal::Ciphertext> ctxt_in1,
            std::shared_ptr<seal::Ciphertext> ctxt_in2,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void evalAdd(std::shared_ptr<seal::Ciphertext> ctxt_in1,
            std::shared_ptr<seal::Plaintext> ptxt_in2,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void evalSub(std::shared_ptr<seal::Ciphertext> ctxt_in1,
            std::shared_ptr<seal::Ciphertext> ctxt_in2,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void evalSub(std::shared_ptr<seal::Ciphertext> ctxt_in1,
            std::shared_ptr<seal::Plaintext> ptxt_in2,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void evalNeg(std::shared_ptr<seal::Ciphertext> ctxt_in,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void evalMul(std::shared_ptr<seal::Ciphertext> ctxt_in1,
            std::shared_ptr<seal::Ciphertext> ctxt_in2,
            std::shared_ptr<seal::Ciphertext> ctxt_out);
        void evalMul(std::shared_ptr<seal::Ciphertext> ctxt_in1,
            std::shared_ptr<seal::Plaintext> ptxt_in2,
            std::shared_ptr<seal::Ciphertext> ctxt_out);

    private:
        std::shared_ptr<seal::SEALContext> context_;
    };

    std::shared_ptr<Context> readContext(std::ifstream stream);
    std::shared_ptr<Context> createContextFromProfile(std::ifstream stream);
}