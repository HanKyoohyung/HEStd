/**
 * @file hestd.h -- HomomorphicEncryption.org API implementation
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2018, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SRC_PKE_LIB_HESTD_H_
#define SRC_PKE_LIB_HESTD_H_

#include "cryptocontext.h"

namespace hestdapi
{
    using KeyIDType = string;
    using ConstKeyIDType = const string &;
    namespace palisade = lbcrypto;

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

        //Write context
        bool writeContext(std::ofstream stream);

        //Write configuration profile
        bool writeProfile(std::ofstream stream);

        /**
        Generate public and secret key.
        */
        KeyIDType keyGen();

        /**
        Generate only secret key.
        */
        KeyIDType keyGenSK();

        /**
        Generate public key from secret key and potentially also
        evaluation keys.
        */
        void keyGenPK(ConstKeyIDType keyID);

        /**
        Read and write secret key.
        */
        KeyIDType readSK(std::ifstream stream);
        void writeSK(ConstKeyIDType  keyID, std::ofstream stream);
        KeyIDType readPK(std::ifstream stream);
        void writePK(ConstKeyIDType  keyID, std::ofstream stream);

        /**
        Read and write ciphertext.
        */
        bool readCiphertext(std::ifstream stream, palisade::Ciphertext ctxt);
        bool writeCiphertext(palisade::ConstCiphertext ctxt, std::ofstream stream);

        /**
        Read and write plaintext.
        */
        bool readPlaintext(std::ifstream stream, palisade::Plaintext ptxt);
        bool writePlaintext(palisade::ConstCiphertext ptxt, std::ofstream stream);

        /**
        Encryption and decryption.
        */
        void encrypt(ConstKeyIDType keyID, palisade::ConstPlaintext ptxtIn, palisade::Ciphertext ctxtOut);
        void decrypt(palisade::ConstCiphertext ctxtIn, palisade::Plaintext ptxtOut);

        /**
        Homomorphic computations.
        */
        void evalAdd(palisade::ConstCiphertext ctxtIn1, palisade::ConstCiphertext ctxtIn2, palisade::Ciphertext ctxtOut);
        void evalAddEq(palisade::Ciphertext ctxtIn1, palisade::ConstCiphertext ctxtIn2);

        void evalAdd(palisade::ConstCiphertext ctxtIn1, palisade::ConstPlaintext ptxtIn2,  palisade::Ciphertext ctxtOut);
        void evalAddEq(palisade::Ciphertext ctxtIn1, palisade::ConstPlaintext ptxtIn2);

        void evalSub(palisade::ConstCiphertext ctxtIn1, palisade::ConstCiphertext ctxtIn2, palisade::Ciphertext ctxtOut);
        void evalSubEq(palisade::Ciphertext ctxtIn1, palisade::ConstCiphertext ctxtIn2);

        void evalSub(palisade::ConstCiphertext ctxtIn1, palisade::ConstPlaintext ptxtIn2, palisade::Ciphertext ctxtOut);
        void evalSubEq(palisade::Ciphertext ctxtIn1, palisade::ConstPlaintext ptxtIn2);

        void evalNeg(palisade::ConstCiphertext ctxtIn,  palisade::Ciphertext ctxtOut);
        void evalNegEq(palisade::Ciphertext ctxtIn);

        void evalMul(palisade::ConstCiphertext ctxtIn1, palisade::ConstCiphertext ctxtIn2, palisade::Ciphertext ctxtOut);
        void evalMulEq(palisade::Ciphertext ctxtIn1, palisade::ConstCiphertext ctxtIn2);

        void evalMul(palisade::ConstCiphertext ctxtIn1, palisade::ConstPlaintext ptxtIn2,  palisade::Ciphertext ctxtOut);
        void evalMulEq(palisade::Ciphertext ctxtIn1, palisade::ConstPlaintext ptxtIn2);

    private:
        palisade::CryptoContext m_cc;
    };

    std::shared_ptr<HEStdContext> readContext(std::ifstream stream);
    std::shared_ptr<HEStdContext> createContextFromProfile(std::ifstream stream);

}

#endif /* SRC_PKE_LIB_HESTD_H_ */
