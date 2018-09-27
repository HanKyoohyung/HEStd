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

#include <iostream>
#include <fstream>
#include "cryptocontext.h"
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/exception.h"

namespace hestd
{
    namespace palisade = lbcrypto;

    using Ciphertext = palisade::Ciphertext<palisade::DCRTPoly>;
    using ConstCiphertext = palisade::ConstCiphertext<palisade::DCRTPoly>;
    using Plaintext = palisade::Plaintext;
    using ConstPlaintext = palisade::ConstPlaintext;

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
		
		HEStdContext(std::ifstream &stream, const string &userProfile) {

	    	palisade::Serialized	ccSer;

	    	if (palisade::SerializableHelper::StreamToSerialization(stream, &ccSer) == false) {
				PALISADE_THROW( palisade::serialize_error, "Could not read the cryptocontext file" );
			}

			m_cc = palisade::CryptoContextFactory<palisade::DCRTPoly>::DeserializeAndCreateContext(ccSer);

		}

        /**
        Generate public and secret key (depending on mode: symmetric or asymmetric)
        */
        void keyGen() {

        	// Generate a public and private key
        	m_kp = m_cc->KeyGen();

        	// Generate relinearization key(s)
        	m_cc->EvalMultKeyGen(m_kp.secretKey);

        	// Generate evalmult keys for summation
        	m_cc->EvalSumKeyGen(m_kp.secretKey);

        	m_cc->EvalAtIndexKeyGen(m_kp.secretKey,{1,2,3});

        }

        /**
        Read and write secret key.
        */
        void readSK(std::ifstream &stream);
        void writeSK(std::ofstream &stream);
        void readPK(std::ifstream &stream);
        void writePK(std::ofstream &stream);

        /**
        Read and write ciphertext.
        */
        bool readCiphertext(std::ifstream &stream, Ciphertext ctxt);
        bool writeCiphertext(ConstCiphertext ctxt, std::ofstream stream);

        /**
        Read and write plaintext.
        */
        bool readPlaintext(std::ifstream &stream, Plaintext ptxt);
        bool writePlaintext(ConstCiphertext ptxt, std::ofstream stream);

        /**
        Encryption and decryption.
        */
        void encrypt(Plaintext ptxtIn, Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->Encrypt(m_kp.publicKey,ptxtIn));
        	return;
        }

        void decrypt(ConstCiphertext ctxtIn, Plaintext &ptxtOut) {
        	m_cc->Decrypt(m_kp.secretKey,ctxtIn,&ptxtOut);
        	return;
        }

        /**
        Homomorphic computations.
        */
        void evalAdd(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut) {
        	*ctxtOut = *(m_cc->EvalAdd(ctxtIn1,ctxtIn2));
        	return;
        }

        void evalAddInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2);

        void evalAdd(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2,  Ciphertext ctxtOut);
        void evalAddInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2);

        void evalSub(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut);
        void evalSubInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2);

        void evalSub(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2, Ciphertext ctxtOut);
        void evalSubInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2);

        void evalNeg(ConstCiphertext ctxtIn,  Ciphertext ctxtOut);
        void evalNegInplace(Ciphertext ctxtIn);

        void evalMul(ConstCiphertext ctxtIn1, ConstCiphertext ctxtIn2, Ciphertext ctxtOut);
        void evalMulInplace(Ciphertext ctxtIn1, ConstCiphertext ctxtIn2);

        void evalMul(ConstCiphertext ctxtIn1, ConstPlaintext ptxtIn2,  Ciphertext ctxtOut);
        void evalMulInplace(Ciphertext ctxtIn1, ConstPlaintext ptxtIn2);


        //Special functions (temporarily added)

        Ciphertext CreateCiphertext() {
        	return Ciphertext(new palisade::CiphertextImpl<palisade::DCRTPoly>());
        }

        Plaintext CreatePlaintext() {
        	return Plaintext(new palisade::PackedEncoding( m_cc->GetElementParams(), m_cc->GetEncodingParams(), {} ) );
        }

        Plaintext CreatePlaintext(const vector<uint64_t>& value) const {
        	return m_cc->MakePackedPlaintext(value);
        }

    private:
        palisade::CryptoContext<palisade::DCRTPoly> m_cc;
        palisade::LPKeyPair<palisade::DCRTPoly> m_kp;
    };

}

#endif /* SRC_PKE_LIB_HESTD_H_ */
