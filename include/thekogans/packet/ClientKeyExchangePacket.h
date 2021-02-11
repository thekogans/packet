// Copyright 2016 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_packet.
//
// libthekogans_packet is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_packet is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_packet. If not, see <http://www.gnu.org/licenses/>.

#if !defined (__thekogans_packet_ClientKeyExchangePacket_h)
#define __thekogans_packet_ClientKeyExchangePacket_h

#include <string>
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct ClientKeyExchangePacket ClientKeyExchangePacket.h thekogans/packet/ClientKeyExchangePacket.h
        ///
        /// \brief
        /// ClientKeyExchangePacket packets are used to initiate \see{crypto::SymmetricKey} exchange. Upon
        /// receipt, the server uses the enclosed \see{CipherSuite} and \see{KeyExchange::Params} to create
        /// it's side of the shared secret. It then packages it's \see{KeyExchange::Params} in the
        /// \see{ServerKeyExchangePacket} packet and sends it back to the client to complete the key exchange.
        ///
        /// The following example illustrates it's use:
        ///
        /// \code{.cpp}
        /// using namespace thekogans;
        /// \endcode

        struct _LIB_THEKOGANS_PACKET_DECL ClientKeyExchangePacket : public Packet {
            /// \brief
            /// Pull in \see{Packet} dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (ClientKeyExchangePacket, util::SpinLock)

            /// \brief
            /// \see{CipherSuite} used to generate the \see{KeyExchange::Params}.
            std::string cipherSuite;
            /// \brief
            /// \see{KeyExchange::Params} used for \see{SymmetricKey} exchange.
            crypto::KeyExchange::Params::SharedPtr params;

            /// \brief
            /// ctor.
            /// \param[in] cipherSuite_ \see{CipherSuite} used to generate the \see{KeyExchange::Params}.
            /// \param[in] params_ \see{KeyExchange::Params} used for \see{SymmetricKey} exchange.
            ClientKeyExchangePacket (
                const std::string &cipherSuite_,
                crypto::KeyExchange::Params::SharedPtr params_) :
                cipherSuite (cipherSuite_),
                params (params_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return
                    util::Serializer::Size (cipherSuite) +
                    util::Serializable::Size (*params);
            }

            /// \brief
            /// De-serialize the packet.
            /// \param[in] header Packet header.
            /// \param[in] serializer Packet contents.
            virtual void Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) override;
            /// \brief
            /// Serialize the packet.
            /// \param[out] serializer Packet contents.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// "CipherSuite"
            static const char * const ATTR_CIPHER_SUITE;
            /// \brief
            /// "Params"
            static const char * const TAG_PARAMS;

            /// \brief
            /// Read a Serializable from an XML DOM.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write a Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const override;

            /// \brief
            /// ClientKeyExchangePacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (ClientKeyExchangePacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ClientKeyExchangePacket_h)
