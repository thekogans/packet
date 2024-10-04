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

#if !defined (__thekogans_packet_ClientHelloPacket_h)
#define __thekogans_packet_ClientHelloPacket_h

#include <string>
#include <thekogans/util/Serializer.h>
#include <thekogans/crypto/KeyExchange.h>
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct ClientHelloPacket ClientHelloPacket.h thekogans/packet/ClientHelloPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the client hello packet. ClientHelloPacket
        /// packets are used to exchange keys between peers. Upon receipt of the \see{PingPacket},
        /// the host initiates a TCP connection with the peer that sent it. Once connection
        /// has been successfully established, the host sends, as it's initial packet, the
        /// ClientHelloPacket packet. This packet contains this host's public key. The
        /// bootstrapping of this handshake is achieved by using the \see{Device}'s cipher,
        /// that initiated the connection, to encrypt the public key (ClientHelloPacket).
        /// Upon receipt of the ClientHelloPacket packet, the peer will attempt to match it
        /// to it's set of known \see{Device}s. Once decrypted it will compute the shared
        /// secret and send back a \see{ServerHelloPacket} containing the servers half of
        /// the shared secret. Again, that packet will be encrypted using the shared
        /// \see{Device}'s cipher. Once we get the \see{ServerHelloPacket}, we compute our
        /// end of the shared secret and from that the pre-master secret and all keying material.

        struct _LIB_THEKOGANS_PACKET_DECL ClientHelloPacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (ClientHelloPacket)

            /// \brief
            /// Host id.
            std::string hostId;
            /// \brief
            /// Client's \see{crypto::CipherSuite}.
            std::string cipherSuite;
            /// \brief
            /// Client's DH/EC public key.
            crypto::KeyExchange::Params::SharedPtr params;

            /// \brief
            /// ctor.
            /// \param[in] hostId_ Host id.
            /// \param[in] cipherSuite_ Client's \see{crypto::CipherSuite}.
            /// \param[in] params_ Client's DH/EC public key.
            ClientHelloPacket (
                const std::string &hostId_,
                const std::string &cipherSuite_,
                crypto::KeyExchange::Params::SharedPtr params_) :
                hostId (hostId_),
                cipherSuite (cipherSuite_),
                params (params_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return
                    util::Serializer::Size (hostId) +
                    util::Serializer::Size (cipherSuite) +
                    util::Serializable::Size (*params);
            }

            /// \brief
            /// Write the serializable from the given serializer.
            /// \param[in] header
            /// \param[in] serializer Serializer to read the serializable from.
            virtual void Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the serializable to the given serializer.
            /// \param[out] serializer Serializer to write the serializable to.
            virtual void Write (util::Serializer &serializer) const override;

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
            /// ClientHelloPacket is neither copy constructable nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (ClientHelloPacket)
        };

        /// \brief
        /// Implement ClientHelloPacket extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (ClientHelloPacket)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ClientHelloPacket_h)
