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

#if !defined (__thekogans_packet_ServerHelloPacket_h)
#define __thekogans_packet_ServerHelloPacket_h

#include <string>
#include <thekogans/crypto/KeyExchange.h>
#include <thekogans/packet/Packet.h>
#include <thekogans/packet/Session.h>
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct ServerHelloPacket ServerHelloPacket.h thekogans/packet/ServerHelloPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the server hello packet. ServerHelloPacket
        /// packets are used to exchange keys between connected peers. Upon receipt of
        /// the \see{ClientHelloPacket} packet, the peer computes it's side of the shared
        /// secret and returns the ServerHelloPacket containing it's public key. It's
        /// peer uses the public key in the ServerHelloPacket to compute it's end of the
        /// shared secret and thus a secure channel has been established.

        struct _LIB_THEKOGANS_PACKET_DECL ServerHelloPacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (ServerHelloPacket)

            /// \brief
            /// Host id.
            std::string hostId;
            /// \brief
            /// \see{Session} info.
            Session session;
            /// \brief
            /// \see{crypto::CipherSuite} to use.
            std::string cipherSuite;
            /// \brief
            /// Client's DH public key.
            crypto::KeyExchange::Params::SharedPtr params;

            /// \brief
            /// ctor.
            /// \param[in] hostId_ Peer host id.
            /// \param[in] session_ \see{Session} info.
            /// \param[in] cipherSuite_ \see{crypto::CipherSuite} to use.
            /// \param[in] params_ Server's DH public key.
            ServerHelloPacket (
                const std::string &hostId_,
                const Session &session_,
                const std::string &cipherSuite_,
                crypto::KeyExchange::Params::SharedPtr params_) :
                hostId (hostId_),
                session (session_),
                cipherSuite (cipherSuite_),
                params (params_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return
                    util::Serializer::Size (hostId) +
                    util::Serializer::Size (session) +
                    util::Serializer::Size (cipherSuite) +
                    params->GetSize ();
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
            /// ServerHelloPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (ServerHelloPacket)
        };

        /// \brief
        /// Implement ServerHelloPacket extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (ServerHelloPacket)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ServerHelloPacket_h)
