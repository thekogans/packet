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

#if !defined (__thekogans_packet_ServerKeyExchangePacket_h)
#define __thekogans_packet_ServerKeyExchangePacket_h

#include <string>
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"
#include "thekogans/packet/Session.h"

namespace thekogans {
    namespace packet {

        /// \struct ServerKeyExchangePacket ServerKeyExchangePacket.h thekogans/packet/ServerKeyExchangePacket.h
        ///
        /// \brief
        /// ServerKeyExchangePacket packets are used by the server to complete the \see{crypto::SymmetricKey}
        /// key exchange started by the client (using (see{ClientKeyExchangePacket}). After receiving the
        /// \see{ClientKeyExchangePacket} packet from the client, the server uses it's params to create it's
        /// \see{SymmetricKey}. It sends it's \see{KeyExchange::Params} public key back to the client to complete
        /// the key exchange.
        ///
        /// The following example illustrates it's use:
        ///
        /// \code{.cpp}
        /// using namespace thekogans;
        /// \endcode

        struct _LIB_THEKOGANS_PACKET_DECL ServerKeyExchangePacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (ServerKeyExchangePacket, util::SpinLock)

            /// \brief
            /// \see{CipherSuite} used to generate the \see{KeyExchange::Params}.
            std::string cipherSuite;
            /// \brief
            /// \see{KeyExchange::Params} used for \see{SymmetricKey} exchange.
            crypto::KeyExchange::Params::Ptr params;

            /// \brief
            /// ctor.
            /// \param[in] cipherSuite_ \see{CipherSuite} used to generate the \see{KeyExchange::Params}.
            /// \param[in] params_ \see{KeyExchange::Params} used for \see{SymmetricKey} exchange.
            ServerKeyExchangePacket (
                const std::string &cipherSuite_,
                crypto::KeyExchange::Params::Ptr params_) :
                cipherSuite (cipherSuite_),
                params (params_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const {
                return
                    util::Serializer::Size (cipherSuite) +
                    util::Serializable::Size (*params);
            }

            /// \brief
            /// De-serialize the packet.
            /// \param[in] header Packet header.
            /// \param[in] serializer Packet contents.
            virtual void Read (
                const Header & /*header*/,
                util::Serializer &serializer);
            /// \brief
            /// Serialize the packet.
            /// \param[out] serializer Packet contents.
            virtual void Write (util::Serializer &serializer) const;

            /// \brief
            /// ServerKeyExchangePacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (ServerKeyExchangePacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ServerKeyExchangePacket_h)