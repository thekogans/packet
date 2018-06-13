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

#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct ClientKeyExchangePacket ClientKeyExchangePacket.h thekogans/packet/ClientKeyExchangePacket.h
        ///
        /// \brief
        /// ClientKeyExchangePacket packets are used to initiate \see{crypto::SymmetricKey} exchange. Upon
        /// receipt, the server uses the DH/EC params to create an ephemeral private/public key pair, and
        /// uses the public key found in the packet to compute it's side of the shared secret. It then
        /// packages it's public key in the \see{ServerKeyExchangePacket} packet and sends it back to the
        /// client to complete the key exchange.
        ///
        /// The following example illustrates it's use:
        ///
        /// \code{.cpp}
        /// using namespace thekogans;
        /// crypto::Params::Ptr params =
        ///     crypto::EC::ParamsFromRFC5639Curve (
        ///         crypto::EC::RFC5639_CURVE_512);
        /// crypto::AsymmetricKey::Ptr privateKey = params->CreateKey ();
        /// keyRing.AddKeyExchangeKey (privateKey);
        /// util::LockGuard<util::SpinLock> guard (spinLock);
        /// WriteBuffer (
        ///     packet::ClientKeyExchangePacket (
        ///         params,
        ///         crypto::KeyExchange (privateKey).GetPublicKey (
        ///             privateKey->GetId ())).Serialize (
        ///                 *keyRing.GetRandomCipher (),
        ///                 &session));
        /// \endcode

        struct _LIB_THEKOGANS_PACKET_DECL ClientKeyExchangePacket : public Packet {
            /// \brief
            /// Pull in \see{Packet} dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (ClientKeyExchangePacket, util::SpinLock)

            /// \brief
            /// DH/EC parameters used to generate the public key.
            crypto::Params::Ptr params;
            /// \brief
            /// Client's DH/EC public key.
            crypto::AsymmetricKey::Ptr publicKey;

            /// \brief
            /// ctor.
            /// \param[in] params_ DH/EC parameters used to generate the public key.
            /// \param[in] publicKey_ Client's DH/EC public key.
            ClientKeyExchangePacket (
                crypto::Params::Ptr params_,
                crypto::AsymmetricKey::Ptr publicKey_) :
                params (params_),
                publicKey (publicKey_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const {
                return
                    util::Serializable::Size (*params) +
                    util::Serializable::Size (*publicKey);
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
            /// ClientKeyExchangePacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (ClientKeyExchangePacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ClientKeyExchangePacket_h)
