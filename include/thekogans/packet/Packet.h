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

#if !defined (__thekogans_packet_Packet_h)
#define __thekogans_packet_Packet_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Session.h"
#include "thekogans/packet/PlaintextHeader.h"

namespace thekogans {
    namespace packet {

        /// \struct Packet Packet.h thekogans/packet/Packet.h
        ///
        /// \brief
        /// Packet extends \see{util::Serializable} to add application level
        /// secure transport. Please consult \see{FrameParser} to learn about
        /// Packet wire structure.

        struct _LIB_THEKOGANS_PACKET_DECL Packet : public util::Serializable {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Packet>.
            typedef util::RefCounted::SharedPtr<Packet> SharedPtr;

            /// \brief
            /// See \see{FrameParser} to learn about the wire structure created
            /// by this method.
            /// \param[in] cipher \see{crypto::Cipher} used to encrypt the packet payload.
            /// \param[in] session Optional \see{Session} whose header will be baked in
            /// to the serialized packet to help prevent replay attacks.
            /// \param[in] compress true == Compress the packet contents before encrypting.
            util::Buffer Serialize (
                crypto::Cipher &cipher,
                Session *session,
                bool compress = false) const;

            /// \brief
            /// This method is not quite a mirror image of Serialize above. That is
            /// to say you can't take Serialize's output and feed it to this method.
            /// The reason is you need to first extract the leading \see{FrameHeader}
            /// to know which \see{crypto::Cipher} to use to decrypt it.
            /// \param[in] ciphertext Serialized packet minus the leading \see{FrameHeader}.
            /// \param[in] cipher \see{crypto::Cipher} corresponding to the \see{FrameHeader::keyId}
            /// used to encrypt the payload.
            /// \param[in] session Optional \see{Session} to validate the baked in \see{Session::Header}.
            static SharedPtr Deserialize (
                util::Buffer &ciphertext,
                crypto::Cipher &cipher,
                Session *session);

            /// \brief
            /// Return the maximum framing overhead needed by Serialize above.
            /// \param[in] type \see{Packet} type being framed.
            /// \return Maximum framing overhead needed by Serialize above.
            static std::size_t GetMaxFramingOverhead (
                    const char *type,
                    std::size_t maxPacketSize) {
                return crypto::Cipher::MAX_FRAMING_OVERHEAD_LENGTH +
                    PlaintextHeader::SIZE +
                    PlaintextHeader::MAX_RANDOM_LENGTH +
                    Session::Header::SIZE +
                    util::Serializable::BinHeader (type, 0, maxPacketSize).Size ();
            }
        };

        /// \brief
        /// Implement Packet::Ptr extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_EXTRACTION_OPERATORS (Packet)

    } // namespace packet

    namespace util {

        /// \brief
        /// Implement Packet::Ptr value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_VALUE_PARSER (packet::Packet)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_packet_Packet_h)
