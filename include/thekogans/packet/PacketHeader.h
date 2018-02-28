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

#if !defined (__thekogans_packet_PacketHeader_h)
#define __thekogans_packet_PacketHeader_h

#include "thekogans/util/Types.h"
#include "thekogans/util/GUID.h"
#include "thekogans/util/Flags.h"
#include "thekogans/util/Constants.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct PacketHeader PacketHeader.h thekogans/packet/PacketHeader.h
        ///
        /// \brief
        /// PacketHeader frames one of the two types of payload supported by the \see{PlaintextHeader}.
        /// \see{PacketHeader} contains either the entire packet (if it's smaller than
        /// \see{TCPFrameParser}::maxDataLength or \see{UDPFrameParser}::maxDataLength)
        /// or the first chunk of a \see{Packet} followed by \see{PacketFragmentHeader}
        /// payloads.

        struct _LIB_THEKOGANS_PACKET_DECL PacketHeader {
            /// \brief
            /// Session id (\see{util::GUID}) to which this packet belongs.
            util::GUID sessionId;
            /// \brief
            /// \see{Packet} sequence number. Used to prevent replay attacks.
            util::ui32 sequenceNumber;
            /// \brief
            /// \see{Packet} id.
            util::ui16 id;
            /// \brief
            /// \see{Packet} version.
            util::ui16 version;
            /// \enum
            /// Payload flags.
            enum {
                /// \brief
                /// \see{Packet} is compressed.
                FLAGS_COMPRESSED = 1
            };
            /// \brief
            /// Payload flags.
            util::ui16 flags;
            /// \brief
            /// Number of frames that make up this packet.
            util::ui16 fragmentCount;
            /// \brief
            /// Total length of \see{Packet} data.
            util::ui32 length;

            enum {
                /// \brief
                /// PacketHeader serialized size.
                SIZE = util::GUID_SIZE +
                    util::UI32_SIZE +
                    util::UI16_SIZE +
                    util::UI16_SIZE +
                    util::UI16_SIZE +
                    util::UI16_SIZE +
                    util::UI32_SIZE
            };

            /// \brief
            /// ctor.
            PacketHeader () :
                sessionId (util::GUID::Empty),
                sequenceNumber (0),
                id (0),
                version (0),
                flags (0),
                fragmentCount (0),
                length (0) {}

            /// \brief
            /// ctor.
            /// \param[in] sessionId_ Session id (\see{util::GUID}) to which this packet belongs.
            /// Used to prevent replay attacks.
            /// \param[in] sequenceNumber_ \see{Packet} sequence number.
            /// \param[in] id_ \see{Packet} id.
            /// \param[in] version_ \see{Packet} version.
            /// \param[in] flags_ \see{Packet} flags.
            /// \param[in] fragmentCount_ Number of frames that make up this packet.
            /// \param[in] length_ Total length of \see{Packet} data.
            PacketHeader (
                const util::GUID &sessionId_,
                util::ui32 sequenceNumber_,
                util::ui16 id_,
                util::ui16 version_,
                util::ui16 flags_,
                util::ui16 fragmentCount_,
                util::ui32 length_) :
                sessionId (sessionId_),
                sequenceNumber (sequenceNumber_),
                id (id_),
                version (version_),
                flags (flags_),
                fragmentCount (fragmentCount_),
                length (length_) {}

            /// \brief
            /// Return true if \see{Packet} is compressed.
            /// \return true if \see{Packet} is compressed.
            inline bool IsCompressed () const {
                return util::Flags16 (flags).Test (FLAGS_COMPRESSED);
            }
        };

        /// \brief
        /// PacketHeader serializer.
        /// \param[in] serializer Where to serialize the packet header.
        /// \param[in] packetHeader PacketHeader to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const PacketHeader &packetHeader) {
            serializer <<
                packetHeader.sessionId <<
                packetHeader.sequenceNumber <<
                packetHeader.id <<
                packetHeader.version <<
                packetHeader.flags <<
                packetHeader.fragmentCount <<
                packetHeader.length;
            return serializer;
        }

        /// \brief
        /// PacketHeader deserializer.
        /// \param[in] serializer Where to deserialize the packet header.
        /// \param[in] packetHeader PacketHeader to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                PacketHeader &packetHeader) {
            serializer >>
                packetHeader.sessionId >>
                packetHeader.sequenceNumber >>
                packetHeader.id >>
                packetHeader.version >>
                packetHeader.flags >>
                packetHeader.fragmentCount >>
                packetHeader.length;
            return serializer;
        }

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PacketHeader_h)
