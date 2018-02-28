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

#if !defined (__thekogans_packet_PacketFragmentHeader_h)
#define __thekogans_packet_PacketFragmentHeader_h

#include "thekogans/util/Types.h"
#include "thekogans/util/GUID.h"
#include "thekogans/util/Constants.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct PacketFragmentHeader PacketFragmentHeader.h thekogans/packet/PacketFragmentHeader.h
        ///
        /// \brief
        /// PacketFragmentHeader frames the second type of payload supported by \see{PlaintextHeader).
        /// (the first being \see{PacketHeader}). PacketFragmentHeader contains \see{Packet} fragments
        /// for packets larger than \see{TCPFrameParser}::maxDataLength or \see{UDPFrameParser}::maxDataLength.

        struct _LIB_THEKOGANS_PACKET_DECL PacketFragmentHeader {
            /// \brief
            /// Session id (\see{util::GUID}) to which this fragment belongs.
            util::GUID sessionId;
            /// \brief
            /// \see{Packet} sequence number. Used to prevent replay attacks.
            /// Also used to match fragments to packets they belong to.
            util::ui32 sequenceNumber;
            /// \brief
            /// Fragment flags.
            util::ui16 flags;
            /// \brief
            /// Fragment index.
            util::ui16 index;
            /// \brief
            /// Fragment offset.
            util::ui32 offset;

            enum {
                /// \brief
                /// PacketFragmentHeader serialized size.
                SIZE = util::GUID_SIZE +
                    util::UI32_SIZE +
                    util::UI16_SIZE +
                    util::UI16_SIZE +
                    util::UI32_SIZE
            };

            /// \brief
            /// ctor.
            PacketFragmentHeader () :
                sessionId (util::GUID::Empty),
                sequenceNumber (0),
                flags (0),
                index (0),
                offset (0) {}
            /// \brief
            /// ctor.
            /// \param[in] sessionId_ Session id (\see{util::GUID}) to which this fragment belongs.
            /// Used to prevent replay attacks.
            /// \param[in] sequenceNumber_ \see{Packet} sequence number.
            /// Used to match fragments to packets they belong to.
            /// \param[in] flags_ Fragment flags.
            /// \param[in] index_ Fragment index.
            /// \param[in] offset_ Fragment offset.
            PacketFragmentHeader (
                const util::GUID &sessionId_,
                util::ui32 sequenceNumber_,
                util::ui16 flags_,
                util::ui16 index_,
                util::ui32 offset_) :
                sessionId (sessionId_),
                sequenceNumber (sequenceNumber_),
                flags (flags_),
                index (index_),
                offset (offset_) {}
        };

        /// \brief
        /// PacketFragmentHeader serializer.
        /// \param[in] serializer Where to serialize the packet fragment header.
        /// \param[in] packetFragmentHeader PacketFragmentHeader to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const PacketFragmentHeader &packetFragmentHeader) {
            serializer <<
                packetFragmentHeader.sessionId <<
                packetFragmentHeader.sequenceNumber <<
                packetFragmentHeader.flags <<
                packetFragmentHeader.index <<
                packetFragmentHeader.offset;
            return serializer;
        }

        /// \brief
        /// PacketFragmentHeader deserializer.
        /// \param[in] serializer Where to deserialize the packet fragment header.
        /// \param[in] packetFragmentHeader PacketFragmentHeader to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                PacketFragmentHeader &packetFragmentHeader) {
            serializer >>
                packetFragmentHeader.sessionId >>
                packetFragmentHeader.sequenceNumber >>
                packetFragmentHeader.flags >>
                packetFragmentHeader.index >>
                packetFragmentHeader.offset;
            return serializer;
        }

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PacketFragmentHeader_h)
