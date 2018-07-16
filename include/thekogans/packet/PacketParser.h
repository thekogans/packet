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

#if !defined (__thekogans_packet_PacketParser_h)
#define __thekogans_packet_PacketParser_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/ID.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Session.h"
#include "thekogans/packet/Packet.h"
#include "thekogans/packet/ValueParser.h"

namespace thekogans {
    namespace packet {

        /// \struct PacketParser PacketParser.h thekogans/packet/PacketParser.h
        ///
        /// \brief
        /// PacketParser processes potentially fragmented buffers containing a packet.
        ///
        /// Once a packet is identified, it has the following format:
        ///
        /// |<------------packet------------->|
        /// +---------------+-----------------+
        /// |               |                 |
        /// | packet header |   packet data   |
        /// |               |                 |
        /// +---------------+-----------------+
        /// |      phs      | variable length |
        ///
        /// |<-------------------packet header------------------->|
        /// +-------+-----------------+---------+-----------------+
        /// |       |                 |         |                 |
        /// | magic |       id        | version |      size       |
        /// |       |                 |         |                 |
        /// +-------+-----------------+---------+-----------------+
        /// |   4   | variable length |    2    | variable length |
        ///
        /// phs = 6 + id size + size size

        struct _LIB_THEKOGANS_PACKET_DECL PacketParser {
            /// \struct PacketParser::PacketHandler PacketParser.h thekogans/packet/PacketParser.h
            ///
            /// \brief
            /// Inherit from this class to receive arriving packets.
            struct _LIB_THEKOGANS_PACKET_DECL PacketHandler {
                /// \brief
                /// dtor.
                virtual ~PacketHandler () {}

                /// \brief
                /// Called by the parser to let the handler know a packet was parsed.
                /// \param[in] packet New \see{Packet}.
                virtual void HandlePacket (Packet::Ptr /*packet*/) throw () = 0;
            };

        private:
            enum {
                /// \brief
                /// Default max \see{util::Serializable} type length.
                MAX_TYPE_LENGTH = 50,
                /// \brief
                /// Default max ciphertext length.
                DEFAULT_MAX_PACKET_SIZE = 2 * 1024 * 1024
            };
            /// \brief
            /// Max ciphertext length allows us to protect ourselves from malicious actors.
            const std::size_t maxPacketSize;
            /// \enum
            /// PacketParser is a state machine. These are it's various states.
            enum {
                /// \brief
                /// Next value is \see{util::Serializable::Header}.
                STATE_HEADER,
                /// \brief
                /// Next value is packet payload.
                STATE_PAYLOAD
            } state;
            /// \brief
            /// Incrementally parsed \see{util::Serializable::Header}.
            util::Serializable::Header header;
            /// \brief
            /// Incrementally parsed payload.
            util::Buffer payload;
            /// \brief
            /// Parses \see{util::Serializable::Header}.
            ValueParser<util::Serializable::Header> headerParser;

        public:
            /// \brief
            /// ctor.
            /// \param[in] maxPacketSize_ Max packet size.
            PacketParser (
                std::size_t maxPacketSize_ = DEFAULT_MAX_PACKET_SIZE) :
                maxPacketSize (maxPacketSize_),
                state (STATE_HEADER),
                payload (util::NetworkEndian),
                headerParser (header) {}

            /// \brief
            /// Return the max ciphertext length allowed by this parser.
            /// \return Max ciphertext length allowed by this parser.
            inline std::size_t GetMaxPacketSize () const {
                return maxPacketSize;
            }

            /// \brief
            /// Parse a buffer containing packet(s) or a packet fragment.
            /// \param[in] buffer Buffer containing a packet fragment.
            /// \param[out] packetHandler PacketHandler api is used to
            /// process incoming packets.
            void HandleBuffer (
                util::Buffer buffer,
                PacketHandler &packetHandler);

        private:
            /// \brief
            /// Reset the parser to the initial state.
            void Reset ();
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PacketParser_h)
