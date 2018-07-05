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

#if !defined (__thekogans_packet_FrameParser_h)
#define __thekogans_packet_FrameParser_h

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

        /// \struct FrameParser FrameParser.h thekogans/packet/FrameParser.h
        ///
        /// \brief
        /// FrameParser processes potentially fragmented buffers containing a framed packet.
        ///
        /// A \see{Packet} on the wire (aka frame) has the following format:
        ///
        /// |<----------------------frame----------------------->|
        /// |<-----------plaintext------------>|<--ciphertext--->|
        /// +--------------+-------------------+-----------------+
        /// |              |                   |                 |
        /// | frame header | ciphertext header |     payload     |
        /// |              |                   |                 |
        /// +--------------+-------------------+-----------------+
        /// |     fhs      |        chs        | variable length |
        ///
        /// |<-------frame header------->|
        /// +--------+-------------------+
        /// |        |                   |
        /// | key id | ciphertext length |
        /// |        |                   |
        /// +--------+-------------------+
        /// |   32   |         4         |
        ///
        /// fhs = 36;
        ///
        /// |<------------ciphertext header------------->|
        /// +-----------+-------------------+------------+
        /// |           |                   |            |
        /// | iv length | ciphertext length | mac length |
        /// |           |                   |            |
        /// +-----------+-------------------+------------+
        /// |     2     |         4         |     2      |
        ///
        /// chs = 8
        ///
        /// |<-----------------------payload---------------------->|
        /// +-----------------+------------------+-----------------+
        /// |                 |                  |                 |
        /// |       iv        |    ciphertext    |       mac       |
        /// |                 |                  |                 |
        /// +-----------------+------------------+-----------------+
        /// | variable length | variable length  | variable length |
        ///
        /// Once verified and decrypted, the payload has the following plaintext structure:
        ///
        /// |<------------------------------plaintext------------------------------>|
        /// +------------------+-----------------+----------------+-----------------+
        /// |                  |                 |                |                 |
        /// | plaintext header |   random data   | session header |     packet      |
        /// |                  |                 |                |                 |
        /// +------------------+-----------------+----------------+-----------------+
        /// |       pths       | variable length |      shs       | variable length |
        ///
        /// |<---plaintext header-->|
        /// +---------------+-------+
        /// |               |       |
        /// | random length | flags |
        /// |               |       |
        /// +---------------+-------+
        /// |       1       |   1   |
        ///
        /// pths = 2
        ///
        /// if PlaintextHeader::flags contains FLAGS_SESSION_HEADER, Session::Header will follow.
        ///
        /// |<-------session header------->|
        /// +------------+-----------------+
        /// |            |                 |
        /// | session id | sequence number |
        /// |            |                 |
        /// +------------+-----------------+
        /// |     16     |        8        |
        ///
        /// shs = 24
        ///
        /// if PlaintextHeader::flags contains FLAGS_COMPRESSED, the packet is inflated.
        ///
        /// |<------------packet------------->|
        /// +---------------+-----------------+
        /// |               |                 |
        /// | packet header |   packet data   |
        /// |               |                 |
        /// +---------------+-----------------+
        /// |      phs      | variable length |
        ///
        /// |<--------------packet header------------->|
        /// +-------+-----------------+---------+------+
        /// |       |                 |         |      |
        /// | magic |       id        | version | size |
        /// |       |                 |         |      |
        /// +-------+-----------------+---------+------+
        /// |   4   | variable length |    2    |  4   |
        ///
        /// phs = 10 + id size

        struct _LIB_THEKOGANS_PACKET_DECL FrameParser {
            /// \struct FrameParser::PacketHandler FrameParser.h thekogans/packet/FrameParser.h
            ///
            /// \brief
            /// Inherit from this class to receive arriving packets.
            struct _LIB_THEKOGANS_PACKET_DECL PacketHandler {
                /// \brief
                /// dtor.
                virtual ~PacketHandler () {}

                /// \brief
                /// Called by the parser to get the cipher for a given key id.
                /// \param[in] keyId \see{crypto::SymmetricKey} id.
                /// \return \see{crypto::Cipher} corresponding to the given key id.
                virtual crypto::Cipher::Ptr GetCipherForKeyId (
                    const crypto::ID & /*keyId*/) throw () = 0;

                /// \brief
                /// Called by the parser to get the current \see{Session}.
                /// \return Current session (0 if not using sessions).
                virtual Session *GetCurrentSession () throw () = 0;

                /// \brief
                /// Called by the parser to let the handler know a packet was parsed.
                /// \param[in] packet New \see{Packet}.
                /// \param[in] cipher \see{crypto::Cipher} that was used to decrypt this packet.
                virtual void HandlePacket (
                    Packet::Ptr /*packet*/,
                    crypto::Cipher::Ptr /*cipher*/) throw () = 0;
            };

        private:
            enum {
                /// \brief
                /// Default max ciphertext length.
                DEFAULT_MAX_CIPHERTEXT_LENGTH = 2 * 1024 * 1024
            };
            /// \brief
            /// Max ciphertext length allows us to protect ourselves from malicious actors.
            const util::ui32 maxCiphertextLength;
            /// \enum
            /// FrameParser is a state machine. These are it's various states.
            enum {
                /// \brief
                /// Next value to parse is the \see{crypto::FrameHeader}.
                STATE_FRAME_HEADER,
                /// \brief
                /// Next value to parse is the encrypted \see{Session::Header}
                /// and \see{Packet}.
                STATE_CIPHERTEXT
            } state;
            /// \brief
            /// Incrementally parsed \see{crypto::FrameHeader}.
            crypto::FrameHeader frameHeader;
            /// \brief
            /// Incrementally parsed payload.
            util::Buffer ciphertext;
            /// \brief
            /// \see{crypto::Cipher} corresponding to frameHeader.keyId.
            crypto::Cipher::Ptr cipher;
            /// \brief
            /// Parses \see{crypto::FrameHeader}.
            ValueParser<crypto::FrameHeader> frameHeaderParser;

        public:
            /// \brief
            /// ctor.
            /// \param[in] maxCiphertextLength_ Max ciphertext length.
            FrameParser (
                util::ui32 maxCiphertextLength_ = DEFAULT_MAX_CIPHERTEXT_LENGTH) :
                maxCiphertextLength (maxCiphertextLength_),
                state (STATE_FRAME_HEADER),
                ciphertext (util::NetworkEndian),
                frameHeaderParser (frameHeader) {}

            /// \brief
            /// Return the max ciphertext length allowed by this parser.
            /// \return Max ciphertext length allowed by this parser.
            inline util::ui32 GetMaxCiphertextLength () const {
                return maxCiphertextLength;
            }

            /// \brief
            /// Parse a buffer containing packet(s) or a packet fragment.
            /// \param[in] buffer Buffer containing a packet fragment.
            /// \param[out] packetHandler PacketHandler api is used to
            /// process incoming packets.
            void HandleBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler);

        private:
            /// \brief
            /// Reset the parser to the initial state.
            void Reset ();
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_FrameParser_h)
