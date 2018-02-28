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

#if !defined (__thekogans_packet_TCPFrameParser_h)
#define __thekogans_packet_TCPFrameParser_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/FrameHeader.h"
#include "thekogans/crypto/CiphertextHeader.h"
#include "thekogans/crypto/ID.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/PlaintextHeader.h"
#include "thekogans/packet/PacketHeader.h"
#include "thekogans/packet/PacketFragmentHeader.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct TCPFrameParser TCPFrameParser.h thekogans/stream/TCPFrameParser.h
        ///
        /// \brief
        /// TCPFrameParser parses \see{crypto::FrameHeader} framed \see{Packet}s that arrive on the wire.
        /// It's suitable for streaming (TCP) transports.

        struct _LIB_THEKOGANS_PACKET_DECL TCPFrameParser {
            enum {
                /// \brief
                /// Min payload length.
                MIN_PAYLOAD_LENGTH =
                    1024 - crypto::FrameHeader::SIZE,
                /// \brief
                /// Max payload length.
                MAX_PAYLOAD_LENGTH =
                    64 * 1024 - crypto::FrameHeader::SIZE,
                /// \brief
                /// Default max payload length.
                DEFAULT_MAX_PAYLOAD_LENGTH =
                    32 * 1024 - crypto::FrameHeader::SIZE,
                /// \brief
                /// Number of bytes taken up by the framing protocol.
                MAX_FRAMING_OVERHEAD =
                    PlaintextHeader::SIZE +
                    PlaintextHeader::MAX_RANDOM_LENGTH +
                    PacketHeader::SIZE
                    //PacketFragmentHeader::SIZE
            };

            /// \struct TCPFrameParser::PacketHandler TCPFrameParser.h thekogans/stream/TCPFrameParser.h
            ///
            /// \brief
            /// All users of TCPFrameParser need to inherit from this class. It's passed in to HandleBuffer
            /// and is used by the TCPFrameParser to notify the handler when a payload needs to be decrypted
            /// and when a new packet is ready.
            struct _LIB_THEKOGANS_PACKET_DECL PacketHandler {
                /// \brief
                /// dtor.
                virtual ~PacketHandler () {}

                /// \brief
                /// Called by the parser after it has parsed the \see{crypto::FrameHeader}::keyId.
                /// If no such key exists, an exception is thrown. It's a very good idea to
                /// terminate the connection if that happens as we're probably being DoSed.
                /// \param[in] keyId \see{crypto::SymmetricKey} to get.
                /// \return \see{crypto::Cipher::Ptr} matching the id.
                virtual bool HaveKeyWithId (const crypto::ID & /*keyId*/) = 0;

                /// \brief
                /// Called by the parser after it has parsed the \see{crypto::FrameHeader}::keyId.
                /// If no such key exists, an exception is thrown. It's a very good idea to
                /// terminate the connection if that happens as we're probably being DoSed.
                /// \param[in] keyId \see{crypto::Key} to get.
                /// \return \see{crypto::Key} matching the id.
                virtual crypto::Cipher::Ptr GetCipher (const crypto::ID & /*keyId*/) = 0;

                /// \brief
                /// Called by the parser to let the handler know a packet was parsed.
                /// \param[in] packetHeader Parsed \see{PacketHeader}.
                /// \param[in] packet Parsed \see{Packet}.
                virtual void HandlePacket (
                    const PacketHeader & /*packetHeader*/,
                    Packet::UniquePtr /*packet*/) = 0;
            };

        private:
            /// \brief
            /// Max payload length allows us to protect ourselves from malicious actors.
            const util::ui32 maxPayloadLength;
            /// \brief
            /// true = compress \see{Packet} before encryption.
            const bool compressPacket;
            /// \brief
            /// Max raw data length per frame.
            const util::ui32 maxDataLength;
            /// \brief
            /// Unique session id to thwart replay attacks.
            util::GUID sessionId;
            /// \brief
            /// Monotonically increasing sequence number to catch out of order packets.
            util::ui32 sequenceNumber;
            /// \enum
            /// TCPFrameParser is a state machine. These are it's various states.
            enum {
                /// \brief
                /// Next value to parse is the \see{crypto::FrameHeader::keyId}.
                STATE_KEY_ID,
                /// \brief
                /// Next value to parse is the \see{crypto::FrameHeader::ciphertextLength}.
                STATE_CIPHERTEXT_LENGTH,
                /// \brief
                /// Next value to parse is the \see{crypto::CiphertextHeader} + ciphertext.
                STATE_CIPHERTEXT
            } state;
            /// \brief
            /// Incrementally parsed frame header.
            crypto::FrameHeader frameHeader;
            /// \brief
            /// Incrementally parsed payload.
            util::Buffer ciphertext;
            /// \brief
            /// Partial read offset.
            util::ui32 offset;
            /// \struct TCPFrameParser::PacketInfo TCPFrameParser.h thekogans/stream/TCPFrameParser.h
            ///
            /// \brief
            /// PacketInfo keeps track of multi-fragment packets. As each fragment is received,
            /// packet info assembles them in to a complete packet and lets the parser know when
            /// the entire packet arrived.
            struct PacketInfo {
                /// \brief
                /// The first fragment will contain the \see{PacketHeader}.
                PacketHeader packetHeader;
                /// \brief
                /// \see{Packet} data.
                util::Buffer packetData;

                /// \brirf
                /// ctor.
                PacketInfo () :
                    packetData (util::NetworkEndian) {}

                /// \brief
                /// Called by FragmentParser::Reset.
                void Reset ();

                /// \brief
                /// Called when processing a \see{PacketHeader} payload.
                /// \param[in] packetHeader_ Newly arrived \see{PacketHeader}.
                /// \param[in] packetFragmentBuffer The \see{Packet} fragment
                /// that arrived with the header.
                void SetPacketHeader (
                    const PacketHeader &packetHeader_,
                    util::Buffer &packetFragmentBuffer);

                /// \brief
                /// Called when processing a \see{PacketFragmentHeader} payload.
                /// \param[in] packetFragmentHeader Newly arrived \see{PacketFragmentHeader}.
                /// \param[in] packetFragmentBuffer The \see{Packet} fragment
                /// that arrived with the fragment header.
                /// \return true = this was the last fragment, false = more fragments tp come.
                bool AddPacketFragmentHeader (
                    const PacketFragmentHeader &packetFragmentHeader,
                    util::Buffer &packetFragmentBuffer);
            } packetInfo;

        public:
            /// \brief
            /// ctor.
            /// \param[in] maxPayloadLength_ Max payload length.
            /// \param[in] compressPacket_ true = compress \see{Packet} before encryption.
            TCPFrameParser (
                util::ui32 maxPayloadLength_ = DEFAULT_MAX_PAYLOAD_LENGTH,
                bool compressPacket_ = false);

            /// \brief
            /// Return maxPayloadLength.
            /// \return maxPayloadLength.
            inline util::ui32 GetMaxPayloadLength () const {
                return maxPayloadLength;
            }

            /// \brief
            /// Return compressPacket.
            /// \return compressPacket.
            inline bool IsCompressPacket () const {
                return compressPacket;
            }

            /// \brief
            /// Return max raw data length per payload.
            /// \return Max raw data length per payload.
            inline util::ui32 GetMaxDataLength () const {
                return maxDataLength;
            }

            /// \brief
            /// Parse a buffer containing a packet fragment.
            /// \param[in] buffer Buffer containing a packet fragment.
            /// \param[in,out] packetHandler PacketHandler::HandlePacket
            /// is called for every complete packet.
            void HandleBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler);

        private:
            /// \brief
            /// Reset the parser to the initial state.
            void Reset ();

            /// \brief
            /// This is where the heavy lifting of parsing the
            /// actual \see{Packet} takes place.
            /// \param[in] buffer Buffer containing either the
            /// whole \see{Packet} or a packet fragment.
            /// \param[in] packetHandler PacketHandler::CheckKeyId
            /// is called for every parsed \see{crypto::FrameHeader}::keyId.
            bool ParseBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler);
            /// \brief
            /// Helper used to parse \see{crypto::FrameHeader}::keyId.
            /// \param[in] buffer Buffer containing the key id being parsed.
            /// \return true = got the whole value.
            bool ParseKeyId (util::Buffer &buffer);
            /// \brief
            /// Helper used to parse \see{crypto::FrameHeader}::ciphertextLength.
            /// \param[in] buffer Buffer containing the ciphertext length being parsed.
            /// \return true = got the whole value.
            bool ParseCiphertextLength (util::Buffer &buffer);
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_TCPFrameParser_h)
