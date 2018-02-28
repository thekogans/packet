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

#include <cassert>
#include <algorithm>
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/packet/PacketHeader.h"
#include "thekogans/packet/PacketFragmentHeader.h"
#include "thekogans/packet/TCPFrameParser.h"

namespace thekogans {
    namespace packet {

        void TCPFrameParser::PacketInfo::Reset () {
            packetHeader = PacketHeader ();
            packetData.Resize (0);
        }

        void TCPFrameParser::PacketInfo::SetPacketHeader (
                const PacketHeader &packetHeader_,
                util::Buffer &packetFragmentBuffer) {
            packetHeader = packetHeader_;
            packetData.Resize (packetHeader.length);
            packetData.readOffset = 0;
            packetData.writeOffset = 0;
            util::ui32 bytesAvailable =
                packetFragmentBuffer.GetDataAvailableForReading ();
            util::ui32 bytesWritten =
                packetFragmentBuffer.AdvanceReadOffset (
                    packetData.Write (
                        packetFragmentBuffer.GetReadPtr (),
                        bytesAvailable));
            if (bytesAvailable != bytesWritten) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Error processing packet (%s, %u, %u, %u). "
                    "Wrote %u of %u bytes.",
                    packetHeader.sessionId.ToString ().c_str (),
                    packetHeader.sequenceNumber,
                    packetHeader.id,
                    packetHeader.length,
                    bytesWritten,
                    bytesAvailable);
            }
        }

        bool TCPFrameParser::PacketInfo::AddPacketFragmentHeader (
                const PacketFragmentHeader &packetFragmentHeader,
                util::Buffer &packetFragmentBuffer) {
            if (packetFragmentHeader.sessionId == packetHeader.sessionId &&
                    packetFragmentHeader.sequenceNumber == packetHeader.sequenceNumber) {
                if (packetFragmentHeader.offset == packetData.writeOffset) {
                    util::ui32 bytesAvailable =
                        packetFragmentBuffer.GetDataAvailableForReading ();
                    util::ui32 bytesWritten =
                        packetFragmentBuffer.AdvanceReadOffset (
                            packetData.Write (
                                packetFragmentBuffer.GetReadPtr (),
                                bytesAvailable));
                    if (bytesAvailable == bytesWritten) {
                        return --packetHeader.fragmentCount == 0;
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Error processing packet fragment (%s, %u, %u, %u). "
                            "Wrote %u of %u bytes.",
                            packetFragmentHeader.sessionId.ToString ().c_str (),
                            packetFragmentHeader.sequenceNumber,
                            packetFragmentHeader.index,
                            packetFragmentHeader.offset,
                            bytesWritten,
                            bytesAvailable);
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Error processing packet fragment (%s, %u, %u, %u). "
                        "Expected offset %u.",
                        packetFragmentHeader.sessionId.ToString ().c_str (),
                        packetFragmentHeader.sequenceNumber,
                        packetFragmentHeader.index,
                        packetFragmentHeader.offset,
                        packetData.writeOffset);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Error processing packet fragment (%s, %u, %u, %u). "
                    "Expected session id and sequence number %s, %u.",
                    packetFragmentHeader.sessionId.ToString ().c_str (),
                    packetFragmentHeader.sequenceNumber,
                    packetFragmentHeader.index,
                    packetFragmentHeader.offset,
                    packetHeader.sessionId.ToString ().c_str (),
                    packetHeader.sequenceNumber);
            }
        }

        TCPFrameParser::TCPFrameParser (
                util::ui32 maxPayloadLength_,
                bool compressPacket_) :
                maxPayloadLength (maxPayloadLength_),
                compressPacket (compressPacket_),
                maxDataLength (
                    crypto::Cipher::GetMaxPlaintextLength (maxPayloadLength) -
                    MAX_FRAMING_OVERHEAD),
                sessionId (util::GUID::Empty),
                sequenceNumber (0),
                state (STATE_KEY_ID),
                ciphertext (util::NetworkEndian, maxPayloadLength),
                offset (0) {
            if (maxPayloadLength < MIN_PAYLOAD_LENGTH || maxPayloadLength > MAX_PAYLOAD_LENGTH) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            struct BufferEndiannessSetter {
                util::Buffer &buffer;
                util::Endianness endianness;
                BufferEndiannessSetter (
                        util::Buffer &buffer_,
                        util::Endianness endianness_) :
                        buffer (buffer_),
                        endianness (endianness_) {
                    std::swap (buffer.endianness, endianness);
                }
                ~BufferEndiannessSetter () {
                    std::swap (buffer.endianness, endianness);
                }
            };
        }

        void TCPFrameParser::HandleBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler) {
            THEKOGANS_UTIL_TRY {
                BufferEndiannessSetter bufferEndiannessSetter (buffer, util::NetworkEndian);
                while (ParseBuffer (buffer, packetHandler)) {
                    crypto::Cipher::Ptr cipher = packetHandler.GetCipher (frameHeader.keyId);
                    if (cipher.Get () != 0) {
                        util::Buffer::UniquePtr plaintext =
                            cipher->Decrypt (
                                ciphertext.GetReadPtr (),
                                ciphertext.GetDataAvailableForReading ());
                        PlaintextHeader plaintextHeader;
                        *plaintext >> plaintextHeader;
                        if (plaintextHeader.type == PlaintextHeader::TYPE_PACKET_HEADER) {
                            plaintext->AdvanceReadOffset (plaintextHeader.randomLength);
                            PacketHeader packetHeader;
                            *plaintext >> packetHeader;
                            if (packetHeader.sessionId == sessionId &&
                                    packetHeader.sequenceNumber == sequenceNumber) {
                                if (packetInfo.packetHeader.fragmentCount == 0) {
                                    if (packetHeader.fragmentCount == 1) {
                                        Packet::UniquePtr packet = Packet::Get (packetHeader, *plaintext);
                                        if (packet.get () != 0) {
                                            packetHandler.HandlePacket (packetHeader, std::move (packet));
                                        }
                                        else {
                                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                                "Received an unrecognized packet; packetHeader.id: %u.",
                                                packetHeader.id);
                                        }
                                    }
                                    else if (Packet::CheckId (packetHeader.id)) {
                                        packetInfo.SetPacketHeader (packetHeader, *plaintext);
                                    }
                                    else {
                                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                            "Received an unrecognized packet; packetHeader.id: %u.",
                                            packetHeader.id);
                                    }
                                }
                                else {
                                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                        "Received an out of order packet; packetHeader.id: %u, "
                                        "packetInfo.packetHeader.id: %u is inclomplete.",
                                        packetHeader.id,
                                        packetInfo.packetHeader.id);
                                }
                            }
                            else {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Received an out of order packet; packetHeader.id: %u, "
                                    "packetHeader.sequenceNumber: %u.",
                                    packetHeader.id,
                                    packetHeader.sequenceNumber);
                            }
                        }
                        else if (plaintextHeader.type == PlaintextHeader::TYPE_PACKET_FRAGMENT_HEADER) {
                            plaintext->AdvanceReadOffset (plaintextHeader.randomLength);
                            PacketFragmentHeader packetFragmentHeader;
                            *plaintext >> packetFragmentHeader;
                            if (packetInfo.AddPacketFragmentHeader (packetFragmentHeader, *plaintext)) {
                                packetHandler.HandlePacket (packetInfo.packetHeader,
                                    Packet::Get (packetInfo.packetHeader, packetInfo.packetData));
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Received an invalid frame; plaintextHeader.type: %u.",
                                plaintextHeader.type);
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to locate Cipehr for keyId: %s.",
                            frameHeader.keyId.ToString ().c_str ());
                    }
                }
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                Reset ();
                THEKOGANS_UTIL_RETHROW_EXCEPTION (exception);
            }
        }

        void TCPFrameParser::Reset () {
            sessionId = util::GUID::Empty;
            sequenceNumber = 0;
            state = STATE_KEY_ID;
            ciphertext.length = maxPayloadLength;
            ciphertext.readOffset = 0;
            ciphertext.writeOffset = 0;
            offset = 0;
            packetInfo.Reset ();
        }

        bool TCPFrameParser::ParseBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler) {
            while (!buffer.IsEmpty ()) {
                switch (state) {
                    case STATE_KEY_ID: {
                        if (ParseKeyId (buffer)) {
                            if (packetHandler.HaveKeyWithId (frameHeader.keyId)) {
                                state = STATE_CIPHERTEXT_LENGTH;
                            }
                            else {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Unknown frame keyId: %s.",
                                    frameHeader.keyId.ToString ().c_str ());
                            }
                        }
                        break;
                    }
                    case STATE_CIPHERTEXT_LENGTH: {
                        if (ParseCiphertextLength (buffer)) {
                            if (frameHeader.ciphertextLength <= MAX_PAYLOAD_LENGTH) {
                                state = STATE_CIPHERTEXT;
                            }
                            else {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Frame too big: %u, %u.",
                                    frameHeader.ciphertextLength,
                                    MAX_PAYLOAD_LENGTH);
                            }
                        }
                        break;
                    }
                    case STATE_CIPHERTEXT: {
                        buffer.AdvanceReadOffset (
                            ciphertext.Write (
                                buffer.GetReadPtr (),
                                ciphertext.GetDataAvailableForWriting ()));
                        if (ciphertext.IsEmpty ()) {
                            // Reset the state for the next packet.
                            state = STATE_KEY_ID;
                            return true;
                        }
                        break;
                    }
                }
            }
            return false;
        }

        bool TCPFrameParser::ParseKeyId (util::Buffer &buffer) {
            util::ui32 bytesAvailable =
                std::min (
                    (util::ui32)crypto::ID::SIZE - offset,
                    buffer.GetDataAvailableForReading ());
            buffer.Read (&frameHeader.keyId.data[offset], bytesAvailable);
            offset += bytesAvailable;
            if (offset == crypto::ID::SIZE) {
                offset = 0;
                return true;
            }
            return false;
        }

        bool TCPFrameParser::ParseCiphertextLength (util::Buffer &buffer) {
            util::ui32 bytesAvailable =
                std::min (
                    (util::ui32)util::UI32_SIZE - offset,
                    buffer.GetDataAvailableForReading ());
            util::ui8 *ciphertextLength = (util::ui8 *)&frameHeader.ciphertextLength;
            buffer.Read (&ciphertextLength[offset], bytesAvailable);
            offset += bytesAvailable;
            if (offset == util::UI32_SIZE) {
                frameHeader.ciphertextLength =
                    util::ByteSwap<util::NetworkEndian, util::HostEndian> (
                        frameHeader.ciphertextLength);
                offset = 0;
                return true;
            }
            return false;
        }

    } // namespace packet
} // namespace thekogans
