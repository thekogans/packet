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
#include "thekogans/packet/PacketHeader.h"
#include "thekogans/packet/PacketFragmentHeader.h"
#include "thekogans/packet/UDPFrameParser.h"

namespace thekogans {
    namespace packet {

        void UDPFrameParser::PacketInfo::SetPacketHeader (
                const PacketHeader &packetHeader_,
                util::Buffer &packetFragmentBuffer) {
            packetHeader = packetHeader_;
            packetData.Resize (packetHeader.length);
            packetData.readOffset = 0;
            packetData.writeOffset = 0;
            packetData.Write (
                packetFragmentBuffer.GetReadPtr (),
                packetFragmentBuffer.GetDataAvailableForReading ());
            fragmentMap.Resize (packetHeader.fragmentCount--);
            fragmentMap.Set (0, true);
        }

        bool UDPFrameParser::PacketInfo::AddPacketFragmentHeader (
                const PacketFragmentHeader &packetFragmentHeader,
                util::Buffer &packetFragmentBuffer) {
            if (packetFragmentHeader.sequenceNumber == packetHeader.sequenceNumber) {
                if (!fragmentMap.Set (packetFragmentHeader.index, true)) {
                    packetData.writeOffset = packetFragmentHeader.offset;
                    util::ui32 bytesAvailable =
                        packetFragmentBuffer.GetDataAvailableForReading ();
                    util::ui32 bytesWritten =
                        packetFragmentBuffer.AdvanceReadOffset (
                            packetData.Write (
                                packetFragmentBuffer.GetReadPtr (),
                                bytesAvailable));
                    if (bytesAvailable == bytesWritten) {
                        if (--packetHeader.fragmentCount == 0) {
                            packetData.writeOffset = packetData.length;
                            return true;
                        }
                        return false;
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
                    "Expected sequence number %s, %u.",
                    packetFragmentHeader.sessionId.ToString ().c_str (),
                    packetFragmentHeader.sequenceNumber,
                    packetFragmentHeader.index,
                    packetFragmentHeader.offset,
                    packetHeader.sessionId.ToString ().c_str (),
                    packetHeader.sequenceNumber);
            }
        }

        void UDPFrameParser::HandleBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler) {
            PacketHeader packetHeader;
            Packet::UniquePtr packet = ParseBuffer (buffer, packetHandler, packetHeader);
            if (packet.get () != 0) {
                packetHandler.HandlePacket (packetHeader, std::move (packet));
            }
        }

        void UDPFrameParser::HandleBuffer (
                util::Buffer &buffer,
                const stream::Address &address,
                PacketHandler &packetHandler) {
            PacketHeader packetHeader;
            Packet::UniquePtr packet = ParseBuffer (buffer, packetHandler, packetHeader);
            if (packet.get () != 0) {
                packetHandler.HandlePacket (packetHeader, std::move (packet), address);
            }
        }

        void UDPFrameParser::HandleBuffer (
                util::Buffer &buffer,
                const stream::Address &from,
                const stream::Address &to,
                PacketHandler &packetHandler) {
            PacketHeader packetHeader;
            Packet::UniquePtr packet = ParseBuffer (buffer, packetHandler, packetHeader);
            if (packet.get () != 0) {
                packetHandler.HandlePacket (packetHeader, std::move (packet), from, to);
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

        Packet::UniquePtr UDPFrameParser::ParseBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler,
                PacketHeader &packetHeader) {
            BufferEndiannessSetter bufferEndiannessSetter (buffer, util::NetworkEndian);
            Packet::UniquePtr packet;
            crypto::FrameHeader frameHeader;
            buffer >> frameHeader;
            crypto::Cipher::Ptr cipher = packetHandler.GetCipher (frameHeader.keyId);
            if (cipher.Get () != 0) {
                util::Buffer::UniquePtr plaintext =
                    cipher->Decrypt (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading ());
                PlaintextHeader plaintextHeader;
                *plaintext >> plaintextHeader;
                if (plaintextHeader.type == PlaintextHeader::TYPE_PACKET_HEADER) {
                    plaintext->AdvanceReadOffset (plaintextHeader.randomLength);
                    *plaintext >> packetHeader;
                    if (packetHeader.sessionId == sessionId &&
                            packetHeader.sequenceNumber == sequenceNumber) {
                        if (packetInfo.packetHeader.fragmentCount == 0) {
                            if (packetHeader.fragmentCount == 1) {
                                packet = Packet::Get (packetHeader, *plaintext);
                                if (packet.get () == 0) {
                                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                        "Received an unrecognized packet; packetHeader.id: %u.",
                                        packetHeader.id);
                                }
                            }
                            else {
                                packetInfo.SetPacketHeader (packetHeader, *plaintext);
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
                        packetHeader = packetInfo.packetHeader;
                        packet = Packet::Get (packetHeader, packetInfo.packetData);
                        if (packet.get () == 0) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Received an unrecognized packet; packetHeader.id: %u.",
                                packetInfo.packetHeader.id);
                        }
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
                    "Received an unrecognized frame (frameHeader.keyId: %s).",
                    frameHeader.keyId.ToString ().c_str ());
            }
            return packet;
        }

    } // namespace packet
} // namespace thekogans
