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

#include <algorithm>
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/packet/PlaintextHeader.h"
#include "thekogans/packet/PacketParser.h"

namespace thekogans {
    namespace packet {

        void PacketParser::HandleBuffer (
                util::Buffer &buffer,
                PacketHandler &packetHandler) {
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
            } bufferEndiannessSetter (buffer, util::NetworkEndian);
            while (buffer.GetDataAvailableForReading () > 0) {
                switch (state) {
                    case STATE_HEADER_MAGIC: {
                        if (ParseValue (buffer, header.magic)) {
                            if (header.magic == util::MAGIC32) {
                                state = STATE_HEADER_TYPE_LENGTH;
                            }
                            else {
                                Reset ();
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Corrupt serializable header: %u.",
                                    header.magic);
                            }
                        }
                        break;
                    }
                    case STATE_HEADER_TYPE_LENGTH: {
                        util::ui32 length = 0;
                        if (ParseValue (buffer, length)) {
                            if (length > 0 && length <= MAX_TYPE_LENGTH) {
                                header.type.resize (length);
                                state = STATE_HEADER_TYPE;
                            }
                            else {
                                Reset ();
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Invalid type length: %u.",
                                    length);
                            }
                        }
                        break;
                    }
                    case STATE_HEADER_TYPE: {
                        util::ui32 bytesAvailable = std::min (
                            (util::ui32)header.type.size () - offset,
                            buffer.GetDataAvailableForReading ());
                        buffer.Read (&header.type[offset], bytesAvailable);
                        offset += bytesAvailable;
                        if (offset == header.type.size ()) {
                            offset = 0;
                            state = STATE_HEADER_VERSION;
                        }
                        break;
                    }
                    case STATE_HEADER_VERSION: {
                        if (ParseValue (buffer, header.version)) {
                            state = STATE_HEADER_SIZE;
                        }
                        break;
                    }
                    case STATE_HEADER_SIZE: {
                        if (ParseValue (buffer, header.size)) {
                            if (header.size > 0 && header.size <= maxPacketSize) {
                                state = STATE_PAYLOAD;
                                payload.reset (
                                    new util::Buffer (
                                        util::NetworkEndian,
                                        header.size));
                            }
                            else {
                                Reset ();
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Invalid payload length: %u.",
                                    header.size);
                            }
                        }
                        break;
                    }
                    case STATE_PAYLOAD: {
                        payload->AdvanceWriteOffset (
                            buffer.Read (
                                payload->GetWritePtr (),
                                payload->GetDataAvailableForWriting ()));
                        if (payload->GetDataAvailableForWriting () == 0) {
                            THEKOGANS_UTIL_TRY {
                                packetHandler.HandlePacket (
                                    Packet::Deserialize (header, *payload));
                                Reset ();
                            }
                            THEKOGANS_UTIL_CATCH (util::Exception) {
                                Reset ();
                                THEKOGANS_UTIL_RETHROW_EXCEPTION (exception);
                            }
                        }
                        break;
                    }
                }
            }
        }

        void PacketParser::Reset () {
            state = STATE_HEADER_MAGIC;
            payload.reset ();
            offset = 0;
        }

    } // namespace packet
} // namespace thekogans
