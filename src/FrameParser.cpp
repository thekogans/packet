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
#include "thekogans/packet/FrameParser.h"

namespace thekogans {
    namespace packet {

        void FrameParser::HandleBuffer (
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
                    case STATE_FRAME_HEADER_KEY_ID: {
                        if (ParseValue (buffer, frameHeader.keyId)) {
                            cipher = packetHandler.GetCipherForKeyId (frameHeader.keyId);
                            if (cipher.Get () != 0) {
                                state = STATE_FRAME_HEADER_CIPHERTEXT_LENGTH;
                            }
                            else {
                                Reset ();
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Invalid key id: %s.",
                                    frameHeader.keyId.ToString ().c_str ());
                            }
                        }
                        break;
                    }
                    case STATE_FRAME_HEADER_CIPHERTEXT_LENGTH: {
                        if (ParseValue (buffer, frameHeader.ciphertextLength)) {
                            if (frameHeader.ciphertextLength > 0 &&
                                    frameHeader.ciphertextLength <= maxCiphertextLength) {
                                state = STATE_CIPHERTEXT;
                                ciphertext.reset (
                                    new util::Buffer (
                                        util::NetworkEndian,
                                        frameHeader.ciphertextLength));
                            }
                            else {
                                Reset ();
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Invalid ciphertext length: %u.",
                                    frameHeader.ciphertextLength);
                            }
                        }
                        break;
                    }
                    case STATE_CIPHERTEXT: {
                        ciphertext->AdvanceWriteOffset (
                            buffer.Read (
                                ciphertext->GetWritePtr (),
                                ciphertext->GetDataAvailableForWriting ()));
                        if (ciphertext->GetDataAvailableForWriting () == 0) {
                            THEKOGANS_UTIL_TRY {
                                packetHandler.HandlePacket (
                                    Packet::Deserialize (
                                        *ciphertext,
                                        *cipher,
                                        packetHandler.GetCurrentSession ()),
                                    cipher);
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

        void FrameParser::Reset () {
            state = STATE_FRAME_HEADER_KEY_ID;
            ciphertext.reset ();
            cipher.Reset ();
            offset = 0;
        }

    } // namespace packet
} // namespace thekogans
