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

#include "thekogans/packet/ValueParser.h"

namespace thekogans {
    namespace packet {

        void ValueParser<util::SizeT>::Reset () {
            size = 0;
            offset = 0;
            state = STATE_SIZE;
        }

        bool ValueParser<util::SizeT>::ParseValue (util::Serializer &serializer) {
            if (state == STATE_SIZE) {
                util::ui8 firstByte;
                if (serializer.Read (&firstByte, 1) == 1) {
                    size = util::SizeT::Size (firstByte);
                    if (size == 1) {
                        value = firstByte >> 1;
                        return true;
                    }
                    offset = 1;
                    valueBuffer[0] = firstByte;
                    state = STATE_VALUE;
                }
            }
            if (state == STATE_VALUE) {
                offset += serializer.Read (
                    valueBuffer + offset,
                    size - offset);
                if (offset == size) {
                    state = STATE_SIZE;
                    util::TenantReadBuffer buffer (
                        serializer.endianness,
                        valueBuffer,
                        size);
                    buffer >> value;
                    return true;
                }
            }
            return false;
        }

        void ValueParser<std::string>::Reset () {
            length = 0;
            lengthParser.Reset ();
            offset = 0;
            state = STATE_LENGTH;
        }

        bool ValueParser<std::string>::ParseValue (util::Serializer &serializer) {
            if (state == STATE_LENGTH) {
                if (lengthParser.ParseValue (serializer)) {
                    value.resize (length);
                    if (length == 0) {
                        return true;
                    }
                    offset = 0;
                    state = STATE_STRING;
                }
            }
            if (state == STATE_STRING) {
                offset += serializer.Read (&value[offset], value.size () - offset);
                if (offset == value.size ()) {
                    state = STATE_LENGTH;
                    return true;
                }
            }
            return false;
        }

        void ValueParser<util::Serializable::Header>::Reset () {
            magicParser.Reset ();
            typeParser.Reset ();
            versionParser.Reset ();
            sizeParser.Reset ();
            state = STATE_MAGIC;
        }

        bool ValueParser<util::Serializable::Header>::ParseValue (util::Serializer &serializer) {
            if (state == STATE_MAGIC) {
                if (magicParser.ParseValue (serializer)) {
                    if (value.magic == util::MAGIC32) {
                        state = STATE_TYPE;
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Corrupt serializable header: %u.",
                            value.magic);
                    }
                }
            }
            if (state == STATE_TYPE) {
                if (typeParser.ParseValue (serializer)) {
                    if (util::Serializable::ValidateType (value.type)) {
                        state = STATE_VERSION;
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unknown serializable type: %s.",
                            value.type.c_str ());
                    }
                }
            }
            if (state == STATE_VERSION) {
                if (versionParser.ParseValue (serializer)) {
                    state = STATE_SIZE;
                }
            }
            if (state == STATE_SIZE) {
                if (sizeParser.ParseValue (serializer)) {
                    state = STATE_MAGIC;
                    return true;
                }
            }
            return false;
        }

        void ValueParser<crypto::FrameHeader>::Reset () {
            keyIdParser.Reset ();
            ciphertextLengthParser.Reset ();
            state = STATE_KEY_ID;
        }

        bool ValueParser<crypto::FrameHeader>::ParseValue (util::Serializer &serializer) {
            if (state == STATE_KEY_ID) {
                if (keyIdParser.ParseValue (serializer)) {
                    state = STATE_CIPHERTEXT_LENGTH;
                }
            }
            if (state == STATE_CIPHERTEXT_LENGTH) {
                if (ciphertextLengthParser.ParseValue (serializer)) {
                    state = STATE_KEY_ID;
                    return true;
                }
            }
            return false;
        }

    } // namespace packet
} // namespace thekogans
