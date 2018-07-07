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

#if !defined (__thekogans_packet_ValueParser_h)
#define __thekogans_packet_ValueParser_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/FrameHeader.h"
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct ValueParser ValueParser.h thekogans/packet/ValueParser.h
        ///
        /// \brief
        /// ValueParser is a template used to incrementally assemble values from stream
        /// like \see{thekogans::util::Serializer}s.

        template<typename T>
        struct ValueParser {
        private:
            /// \brief
            /// Value to parse.
            T &value;
            /// \brief
            /// Offset in to valueBuffer.
            util::ui32 offset;
            /// \brief
            /// Partial value.
            util::ui8 valueBuffer[sizeof (T)];

        public:
            /// \brief
            /// ctor.
            /// \param[out] value_ Value to parse.
            explicit ValueParser (T &value_) :
                value (value_),
                offset (0) {}

            /// \brief
            /// Rewind the offset to get it ready for the next value.
            inline void Reset () {
                offset = 0;
            }

            /// \brief
            /// Try to parse a value from the given serializer.
            /// \param[in] serializer Contains a complete or partial value.
            /// \return Value was successfully parsed.
            bool ParseValue (util::Serializer &serializer) {
                offset += serializer.Read (
                    valueBuffer + offset,
                    sizeof (T) - offset);
                if (offset == sizeof (T)) {
                    Reset ();
                    util::TenantReadBuffer buffer (
                        serializer.endianness,
                        valueBuffer,
                        sizeof (T));
                    buffer >> value;
                    return true;
                }
                return false;
            }
        };

        /// \struct ValueParser<std::string> ValueParser.h thekogans/packet/ValueParser.h
        ///
        /// \brief
        /// Specialization of ValueParser for std::string.

        template<>
        struct _LIB_THEKOGANS_PACKET_DECL ValueParser<std::string> {
        private:
            /// \brief
            /// String to parse.
            std::string &value;
            /// \brief
            /// String length.
            util::ui32 length;
            /// \brief
            /// String length parser.
            ValueParser<util::ui32> lengthParser;
            /// \brief
            /// Offset in to value where to write the next chunk.
            util::ui32 offset;
            /// \enum
            /// std::string parser is a state machine. These are it's various states.
            enum {
                /// \brief
                /// Next value is length.
                STATE_LENGTH,
                /// \brief
                /// Next value is string.
                STATE_STRING
            } state;

        public:
            /// \brief
            /// ctor.
            /// \param[out] value_ Value to parse.
            explicit ValueParser (std::string &value_) :
                value (value_),
                length (0),
                lengthParser (length),
                offset (0),
                state (STATE_LENGTH) {}

            /// \brief
            /// Rewind the lengthParser to get it ready for the next value.
            void Reset ();

            /// \brief
            /// Try to parse a std::string from the given buffer.
            /// \param[in] buffer Contains a complete or partial std::string.
            /// \return Value was successfully parsed.
            bool ParseValue (util::Serializer &serializer);
        };

        /// \struct ValueParser<util::Serializable::Header> ValueParser.h thekogans/packet/ValueParser.h
        ///
        /// \brief
        /// Specialization of ValueParser for \see{util::Serializable::Header}.

        template<>
        struct _LIB_THEKOGANS_PACKET_DECL ValueParser<util::Serializable::Header> {
        private:
            /// \brief
            /// \see{util::Serializable::Header} to parse.
            util::Serializable::Header &value;
            /// \brief
            /// Parses \see{util::Serializable::Header::magic}.
            ValueParser<util::ui32> magicParser;
            /// \brief
            /// Parses \see{util::Serializable::Header::type}.
            ValueParser<std::string> typeParser;
            /// \brief
            /// Parses \see{util::Serializable::Header::version}.
            ValueParser<util::ui16> versionParser;
            /// \brief
            /// Parses \see{util::Serializable::Header::size}.
            ValueParser<util::ui32> sizeParser;
            /// \enum
            /// \see{util::Serializable::Header} parser is a state machine.
            /// These are it's various states.
            enum {
                /// \brief
                /// Next value is \see{util::Serializable::Header::magic}.
                STATE_MAGIC,
                /// \brief
                /// Next value is \see{util::Serializable::Header::type}.
                STATE_TYPE,
                /// \brief
                /// Next value is \see{util::Serializable::Header::version}.
                STATE_VERSION,
                /// \brief
                /// Next value is \see{util::Serializable::Header::size}.
                STATE_SIZE
            } state;

        public:
            /// \brief
            /// ctor.
            /// \param[out] value_ Value to parse.
            explicit ValueParser (util::Serializable::Header &value_) :
                value (value_),
                magicParser (value.magic),
                typeParser (value.type),
                versionParser (value.version),
                sizeParser (value.size),
                state (STATE_MAGIC) {}

            /// \brief
            /// Rewind the sub-parsers to get them ready for the next value.
            void Reset ();

            /// \brief
            /// Try to parse a \see{util::Serializable::Header} from the given buffer.
            /// \param[in] buffer Contains a complete or partial \see{util::Serializable::Header}.
            /// \return Value was successfully parsed.
            bool ParseValue (util::Serializer &serializer);
        };

        /// \struct ValueParser<crypto::FrameHeader> ValueParser.h thekogans/packet/ValueParser.h
        ///
        /// \brief
        /// Specialization of ValueParser for \see{crypto::FrameHeader}.

        template<>
        struct _LIB_THEKOGANS_PACKET_DECL ValueParser<crypto::FrameHeader> {
        private:
            /// \brief
            /// String to parse.
            crypto::FrameHeader &value;
            /// \brief
            /// Parses \see{crypto::FrameHeader::keyId}.
            ValueParser<crypto::ID> keyIdParser;
            /// \brief
            /// Parses \see{crypto::FrameHeader::ciphertextLength}.
            ValueParser<util::ui32> ciphertextLengthParser;
            /// \enum
            /// \see{crypto::FrameHeader} parser is a state machine. These are it's various states.
            enum {
                /// \brief
                /// Next value to parse is the \see{crypto::FrameHeader::keyId}.
                STATE_KEY_ID,
                /// \brief
                /// Next value to parse is the \see{crypto::FrameHeader::ciphertextLength}.
                STATE_CIPHERTEXT_LENGTH
            } state;

        public:
            /// \brief
            /// ctor.
            /// \param[out] value_ Value to parse.
            explicit ValueParser (crypto::FrameHeader &value_) :
                value (value_),
                keyIdParser (value.keyId),
                ciphertextLengthParser (value.ciphertextLength),
                state (STATE_KEY_ID) {}

            /// \brief
            /// Rewind the sub-parsers to get them ready for the next value.
            void Reset ();

            /// \brief
            /// Try to parse a \see{crypto::FrameHeader} from the given buffer.
            /// \param[in] buffer Contains a complete or partial \see{crypto::FrameHeader}.
            /// \return Value was successfully parsed.
            bool ParseValue (util::Serializer &serializer);
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ValueParser_h)
