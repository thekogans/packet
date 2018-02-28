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

#if !defined (__thekogans_packet_Packet_h)
#define __thekogans_packet_Packet_h

#include <memory>
#include <vector>
#include <map>
#include "thekogans/util/Types.h"
#include "thekogans/util/GUID.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/PacketHeader.h"

namespace thekogans {
    namespace packet {

        /// \struct Packet Packet.h thekogans/packet/Packet.h
        ///
        /// \brief
        /// Packet is an abstract base for all packet types. It provides
        /// machinery necessary for different packet types to register
        /// themselves and be dynamically discovered at run time. Packet's
        /// one and only job is to serialize and reconstitute itself from
        /// rest. To that end, it exposes a single public api, Serialize.
        /// The api comes in different flavors to be used in different
        /// contexts.

        struct _LIB_THEKOGANS_PACKET_DECL Packet {
            /// \brief
            /// Convenient typedef for std::unique_ptr<Packet>.
            typedef std::unique_ptr<Packet> UniquePtr;

            /// \brief
            /// Packet factory type.
            /// \param[in] packetHeader \see{PacketHeader}.
            /// \param[in] buffer Serialized packet data.
            /// \return A concrete packet.
            typedef UniquePtr (*Factory) (
                const PacketHeader &packetHeader,
                util::Buffer &buffer);
            /// \brief
            /// Packet factory map. This map gets populated at initialization
            /// and is used at runtime to dynamically parse and create concrete
            /// Packes from buffers.
            typedef std::map<util::ui32, Factory> Map;

            /// \brief
            /// Controls Map's lifetime.
            static Map &GetMap ();
            /// \brief
            /// Used by [TCP | UDP]FrameParser to check arrived packet id.
            /// \return true = Id is valid, false = Id is invalid.
            static bool CheckId (util::ui16 id);
            /// \brief
            /// Used at runtime to unframe/decrypt a concrete packet.
            /// \param[in] packetHeaderAndData Buffer containing a serialized packet.
            /// \return A concrete packet type.
            static UniquePtr Get (
                util::Buffer &packetHeaderAndData);
            /// \brief
            /// Used at runtime to unframe/decrypt a concrete packet.
            /// \param[in] packetHeader Packet header.
            /// \param[in] packetData Packet data.
            /// \return A concrete packet type.
            static UniquePtr Get (
                const PacketHeader &packetHeader,
                util::Buffer &packetData);

            /// \struct Packet::MapInitializer Packet.h thekogans/packet/Packet.h
            ///
            /// \brief
            /// MapInitializer is used to initialize the Packet::map.
            /// It should not be used directly, and instead is included
            /// in THEKOGANS_PACKET_DECLARE_PACKET/THEKOGANS_PACKET_IMPLEMENT_PACKET.
            /// If you're deriving a new packet from Packet add
            /// THEKOGANS_PACKET_DECLARE_PACKET to it's declaration,
            /// and THEKOGANS_PACKET_IMPLEMENT_PACKET to it's definition.
            struct MapInitializer {
                /// \brief
                /// ctor.
                /// \param[in] id Packet type id.
                /// \param[in] factory Packet type factory.
                MapInitializer (
                    util::ui16 id,
                    Factory factory);
            };

            /// \brief
            /// dtor.
            virtual ~Packet () {}

            /// \brief
            /// Serialize, encrypt, mac and frame the packet. \see{TCPTunnel}::SendPacket
            /// uses this api to prepare the packet for travel.
            /// The following best practices are observed:
            ///   - Encrypt then mac (EtM) to avoid the cryptographic doom principle:
            ///     https://moxie.org/blog/the-cryptographic-doom-principle/
            ///   - An explicit IV per packet to avoid BEAST:
            ///     http://www.slideshare.net/danrlde/20120418-luedtke-ssltlscbcbeast
            ///   - A monotonicaly increasing sequence number to avoid replay attacks.
            ///   - A random length random vector prepended to the packet to avoid
            ///     known plaintext attacks.
            ///   - The only identifiable per frame plaintext information are the key
            ///     id and the payload length. The key id is a SHA256 hash of key data.
            ///     The payload length is bounded to avoid DoS attacks.
            /// \param[in] sequenceNumber Packet sequence number.
            /// \param[in] cipher \see{Cipher} used to encrypt and mac the payload.
            /// \param[in] compress Compress the packet before encrypting.
            /// \param[in] maxDataLength Max payload length per frame.
            /// \param[out] frames Encrypted frames ready to be put on the wire.
            void Serialize (
                const util::GUID &sessionId,
                util::ui32 sequenceNumber,
                crypto::Cipher &cipher,
                bool compress,
                util::ui32 maxDataLength,
                std::vector<util::Buffer::UniquePtr> &frames) const;

            /// \brief
            /// Serialize, encrypt and mac the packet. \see{UDPTunnel}::SendPacket
            /// uses this api to prepare the packet for travel.
            /// \param[in] sequenceNumber Packet sequence number.
            /// \param[in] cipher \see{Cipher} used to encrypt and mac the packet.
            /// \param[in] compress Compress the packet before encrypting.
            /// \return Serialized, encrypted and mac'ed packet.
            util::Buffer::UniquePtr Serialize (
                const util::GUID &sessionId,
                util::ui32 sequenceNumber,
                crypto::Cipher &cipher,
                bool compress) const;

            /// \brief
            /// Return packet id.
            /// \return Packet id.
            virtual util::ui16 GetId () const = 0;

        protected:
            /// \brief
            /// Return packet version.
            /// \return Packet version.
            virtual util::ui16 GetVersion () const = 0;

            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual util::ui32 GetSize () const = 0;

            /// \brief
            /// De-serialize the packet.
            /// \param[in] packetHeader Packet header.
            /// \param[in] packetData Packet contents.
            virtual void Read (
                const PacketHeader & /*packetHeader*/,
                util::Buffer & /*packetData*/) = 0;
            /// \brief
            /// Serialize the packet.
            /// \param[in] buffer Packet contents.
            virtual void Write (util::Buffer & /*buffer*/) const = 0;
        };

        /// \def THEKOGANS_PACKET_DECLARE_PACKET_COMMON(type)
        /// Used by THEKOGANS_PACKET_DECLARE_PACKET below.
        #define THEKOGANS_PACKET_DECLARE_PACKET_COMMON(type)\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
        public:\
            type (\
                    const thekogans::packet::PacketHeader &packetHeader,\
                    thekogans::util::Buffer &packetData) {\
                Read (packetHeader, packetData);\
            }\
            static thekogans::packet::Packet::UniquePtr Create (\
                    const thekogans::packet::PacketHeader &packetHeader,\
                    thekogans::util::Buffer &packetData) {\
                return thekogans::packet::Packet::UniquePtr (\
                    new type (packetHeader, packetData));\
            }\
            virtual thekogans::util::ui16 GetId () const {\
                return ID;\
            }\
            virtual thekogans::util::ui16 GetVersion () const {\
                return VERSION;\
            }

    #if defined (TOOLCHAIN_TYPE_Static)
        /// \def THEKOGANS_PACKET_DECLARE_PACKET(type)
        /// Use this macro in Packet declarations (*.h).
        /// It will add the necessary machinery to make
        /// the packet dynamically discoverable.
        #define THEKOGANS_PACKET_DECLARE_PACKET(type)\
        public:\
            THEKOGANS_PACKET_DECLARE_PACKET_COMMON (type)\
            static void StaticInit () {\
                std::pair<Map::iterator, bool> result =\
                    GetMap ().insert (Map::value_type (type::ID, type::Create));\
                if (!result.second) {\
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (\
                        "Packet with id: %u already registered.", type::ID);\
                }\
            }

        /// \def THEKOGANS_PACKET_DECLARE_PACKET(type)
        /// Use this macro in Packet implementations (*.cpp).
        /// It will add the necessary machinery to make the
        /// packet dynamically discoverable.
        #define THEKOGANS_PACKET_IMPLEMENT_PACKET(type)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)
    #else // defined (TOOLCHAIN_TYPE_Static)
        /// \def THEKOGANS_PACKET_DECLARE_PACKET(type)
        /// Use this macro in Packet declarations (*.h).
        /// It will add the necessary machinery to make
        /// the packet dynamically discoverable.
        #define THEKOGANS_PACKET_DECLARE_PACKET(type)\
        public:\
            THEKOGANS_PACKET_DECLARE_PACKET_COMMON (type)\
            static thekogans::packet::Packet::MapInitializer mapInitializer;

        /// \def THEKOGANS_PACKET_DECLARE_PACKET(type)
        /// Use this macro in Packet implementations (*.cpp).
        /// It will add the necessary machinery to make the
        /// packet dynamically discoverable.
        #define THEKOGANS_PACKET_IMPLEMENT_PACKET(type)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
            thekogans::packet::Packet::MapInitializer\
                type::mapInitializer (type::ID, type::Create);
    #endif // defined (TOOLCHAIN_TYPE_Static)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_Packet_h)
