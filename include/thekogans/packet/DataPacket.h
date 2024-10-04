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

#if !defined (__thekogans_packet_DataPacket_h)
#define __thekogans_packet_DataPacket_h

#include <string>
#include <thekogans/util/SizeT.h>
#include <thekogans/util/Buffer.h>
#include <thekogans/util/Serializer.h>
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct DataPacket DataPacket.h thekogans/packet/DataPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the data packet. DataPacket
        /// packets are used to send application specific data to network peers.
        /// DataPacket packets can only exist in secure \see{Tunnel}s.
        /// This means that DataPacket packets have to come after all
        /// discovery (\see{InitiateDiscoveryPacket}, \see{BeaconPacket} and
        /// \see{PingPacket}) and after all handshake (\see{ClientHelloPacket},
        /// \see{ServerHelloPacket}, \see{ClientDeviceListPacket} and
        /// \see{ServerDeviceListPacket}) packets.

        struct _LIB_THEKOGANS_PACKET_DECL DataPacket : public packet::Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (DataPacket)

            /// \brief
            /// Peer id.
            std::string hostId;
            /// \brief
            /// For multi-chunk packets, will hold the chunk number.
            util::SizeT chunkNumber;
            /// \brief
            /// For multi-chunk packets, will hold the chunk count.
            util::SizeT chunkCount;
            /// \brief
            /// Buffer length.
            util::Buffer buffer;

            /// \brief
            /// ctor.
            /// \param[in] hostId_ Peer id.
            /// \param[in] chunkNumber_ For multi-chunk packets, will hold the chunk number.
            /// \param[in] chunkCount_ For multi-chunk packets, will hold the chunk count.
            /// \param[in] buffer_ Data buffer.
            DataPacket (
                const std::string &hostId_,
                std::size_t chunkNumber_,
                std::size_t chunkCount_,
                util::Buffer buffer_) :
                hostId (hostId_),
                chunkNumber (chunkNumber_),
                chunkCount (chunkCount_),
                buffer (std::move (buffer_)) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return
                    util::Serializer::Size (hostId) +
                    util::Serializer::Size (chunkNumber) +
                    util::Serializer::Size (chunkCount) +
                    util::Serializer::Size (buffer);
            }

            /// \brief
            /// Write the serializable from the given serializer.
            /// \param[in] header
            /// \param[in] serializer Serializer to read the serializable from.
            virtual void Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the serializable to the given serializer.
            /// \param[out] serializer Serializer to write the serializable to.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// Read a Serializable from an XML DOM.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write a Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const override;

            /// \brief
            /// DataPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (DataPacket)
        };

        /// \brief
        /// Implement DataPacket extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (DataPacket)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_DataPacket_h)
