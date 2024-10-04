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

#if !defined (__thekogans_packet_InitiateDiscoveryPacket_h)
#define __thekogans_packet_InitiateDiscoveryPacket_h

#include <string>
#include <thekogans/util/Serializer.h>
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct InitiateDiscoveryPacket InitiateDiscoveryPacket.h thekogans/packet/InitiateDiscoveryPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the initiate discovery packet.
        /// InitiateDiscoveryPacket packets are used by a master* host to
        /// alert all drones to initiate local sub-net peer discovery. Upon
        /// receipt of this packet, a drone will broadcast a \see{BeaconPacket}
        /// and wait for pings. Upon arrival of a ping (\see{PingPacket}), the
        /// drone will attempt to connect to it's peer using an ordinal based
        /// graph creation algorithm.
        /// * See \see{Device}'s implementation to learn that a master is a
        /// host where \see{Device::InitiateDiscovery} is called.

        struct _LIB_THEKOGANS_PACKET_DECL InitiateDiscoveryPacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (InitiateDiscoveryPacket)

            /// \brief
            /// Host id.
            std::string hostId;

            /// \brief
            /// ctor.
            /// \param[in] hostId_ Host id.
            InitiateDiscoveryPacket (const std::string &hostId_) :
                hostId (hostId_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return util::Serializer::Size (hostId);
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
            /// InitiateDiscoveryPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (InitiateDiscoveryPacket)
        };

        /// \brief
        /// Implement InitiateDiscoveryPacket extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (InitiateDiscoveryPacket)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_InitiateDiscoveryPacket_h)
