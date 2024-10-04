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

#if !defined (__thekogans_packet_PingPacket_h)
#define __thekogans_packet_PingPacket_h

#include <string>
#include "thekogans/util/Serializer.h"
#include "thekogans/util/GUID.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct PingPacket PingPacket.h thekogans/packet/PingPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the ping packet. PingPacket packets
        /// are unicast by peers back to their origin to respond to \see{BeaconPacket}
        /// packet broadcasts. Upon receipt of the PingPacket packet, a peer will
        /// attempt (using an ordinal based graph creation algorithm) to establish
        /// a secure \see{Tunnel} for data transfers. See \see{InitiateDiscoveryPacket}
        /// and \see{Device} implementation to learn more.

        struct _LIB_THEKOGANS_PACKET_DECL PingPacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (PingPacket)

            /// \brief
            /// Host id.
            std::string hostId;
            /// \brief
            /// Port the host is listening on for connections.
            util::ui16 port;

            /// \brief
            /// ctor.
            /// \param[in] hostId_ Peer host id.
            /// \param[in] port_ Port used to connect to the discovered peer.
            PingPacket (
                const std::string &hostId_,
                util::ui16 port_) :
                hostId (hostId_),
                port (port_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return
                    util::Serializer::Size (hostId) +
                    util::Serializer::Size (port);
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
            /// PingPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (PingPacket)
        };

        /// \brief
        /// Implement PingPacket extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (PingPacket)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PingPacket_h)
