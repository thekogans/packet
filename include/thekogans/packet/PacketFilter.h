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

#if !defined (__thekogans_packet_PacketFilter_h)
#define __thekogans_packet_PacketFilter_h

#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \brief
        /// Forward declaration of PacketFilter.
        struct PacketFilter;

        enum {
            /// \brief
            /// PacketFilterList list id.
            PACKET_FILTER_LIST_ID
        };

        /// \brief
        /// Convenient typedef for util::IntrusiveList<PacketFilter, PACKET_FILTER_LIST_ID>.
        typedef util::IntrusiveList<PacketFilter, PACKET_FILTER_LIST_ID> PacketFilterList;

    #if defined (_MSC_VER)
        #pragma warning (push)
        #pragma warning (disable : 4275)
    #endif // defined (_MSC_VER)

        /// \struct PacketFilter PacketFilter.h thekogans/packet/PacketFilter.h
        ///
        /// \brief
        /// PacketFilter is the base for all incoming and outgoing packet filters. You
        /// install packet filters in to \see{Tunnel} incoming and outging filter chains.

        struct _LIB_THEKOGANS_PACKET_DECL PacketFilter :
                public util::ThreadSafeRefCounted,
                public PacketFilterList::Node {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<PacketFilter>.
            typedef util::ThreadSafeRefCounted::Ptr<PacketFilter> Ptr;

            /// \brief
            /// dtor.
            virtual ~PacketFilter () {}

            /// \brief
            /// Filter the given packet. You can return one of the following;
            /// 1. The given packet (possibly modified) for further processing.
            /// 2. A new packet to stand in the given packets place.
            /// 3. Packet::Ptr (). This will stop all further processing of the
            ///    given packet.
            /// IMPORTANT: If after checking the packet type you realize that
            /// the given packet is not something you care about you should return
            /// CallNextPacketFilter to give downstream filters a chance at the
            /// packet.
            /// \param[in] packet \see{Packet} to filter.
            /// \return A filtered packet.
            virtual Packet::Ptr FilterPacket (Packet::Ptr /*packet*/) = 0;

        protected:
            /// \brief
            /// If there's a next packet filter, pass the packet to it,
            /// otherwise just return it unchanged.
            /// \param[in] packet \see{Packet} to pass to the next filter.
            /// \return Either the results of next packet filter (if there is one),
            /// or an unchanged packet.
            inline Packet::Ptr CallNextPacketFilter (Packet::Ptr packet) const {
                return next != 0 ? next->FilterPacket (packet) : packet;
            }
        };

    #if defined (_MSC_VER)
        #pragma warning (pop)
    #endif // defined (_MSC_VER)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PacketFilter_h)
