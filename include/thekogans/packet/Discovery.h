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

#if !defined (__thekogans_packet_Discovery_h)
#define __thekogans_packet_Discovery_h

#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct Discovery Discovery.h thekogans/packet/Discovery.h
        ///
        /// \brief
        /// Base class for all discovery methods. Defines the basic API all
        /// discovery methods must implement.

        struct _LIB_THEKOGANS_PACKET_DECL Discovery {
            /// \brief
            /// dtor.
            virtual ~Discovery () {}

            /// \brief
            /// Start listening for peers.
            virtual void Start () = 0;
            /// \brief
            /// Stop listening for peers.
            virtual void Stop () = 0;

            /// \brief
            /// Initiate peer discovery.
            virtual void InitiateDiscovery () = 0;
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_Discovery_h)
