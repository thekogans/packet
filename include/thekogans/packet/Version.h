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

#if !defined (__thekogans_packet_Version_h)
#define __thekogans_packet_Version_h

#include "thekogans/util/Version.h"
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \brief
        /// Return the compiled packet version.
        /// \return Compiled packet version.
        _LIB_THEKOGANS_PACKET_DECL const util::Version & _LIB_THEKOGANS_PACKET_API GetVersion ();

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_Version_h)
