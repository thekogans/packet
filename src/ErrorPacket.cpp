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

#include <pugixml.hpp>
#include "thekogans/packet/ErrorPacket.h"

using namespace thekogans;

namespace thekogans {
    namespace packet {

        THEKOGANS_PACKET_IMPLEMENT_PACKET (ErrorPacket)

        void ErrorPacket::Read (
                const PacketHeader & /*packetHeader*/,
                util::Buffer &buffer) {
            std::string exceptionString;
            buffer >> exceptionString;
            pugi::xml_document document;
            pugi::xml_parse_result result =
                document.load_buffer (exceptionString.c_str (), exceptionString.size ());
            if (result) {
                exception.Parse (document.document_element ());
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to parse:\n%s\n%s",
                    exceptionString.c_str (),
                    result.description ());
            }
        }

        void ErrorPacket::Write (util::Buffer &buffer) const {
            buffer << exception.ToString (0);
        }

    } // namespace packet
} // namespace thekogans
