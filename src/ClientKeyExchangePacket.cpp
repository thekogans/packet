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

#include "thekogans/packet/ClientKeyExchangePacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (
            ClientKeyExchangePacket,
            1,
            util::SpinLock,
            8,
            util::DefaultAllocator::Global)

        void ClientKeyExchangePacket::Read (
                const Header & /*header*/,
                util::Serializer &serializer) {
            serializer >> publicKey;
        }

        void ClientKeyExchangePacket::Write (util::Serializer &serializer) const {
            serializer << *publicKey;
        }

    } // namespace packet
} // namespace thekogans
