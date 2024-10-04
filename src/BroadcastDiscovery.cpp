// Copyright 2011 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_util.
//
// libthekogans_util is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_util is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_util. If not, see <http://www.gnu.org/licenses/>.

#include <thekogans/util/LockGuard.h>
#include "thekogans/packet/InitiateDiscoveryPacket.h"
#include "thekogans/packet/BeaconPacket.h"
#include "thekogans/packet/PingPacket.h"
#include "thekogans/packet/BroadcastDiscovery.h"

namespace thekogans {
    namespace packet {

        void BroadcastDiscovery::Start (util::ui16 port) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (discoverySocket == nullptr) {
                discoverySocket.Reset (new stream::UDPSocket);
                util::Subscriber<stream::UDPSocketEvents>::Subscribe (*discoverySocket);
                discoverySocket->SetBroadcast (true);
                discoverySocket->SetRecvPktInfo (true);
                discoverySocket->Bind (stream::Address::Any (port));
                discoverySocket->ReadMsg (Options::Instance ()->blockSize);
            }
        }

        void BroadcastDiscovery::Stop () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (discoverySocket != nullptr) {
                util::Subscriber<stream::UDPSocketEvents>::Unsubscribe (*discoverySocket);
                discoverySocket.Reset ();
            }
        }

        namespace {
            void BroadcastPacket (
                    stream::UDPSocket::SharedPtr udpSocket,
                    util::Buffer::SharedPtr buffer) {
                stream::AdapterAddressesList addressesList =
                    stream::Adapters::Instance ().GetAddressesList ();
                for (stream::AdapterAddressesList::iterator
                        it = addressesList.begin (),
                        end = addressesList.end (); it != end; ++it) {
                    for (stream::AdapterAddresses::IPV4Addresses::iterator
                            jt = (*it).ipv4.begin (),
                            end = (*it).ipv4.end (); jt != end; ++jt) {
                        if ((*jt).broadcast != stream::Address::Empty) {
                            udpSocket->WriteTo (
                                buffer->GetReadPtr (),
                                buffer->GetDataAvailableForReading (),
                                stream::Address (port, (*jt).broadcast.GetAddr ()));
                            break;
                        }
                    }
                }
            }
        }

        void BroadcastDiscovery::InitiateDiscovery (crypto::Cipher::SharedPtr cipher) {
            BroadcastPacket (
                discoverySocket,
                InitiateDiscoveryPacket (
                    util::SystemInfo::Instance ().GetHostName ()).Serialize (cipher, 0));
        }

        void BroadcastDiscovery::OnUDPSocketReadMsg (
                stream::UDPSocket::SharedPtr udpSocket,
                util::Buffer::SharedPtr buffer,
                const stream::Address &from,
                const stream::Address &to) throw () {
            jobQueue.EnqJob (
                [udpSocket, buffer, from, to] (
                        const RunLoop::Job & /*job*/,
                        const std::atomic<bool> & /*done*/) {
                    crypto::FrameHeader frameHeader;
                    *buffer >> frameHeader;
                    crypto::Cipher::SharedPtr cipher = keyRing->GetCipher (frameHeader.keyId);
                    if (cipher != nullptr) {
                        packet::Packet::SharedPtr packet =
                            packet::Packet::Deserialize (*buffer, *cipher, 0);
                        if (packet != nullptr) {
                            if (packet->Type () == InitiateDiscoveryPacket::TYPE) {
                                BroadcastPacket (
                                    udpSocket,
                                    BeaconPacket (
                                        util::SystemInfo::Instance ()->GetHostName ()).Serialize (
                                            cipher, 0));
                            }
                            else if (packet->Type () == BeaconPacket::TYPE) {
                                BeaconPacket *beacon =
                                    static_cast<BeaconPacket *> (packet.Get ());
                                if (beacon->hostId != util::SystemInfo::Instance ()->GetHostName ()) {
                                    udpSocket->WriteTo (
                                        PingPacket (
                                            util::SystemInfo::Instance ()->GetHostName ()).Serialize (
                                                cipher, 0),
                                        from);
                                }
                            }
                            else if (packet->Type () == PingPacket::TYPE) {
                                PingPacket *ping = static_cast<PingPacket *> (packet.Get ());
                                BroadcastDiscovery::Instance ()->Produce (
                                    std::bind (
                                        &DiscoveryEvents::OnDiscoveryPeerDiscovered,
                                        std::placeholders::_1,
                                        ping.hostId,
                                        ping.port,
                                        from));
                            }
                        }
                    }
                }
            );
        }

    } // namespace packet
} // namespace thekogans
