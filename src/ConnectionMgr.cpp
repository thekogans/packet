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

#include <thekogans/util/LockGuard.h>
#include "thekogans/packet/ConnectionMgr.h"

namespace thekogans {
    namespace packet {

        Tunnel::SharedPtr ConnectionMgr::GetConnection (const std::string &hostId) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            ConnectionMap::iterator it = connectionMap.find (hostId);
            return it != connectionMap.end () ? it->second : Tunnel::SharedPtr ();
        }

        void ConnectionMgr::InitiateConnection (
                const std::string &hostId,
                const stream::Address &address) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            ConnectionMap::iterator it = connectionMap.find (hostId);
            if (it == connectionMap.end ()) {
                ConnectionMap::iterator it = pendingConnectionMap.find (hostId);
                if (it == pendingConnectionMap.end ()) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Initiating connection to %s.\n",
                        hostId.c_str ());
                    stream::TCPSocket::SharedPtr socket (new stream::TCPSocket);
                    util::Subscriber<stream::StreamEvents>::Subscribe (*socket);
                    util::Subscriber<stream::TCPSocketEvents>::Subscribe (*socket);
                    socket->Bind (stream::Address::Any);
                    socket->Connect (address);
                    pendingConnectionMap.insert (ConnectionMap::value_type (hostId, tunnel));
                    timer.Start (util::TimeSpec::FromSeconds (timerPeriod), true);
                }
                else {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "A pending connection to %s already exists.\n",
                        hostId.c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                    THEKOGANS_PACKET,
                    "A connection to %s already exists.\n",
                    hostId.c_str ());
            }
        }

        void ConnectionMgr::AddPendingConnection (Tunnel::SharedPtr tunnel) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            pendingConnectionList.push_back (tunnel);
            timer.Start (util::TimeSpec::FromSeconds (timerPeriod), true);
        }

        void ConnectionMgr::PromotePendingConnection (
                Tunnel &tunnel,
                bool initiator) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                THEKOGANS_PACKET,
                "Promoted pending connection, %s.\n",
                tunnel.GetConnectionString ().c_str ());
            connectionMap.insert (
                ConnectionMap::value_type (tunnel.hostId, Tunnel::SharedPtr (&tunnel)));
            if (initiator) {
                ConnectionMap::iterator it =
                    pendingConnectionMap.find (
                        GetKey (tunnel.hostId, tunnel.addressPair));
                if (it != pendingConnectionMap.end ()) {
                    pendingConnectionMap.erase (it);
                }
            }
            else {
                for (ConnectionList::iterator
                        it = pendingConnectionList.begin (),
                        end = pendingConnectionList.end (); it != end; ++it) {
                    if ((*it).Get () == &tunnel) {
                        pendingConnectionList.erase (it);
                        break;
                    }
                }
            }
            Produce (
                std::bind (
                    &ConnectionMgrEvents::OnConnectionMgrConnectionEstablished,
                    std::placeholders::_1,
                    Tunnel::SharedPtr (&tunnel),
                    initiator));
            timer.Start (util::TimeSpec::FromSeconds (timerPeriod), true);
        }

        void ConnectionMgr::ReapDeadConnection (Tunnel &tunnel) {
            {
                util::LockGuard<util::SpinLock> guard (spinLock);
                if (tunnel.hostId.empty ()) {
                    for (ConnectionList::iterator
                            it = pendingConnectionList.begin (),
                            end = pendingConnectionList.end (); it != end; ++it) {
                        if ((*it).Get () == &tunnel) {
                            THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                THEKOGANS_PACKET,
                                "Reaped dead pending connection: %s.\n",
                                tunnel.addressPair.first.AddrToString ().c_str ());
                            pendingConnectionList.erase (it);
                            break;
                        }
                    }
                }
                else {
                    ConnectionMap::iterator it = pendingConnectionMap.find (tunnel.hostId);
                    if (it != pendingConnectionMap.end ()) {
                        THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                            THEKOGANS_PACKET,
                            "Reaped dead pending connection: %s.\n",
                            key.c_str ());
                        pendingConnectionMap.erase (it);
                    }
                    else {
                        ConnectionMap::iterator it = connectionMap.find (tunnel.hostId);
                        if (it != connectionMap.end ()) {
                            THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                THEKOGANS_PACKET,
                                "Reaped dead connection: %s.\n",
                                tunnel.hostId.c_str ());
                            connectionMap.erase (it);
                        }
                    }
                }
                if (pendingConnectionMap.empty () &&
                        pendingConnectionList.empty () &&
                        connectionMap.empty ()) {
                    timer.Stop ();
                }
            }
            Produce (
                std::bind (
                    &ConnectionMgrEvents::OnConnectionMgrConnectionTerminated,
                    std::placeholders::_1,
                    tunnel.hostId,
                    tunnel.addressPair.first));
        }

        void ConnectionMgr::ReportConnectionError (
                Tunnel &tunnel,
                const util::Exception &exception) {
            Produce (
                std::bind (
                    &ConnectionMgrEvents::OnConnectionMgrConnectionError,
                    std::placeholders::_1,
                    Tunnel::SharedPtr (&tunnel),
                    exception));
        }

        void ConnectionMgr::ShutdownConnection (const std::string &hostId) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            ConnectionMap::iterator it = connectionMap.find (hostId);
            if (it != connectionMap.end ()) {
                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                    THEKOGANS_PACKET,
                    "Shutting down deviceless connection: %s.\n",
                    it->second->addressPair.first.AddrToString ().c_str ());
                it->second->Shutdown ();
            }
        }

        void ConnectionMgr::ReapStaleConnections (const stream::AdapterAddresses &addresses) {
            util::LockGuard<util::SpinLock> guard (spinLock);
            for (ConnectionMap::const_iterator
                     it = pendingConnectionMap.begin (),
                     end = pendingConnectionMap.end (); it != end; ++it) {
                if (addresses.Contains (it->second->GetHostAddress ())) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Shutting down stale pending connection: %s.\n",
                        it->first.c_str ());
                    it->second->Shutdown ();
                }
            }
            for (ConnectionList::const_iterator
                     it = pendingConnectionList.begin (),
                     end = pendingConnectionList.end (); it != end; ++it) {
                if (addresses.Contains ((*it)->GetHostAddress ())) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Shutting down stale pending connection: %s.\n",
                        (*it)->addressPair.first.AddrToString ().c_str ());
                    (*it)->Shutdown ();
                }
            }
            for (ConnectionMap::const_iterator
                     it = connectionMap.begin (),
                     end = connectionMap.end (); it != end; ++it) {
                if (addresses.Contains (it->second->GetHostAddress ())) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Shutting down stale connection: %s.\n",
                        it->second->hostId.c_str ());
                    it->second->Shutdown ();
                }
            }
            if (pendingConnectionMap.empty () &&
                    pendingConnectionList.empty () &&
                    connectionMap.empty ()) {
                timer.Stop ();
            }
        }

        void ConnectionMgr::Alarm (util::Timer & /*timer*/) throw () {
            time_t now = time (0);
            util::LockGuard<util::SpinLock> guard (spinLock);
            for (ConnectionMap::const_iterator
                    it = pendingConnectionMap.begin (),
                    end = pendingConnectionMap.end (); it != end; ++it) {
                if (now > it->second->epoch + maxPendingConnectionTime) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Shutting down idle pending connection: %s.\n",
                        it->first.c_str ());
                    // Calling Shutdown will trigger async EOF handling which
                    // will eventually wind up in Tunnel::HandleStreamDisconnect
                    // which will eventually call ReapDeadConnection.
                    it->second->Shutdown ();
                }
            }
            for (ConnectionList::const_iterator
                    it = pendingConnectionList.begin (),
                    end = pendingConnectionList.end (); it != end; ++it) {
                if (now > (*it)->epoch + maxPendingConnectionTime) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Shutting down idle pending connection: %s.\n",
                        (*it)->addressPair.first.AddrToString ().c_str ());
                    // Calling Shutdown will trigger async EOF handling which
                    // will eventually wind up in Tunnel::HandleStreamDisconnect
                    // which will eventually call ReapDeadConnection.
                    (*it)->Shutdown ();
                }
            }
        #if defined (THEKOGANS_PACKET_CONFIG_Release)
            for (ConnectionMap::const_iterator
                    it = connectionMap.begin (),
                    end = connectionMap.end (); it != end; ++it) {
                if (now > it->second->lastReceivedPacketTime + maxConnectionIdleTime * 2) {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        THEKOGANS_PACKET,
                        "Shutting down idle connection to: %s.\n",
                        it->second->hostId.c_str ());
                    // Calling Shutdown will trigger async EOF handling which
                    // will eventually wind up in Tunnel::HandleDisconnected
                    // which will eventually call ReapDeadConnection.
                    it->second->Shutdown ();
                }
                else if (now > it->second->lastSentPacketTime + maxConnectionIdleTime) {
                    THEKOGANS_UTIL_TRY {
                        // If we have a half open connection SendHeartbeat will fail
                        // and will trigger async error handling which will eventually
                        // wind up in Tunnel::HandleStreamError.
                        it->second->SendHeartbeat ();
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_PACKET)
                }
            }
        #endif // defined (THEKOGANS_PACKET_CONFIG_Release)
        }

        void ConnectionMgr::OnAdaptersAdapterAdded (
                const stream::AdapterAddresses &addresses) throw () {
            THEKOGANS_UTIL_LOG_SUBSYSTEM_INFO (
                THEKOGANS_PACKET,
                "Added adapter (%s, %u).\n",
                addresses.name.c_str (),
                addresses.index);
        }

        void ConnectionMgr::OnAdaptersAdapterDeleted (
                const stream::AdapterAddresses &addresses) throw () {
            THEKOGANS_UTIL_LOG_SUBSYSTEM_INFO (
                THEKOGANS_PACKET,
                "Deleted adapter (%s, %u).\n",
                addresses.name.c_str (),
                addresses.index);
            ReapStaleConnections (addresses);
        }

        void ConnectionMgr::OnAdaptersAdapterChanged (
                const stream::AdapterAddresses &oldAddresses,
                const stream::AdapterAddresses &newAddresses) throw () {
            THEKOGANS_UTIL_LOG_SUBSYSTEM_INFO (
                THEKOGANS_PACKET,
                "Adapter changed (%s, %u).\n",
                oldAddresses.name.c_str (),
                oldAddresses.index);
            ReapStaleConnections (oldAddresses);
        }

    } // namespace packet
} // namespace thekogans
