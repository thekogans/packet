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

#if !defined (__thekogans_packet_ConnectionMgr_h)
#define __thekogans_packet_ConnectionMgr_h

#include <ctime>
#include <string>
#include <list>
#include <map>
#include <thekogans/util/Singleton.h>
#include <thekogans/util/SpinLock.h>
#include <thekogans/util/Timer.h>
#include <thekogans/util/Subscriber.h>
#include <thekogans/util/Producer.h>
#include <thekogans/crypto/Cipher.h>
#include <thekogans/stream/Adapters.h>
#include <thekogans/stream/Address.h>
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Tunnel.h"

namespace thekogans {
    namespace packet {

        /// \struct ConnectionMgrEvents ConnectionMgr.h thekogans/packet/ConnectionMgr.h
        ///
        /// \brief
        /// Provides async event notifications to interested listeners (\see{Device}).
        /// If you're interested in ConnectionMgr events, derive form this class
        /// like this; public util::Subscriber<ConnectionMgrEvents> and
        /// call util::Subscriber<ConnectionMgrEvents>::Subscribe (
        /// ConnectionMgr::Instance ()).

        struct _LIB_THEKOGANS_PACKET_DECL ConnectionMgrEvents {
            /// \brief
            /// An error was reported by a connection (\see{Tunnel}).
            /// \param[in] tunnel Connection on which the error occurred.
            /// \param[in] exception The error.
            virtual void OnConnectionMgrConnectionError (
                Tunnel::SharedPtr tunnel,
                const util::Exception &exception) throw () {}
            /// \brief
            /// Connection (including the handshake) has been established. The tunnel is
            /// secure and it's now safe to start sending data through it.
            /// \param[in] tunnel Tunnel that established the connection.
            /// \param[in] initiator true = connection initiator.
            virtual void OnConnectionMgrConnectionEstablished (
                Tunnel::SharedPtr tunnel,
                bool initiator) throw () {}
            /// \brief
            /// Connection has been terminated.
            /// \param[in] hostId Host id of the tunnel that terminated the connection.
            /// \param[in] address Address of the tunnel that terminated the connection.
            virtual void OnConnectionMgrConnectionTerminated (
                const std::string &hostId,
                const stream::Address &address) throw () {}
        };

        /// \struct ConnectionMgr ConnectionMgr.h thekogans/packet/ConnectionMgr.h
        ///
        /// \brief
        /// Maintains a map of all peer connections (see \see{Tunnel}). Providing
        /// central point of access to all clients that use them.

        struct _LIB_THEKOGANS_PACKET_DECL ConnectionMgr :
                public util::RefCountedSingleton<ConnectionMgr>,
                public util::Subscriber<util::TimerEvents>,
                public util::Subscriber<stream::AdaptersEvents>,
                public util::Subscriber<stream::StreamEvents>,
                public util::Producer<ConnectionMgrEvents> {
            /// \brief
            /// Declare \see{util::RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (ConnectionMgr)

            /// \brief
            /// Convenient typedef for std::list<Tunnel::SharedPtr>.
            typedef std::list<Tunnel::SharedPtr> ConnectionList;

        private:
            enum {
                /// \brief
                /// Default timer period.
                DEFAULT_TIMER_PERIOD = 5,
                /// \brief
                /// Default max pending connection time.
                DEFAULT_MAX_PENDING_CONNECTION_TIME = 25,
                /// \brief
                /// Default max connection idle time.
                DEFAULT_MAX_CONNECTION_IDLE_TIME = 10
            };
            /// \brief
            /// Timer period.
            time_t timerPeriod;
            /// \brief
            /// Max pending connection time.
            time_t maxPendingConnectionTime;
            /// \brief
            /// Max connection idle time.
            time_t maxConnectionIdleTime;
            /// \brief
            /// Convenient typedef for std::map<std::string, Tunnel::SharedPtr>.
            typedef std::map<std::string, Tunnel::SharedPtr> ConnectionMap;
            /// \brief
            /// Initiated pending connections map.
            ConnectionMap pendingConnectionMap;
            /// \brief
            /// Received pending connections list.
            ConnectionList pendingConnectionList;
            /// \brief
            /// Active connections map.
            ConnectionMap connectionMap;
            /// \brief
            /// ConnectionMgr is a \see{util::Singleton}
            /// and access to it's members must be protected.
            util::SpinLock spinLock;
            /// \brief
            /// Used to reap dead pending connections and to probe idle
            /// connections for health (send \see{HeartbeatPacket}).
            util::Timer::SharedPtr timer;

        public:
            /// \brief
            /// ctor.
            ConnectionMgr () :
                    timerPeriod (DEFAULT_TIMER_PERIOD),
                    maxPendingConnectionTime (DEFAULT_MAX_PENDING_CONNECTION_TIME),
                    maxConnectionIdleTime (DEFAULT_MAX_CONNECTION_IDLE_TIME),
                    timer (util::Timer::Create ("ConnectionMgr")) {
                util::Subscriber<util::TimerEvents>::Subscribe (timer);
                util::Subscriber<stream::AdaptersEvents>::Subscribe (
                    stream::Adapters::Instance ());
            }

            /// \brief
            /// Given a host id, return the corresponding connection.
            /// \param[in] hostId Host id.
            /// \return Connection corresponding to the given host id.
            Tunnel::SharedPtr GetConnection (const std::string &hostId);

        private:
            /// \brief
            /// Initiate a connection to a given host.
            /// \param[in] hostId Host id.
            /// \param[in] addressPair Host addresses (from, to).
            /// \param[in] deviceId \see{Device} id on whose behalf
            /// we're initiating the connection.
            /// \param[in] deviceSerialNumber \see{Device} serial number
            /// on whose behalf we're initiating the connection.
            void InitiateConnection (
                const std::string &hostId,
                const Tunnel::PeerHostAddressPair &addressPair,
                util::ui32 deviceId,
                util::ui32 deviceSerialNumber);
            /// \brief
            /// Add a pending connection to the PendingConnectionList.
            /// \param[in] tunnel Pending connection.
            void AddPendingConnection (Tunnel &tunnel);
            /// \brief
            /// Promote a given pending connection to full connection status.
            /// \param[in] tunnel Pending connection.
            /// \param[in] initiator true = connection initiator.
            void PromotePendingConnection (
                Tunnel &tunnel,
                bool initiator);
            /// \brief
            /// Delete a dead (pending) connection.
            /// \param[in] tunnel Dead (pending) connection.
            void ReapDeadConnection (Tunnel &tunnel);

            /// \brief
            /// Notify event handlers that a connection error occurred.
            /// \param[in] tunnel (Pending) connection.
            /// \param[in] exception The error.
            void ReportConnectionError (
                Tunnel &tunnel,
                const util::Exception &exception);

            /// \brief
            /// Called by adapter change handlers to remove stale connections.
            /// \param[in] addresses Adapter that has gone stale.
            void ReapStaleConnections (
                const stream::AdapterAddresses &addresses);
            /// \brief
            /// Check the \see{Tunnel} with the given hostId and if
            /// all it has is a device with the given id and serial
            /// number, shut it down.
            void ShutdownConnection (const std::string &hostId);

            // util::TimerEvents
            /// \brief
            /// Timer callback to reap dead pending connections.
            /// \param[in] timer The expired timer.
            virtual void OnTimerAlarm (
                RefCounted::SharedPtr<Timer> /*timer*/) throw () override;

            // stream::AdaptersEvents
            /// \brief
            /// Called when a new adapter was added to the network.
            /// \param[in] addresses New adapter addresses.
            virtual void OnAdaptersAdapterAdded (
                const stream::AdapterAddresses &addresses) throw () override;
            /// \brief
            /// Called when an existing adapter was removed from the network.
            /// \param[in] addresses Deleted adapter addresses.
            virtual void OnAdaptersAdapterDeleted (
                const stream::AdapterAddresses &addresses) throw () override;
            /// \brief
            /// Called when an existing adapter was modified.
            /// \param[in] oldAddresses Old adapter addresses.
            /// \param[in] newAddresses New adapter addresses.
            virtual void OnAdaptersAdapterChanged (
                const stream::AdapterAddresses &oldAddresses,
                const stream::AdapterAddresses &newAddresses) throw () override;

            /// \brief
            /// Called to handle Tunnel errors.
            /// \param[in] stream Tunnel that erred.
            virtual void OnStreamError (
                stream::Stream::SharedPtr stream,
                const util::Exception &exception) throw () override;
            /// \brief
            /// Called to inform that an existing Tunnel has disconnected.
            /// \param[in] stream Tunnel that disconnected..
            virtual void OnStreamDisconnect (
                stream::Stream::SharedPtr stream) throw () override;

            friend struct Tunnel;
        #if defined (THEKOGANS_PACKET_HAVE_BROADCAST_DISCOVERY)
            friend struct BroadcastDiscovery;
        #endif // defined (THEKOGANS_PACKET_HAVE_BROADCAST_DISCOVERY)
        #if defined (THEKOGANS_PACKET_HAVE_NODE_STORE_DISCOVERY)
            friend struct NodeStoreDiscovery;
        #endif // defined (THEKOGANS_PACKET_HAVE_NODE_STORE_DISCOVERY)

            /// \brief
            /// ConnectionMgr is a singleton. It's neither copy constructable
            /// nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (ConnectionMgr)
        };

    #if defined (_MSC_VER)
        #pragma warning (pop)
    #endif // defined (_MSC_VER)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ConnectionMgr_h)
