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

#if !defined (__thekogans_packet_DiscoveryMgr_h)
#define __thekogans_packet_DiscoveryMgr_h

#include <string>
#include <map>
#include <thekogans/util/Types.h>
#include <thekogans/util/Singleton.h>
#include <thekogans/util/SpinLock.h>
#include <thekogans/util/JobQueue.h>
#include <thekogans/util/TimeSpec.h>
#include <thekogans/stream/ServerTCPSocket.h>
#include <thekogans/stream/AsyncIoEventSink.h>
#include <thekogans/stream/ServerTCPSocket.h>
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Discovery.h"

namespace thekogans {
    namespace packet {

        struct Device;

        /// \struct DiscoveryMgr DiscoveryMgr.h thekogans/packet/DiscoveryMgr.h
        ///
        /// \brief
        /// DiscoveryMgr coordinates the \see{Device} peer network discovery process. To
        /// do this, it uses an array of registered \see{Discovery} instances.

        struct _LIB_THEKOGANS_PACKET_DECL DiscoveryMgr :
                public util::Singleton<DiscoveryMgr, util::SpinLock>,
                public stream::AsyncIoEventSink {
        private:
            /// \brief
            /// List of registered \see{Discovery} methods.
            bool discoveries[Discovery::LastDiscovery];
            /// \brief
            /// Used to listen for connection requests.
            stream::ServerTCPSocket::SharedPtr serverTCPSocket;
            /// \brief
            /// DiscoveryMgr job queue.
            util::JobQueue jobQueue;

        public:
            /// \brief
            /// ctor.
            DiscoveryMgr ();

            /// \brief
            /// Create the ServerTCPSocket and iterate over all registered
            /// \see{Discovery} instanes and call their Start.
            /// \param[in] tries Number of times to try to create the socket.
            /// \param[in] timeSpec Interval between attempts.
            void Start (
                util::ui32 tries = 10,
                util::TimeSpec timeSpec =
                    util::TimeSpec::FromSeconds (2));
            /// \brief
            /// Destroy the ServerTCPSocket and tell all \see{Discovery} instances
            /// to stop.
            void Stop ();

            /// \brief
            /// Enable or disable the given discovery method.
            /// \param[in] discovery \see{Discovey} method id.
            /// \param[in] enable true = enable, false = disable.
            /// \param[in] tries Number of times to try the discovery method before giving up.
            /// \param[in] timeSpec How long to wait between tries.
            void EnableDiscovery (
                util::ui32 discovery,
                bool enable,
                util::ui32 tries = 10,
                util::TimeSpec timeSpec =
                    util::TimeSpec::FromSeconds (2));
            /// \brief
            /// Return true if the given \see{Discovery} method is enabled.
            /// \return true = the given \see{Discovery} method is enabled.
            bool IsDiscoveryEnabled (util::ui32 discovery);

            enum {
                /// \brief
                /// Default number of discovery attempts.
                DEFAULT_DISCOVERY_TRIES = 3,
                /// \brief
                /// Default timeout (in seconds) between attempts.
                DEFAULT_DISCOVERY_TIMEOUT = 3
            };

            /// \brief
            /// Initiate discovery for a given device.
            /// \param[in] device \see{Device} for which to initiate discovery.
            /// \param[in] tries Number of times to try the discovery method before giving up.
            /// \param[in] timeSpec How long to wait between tries.
            /// \param[in] force true == Force peer rediscovery.
            /// \return A discovery job.
            util::RunLoop::Job::SharedPtr InitiateDiscovery (
                Device &device,
                util::ui32 tries = DEFAULT_DISCOVERY_TRIES,
                const util::TimeSpec &timeSpec =
                    util::TimeSpec::FromSeconds (DEFAULT_DISCOVERY_TIMEOUT),
                bool force = false);

            /// \brief
            /// Cancel all discovery jobs.
            void CancelDiscovery ();

            /// \brief
            /// Given a pending or running discovery job, wait for it to complete.
            /// \param[in] discoveryJob Pending or running discovery job.
            /// \param[in] timeSpec How long to wait for it to complete.
            /// \return true == Discovery job completed successfuly. false == discovery job was cancelled.
            bool WaitForDiscovery (
                util::RunLoop::Job::SharedPtr discoveryJob,
                const util::TimeSpec &timeSpec = util::TimeSpec::Infinite);

        private:
            /// \brief
            /// Create serverTCPSocket.
            void CreateListener ();

            // stream::AsyncIoEventSink
            /// Called to initiate stream error processing.
            /// \param[in] stream Stream on which an error occurred.
            /// \param[in] exception Exception representing the error.
            virtual void HandleStreamError (
                stream::Stream &stream,
                const util::Exception &exception) throw ();
            /// \brief
            /// Called to create a custom stream (\see{Tunnel}).
            /// \param[in] handle \see{Tunnel} handle.
            virtual stream::TCPSocket::SharedPtr GetTCPSocket (
                THEKOGANS_UTIL_HANDLE handle);

            /// \brief
            /// DiscoveryMgr is a singleton. It's neither copy constructable
            /// nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (DiscoveryMgr)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_DiscoveryMgr_h)
