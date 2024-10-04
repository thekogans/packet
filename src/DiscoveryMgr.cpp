// DiscoveryMgr.cpp - Marconi
//
// Created by Boris Kogan on 4/25/2016.
// Copyright (c) 2016 Logitech, Inc. All rights reserved.

#include <thekogans/util/GUID.h>
#include <thekogans/stream/AsyncIoEventQueue.h>
#include "logitech/marconi/Device.h"
#include "logitech/marconi/GlobalInfo.h"
#include "logitech/marconi/Discovery.h"
#include "logitech/marconi/Tunnel.h"
#include "logitech/marconi/DiscoveryMgr.h"

using namespace thekogans;

namespace logitech {
    namespace marconi {

        DiscoveryMgr::DiscoveryMgr () :
                jobQueue ("DiscoveryMgr") {
            for (util::ui32 i = 0; i < Discovery::LastDiscovery; ++i) {
                discoveries[i] = true;
            }
        }

        void DiscoveryMgr::Start (
                util::ui32 tries,
                util::TimeSpec timeSpec) {
            struct StartJob : public util::RunLoop::Job {
                util::ui32 tries;
                util::TimeSpec timeSpec;
                StartJob (
                    util::ui32 tries_,
                    const util::TimeSpec &timeSpec_) :
                    tries (tries_),
                    timeSpec (timeSpec_) {}
                virtual void Execute (const std::atomic<bool> &done) throw () {
                    if (!ShouldStop (done)) {
                        THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                            LOGITECH_MARCONI,
                            "Starting DiscoveryMgr on TCP port: %u.\n",
                            GlobalInfo::Instance ().discoveryMgrPort);
                        THEKOGANS_UTIL_TRY {
                            if (DiscoveryMgr::Instance ().serverTCPSocket.Get () == 0) {
                                DiscoveryMgr::Instance ().CreateListener ();
                                for (util::ui32 i = 0; !ShouldStop (done) && i < Discovery::LastDiscovery; ++i) {
                                    if (Discovery::discoveries[i] != 0) {
                                        Discovery::discoveries[i]->Start (tries, timeSpec);
                                    }
                                }
                            }
                        }
                        THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
                    }
                }
            };
            jobQueue.EnqJob (
                util::RunLoop::Job::SharedPtr (
                    new StartJob (tries, timeSpec)));
        }

        void DiscoveryMgr::Stop () {
            // Cancel all in flight discovery jobs.
            jobQueue.CancelAllJobs ();
            struct StopJob : public util::RunLoop::Job {
                virtual void Execute (const std::atomic<bool> &done) throw () {
                    if (!ShouldStop (done)) {
                        THEKOGANS_UTIL_TRY {
                            if (DiscoveryMgr::Instance ().serverTCPSocket.Get () != 0) {
                                for (util::ui32 i = 0; !ShouldStop (done) && i < Discovery::LastDiscovery; ++i) {
                                    if (Discovery::discoveries[i] != 0) {
                                        Discovery::discoveries[i]->Stop ();
                                    }
                                }
                                stream::GlobalAsyncIoEventQueue::Instance ().DeleteStream (
                                    *DiscoveryMgr::Instance ().serverTCPSocket);
                                DiscoveryMgr::Instance ().serverTCPSocket.Reset ();
                            }
                        }
                        THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
                    }
                }
            };
            jobQueue.EnqJob (util::RunLoop::Job::SharedPtr (new StopJob));
            jobQueue.WaitForIdle ();
        }

        void DiscoveryMgr::EnableDiscovery (
                util::ui32 discovery,
                bool enable,
                util::ui32 tries,
                util::TimeSpec timeSpec) {
            struct EnableDiscoveryJob : public util::RunLoop::Job {
                util::ui32 discovery;
                bool enable;
                util::ui32 tries;
                util::TimeSpec timeSpec;
                EnableDiscoveryJob (
                    util::ui32 discovery_,
                    bool enable_,
                    util::ui32 tries_,
                    const util::TimeSpec &timeSpec_) :
                    discovery (discovery_),
                    enable (enable_),
                    tries (tries_),
                    timeSpec (timeSpec_) {}
                virtual void Execute (const std::atomic<bool> & /*done*/) throw () {
                    THEKOGANS_UTIL_TRY {
                        if (discovery < Discovery::LastDiscovery) {
                            DiscoveryMgr::Instance ().discoveries[discovery] = enable;
                            if (!GlobalInfo::Instance ().discoveries[discovery]) {
                                GlobalInfo::Instance ().discoveries[discovery] = true;
                                Discovery::RegisterDiscovery (discovery);
                            }
                            THEKOGANS_UTIL_TRY {
                                if (DiscoveryMgr::Instance ().discoveries[discovery]) {
                                    Discovery::discoveries[discovery]->Start (tries, timeSpec);
                                }
                                else {
                                    Discovery::discoveries[discovery]->Stop ();
                                }
                            }
                            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
                        }
                        else {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                        }
                    }
                    THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
                }
            };
            jobQueue.EnqJob (
                util::RunLoop::Job::SharedPtr (
                    new EnableDiscoveryJob (
                        discovery, enable, tries, timeSpec)));
        }

        bool DiscoveryMgr::IsDiscoveryEnabled (util::ui32 discovery) {
            if (discovery < Discovery::LastDiscovery) {
                return GlobalInfo::Instance ().discoveries[discovery] && discoveries[discovery];
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::RunLoop::Job::SharedPtr DiscoveryMgr::InitiateDiscovery (
                Device &device,
                util::ui32 tries,
                const util::TimeSpec &timeSpec,
                bool force) {
            struct DiscoveryJob : public util::RunLoop::Job {
                Device::SharedPtr device;
                util::ui32 tries;
                util::TimeSpec timeSpec;
                bool force;
                DiscoveryJob (
                        Device &device_,
                        util::ui32 tries_,
                        const util::TimeSpec &timeSpec_,
                        bool force_) :
                        device (&device_),
                        tries (tries_),
                        timeSpec (timeSpec_),
                        force (force_) {
                    // This is a completely autonomous discovery
                    // job, and as such, it's lifetime needs to be
                    // well bound. I picked these values completely
                    // at random. Just something that felt reasonable
                    // to me.
                    const util::ui32 MIN_TRIES = 1;
                    const util::ui32 MAX_TRIES = 10;
                    tries = util::CLAMP (tries, MIN_TRIES, MAX_TRIES);
                    const util::TimeSpec MIN_WAIT_BETWEEN_TRIES = util::TimeSpec::FromSeconds (1);
                    const util::TimeSpec MAX_WAIT_BETWEEN_TRIES = util::TimeSpec::FromSeconds (10);
                    timeSpec = util::CLAMP (timeSpec, MIN_WAIT_BETWEEN_TRIES, MAX_WAIT_BETWEEN_TRIES);
                }
                virtual void Execute (const std::atomic<bool> &done) throw () {
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        LOGITECH_MARCONI,
                        "Discovery job execution started for device: (%u, %u, %u), force: %s, "
                        "%d methods available, %d tries spaced " THEKOGANS_UTIL_UI64_FORMAT " ms apart.\n",
                        device->GetId (),
                        device->GetSerialNumber (),
                        device->GetChannel (),
                        util::boolTostring (force).c_str (),
                        Discovery::LastDiscovery,
                        tries,
                        timeSpec.ToMilliseconds ());
                    // Notify event handlers discovery is about to begin.
                    device->Produce (
                        std::bind (
                            &DeviceEvents::OnDeviceBeginDiscovery,
                            std::placeholders::_1,
                            device,
                            force,
                            GetId ()));
                    while (!ShouldStop (done) && tries-- > 0) {
                        for (util::ui32 i = 0; !ShouldStop (done) && i < Discovery::LastDiscovery; ++i) {
                            if (DiscoveryMgr::Instance ().discoveries[i] && Discovery::discoveries[i] != 0 &&
                                    device->IsPeerEnabled (device->GetChannel ())) {
                                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                    LOGITECH_MARCONI,
                                    "Discovery method %s (%d) started for device: (%u, %u, %u), force: %s, %d tries remain\n",
                                    Discovery::discoveryNames[i],
                                    i,
                                    device->GetId (),
                                    device->GetSerialNumber (),
                                    device->GetChannel (),
                                    util::boolTostring (force).c_str (),
                                    tries);
                                THEKOGANS_UTIL_TRY {
                                    Discovery::discoveries[i]->InitiateDiscovery (*device, force);
                                }
                                THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
                                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                    LOGITECH_MARCONI,
                                    "Discovery method %s (%d) ended for device: (%u, %u, %u), force: %s, %d tries remain\n",
                                    Discovery::discoveryNames[i],
                                    i,
                                    device->GetId (),
                                    device->GetSerialNumber (),
                                    device->GetChannel (),
                                    util::boolTostring (force).c_str (),
                                    tries);
                            }
                            else {
                                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                                    LOGITECH_MARCONI,
                                        "Discovery method %s (%d) skipped for device: (%u, %u, %u).\n",
                                    Discovery::discoveryNames[i],
                                    i,
                                    device->GetId (),
                                    device->GetSerialNumber (),
                                    device->GetChannel ());
                            }
                        }
                        // If we were asked to try a few times,
                        if (!ShouldStop (done) && tries > 0) {
                            // sleep a while,
                            Sleep (timeSpec);
                        }
                        // and try again.
                    }
                    // Notify event handlers discovery has ended.
                    device->Produce (
                        std::bind (
                            &DeviceEvents::OnDeviceEndDiscovery,
                            std::placeholders::_1,
                            device,
                            force,
                            GetId ()));
                    THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                        LOGITECH_MARCONI,
                        "Discovery job execution finished for device: (%u, %u, %u).\n",
                        device->GetId (),
                        device->GetSerialNumber (),
                        device->GetChannel (),
                        Discovery::LastDiscovery);
                }
            };
            util::RunLoop::Job::SharedPtr job (
                new DiscoveryJob (device, tries, timeSpec, force));
            jobQueue.EnqJob (job);
            return job;
        }

        void DiscoveryMgr::CancelDiscovery () {
            // Cancel all in flight discovery jobs.
            jobQueue.CancelAllJobs ();
            jobQueue.WaitForIdle ();
        }

        bool DiscoveryMgr::WaitForDiscovery (
                thekogans::util::RunLoop::Job::SharedPtr discoveryJob,
                const thekogans::util::TimeSpec &timeSpec) {
            return jobQueue.WaitForJob (discoveryJob, timeSpec);
        }

        void DiscoveryMgr::CreateListener () {
            // Setup a secure tunnel listener.
            THEKOGANS_UTIL_TRY {
                serverTCPSocket.Reset (
                    new stream::ServerTCPSocket (
                        stream::Address::Any (
                            GlobalInfo::Instance ().discoveryMgrPort)));
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
            if (serverTCPSocket.Get () == 0) {
                // If we weren't able to bind, assume it's
                // because our choice of port is the problem.
                // Let the OS pick a free port for us and update
                // GlobalInfo so that PingPacket can use it to
                // notify it's peers.
                // NOTE: No catching here. If this fails,
                // DiscoveryMgr is unusable.
                serverTCPSocket.Reset (
                    new stream::ServerTCPSocket (
                        stream::Address::Any (0)));
                util::ui16 discoveryMgrPort = serverTCPSocket->GetHostAddress ().GetPort ();
                GlobalInfo::Instance ().SetDiscoveryMgrPort (discoveryMgrPort);
                THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                    LOGITECH_MARCONI,
                    "DiscoveryMgr ended up using port %d.\n",
                    discoveryMgrPort);
            }
            stream::GlobalAsyncIoEventQueue::Instance ().AddStream (*serverTCPSocket, *this);
        }

        void DiscoveryMgr::HandleStreamError (
                stream::Stream &stream,
                const util::Exception &exception) throw () {
            THEKOGANS_UTIL_LOG_SUBSYSTEM_EXCEPTION (LOGITECH_MARCONI, exception)
            struct CreateListenerJob : public util::RunLoop::Job {
                virtual void Execute (const std::atomic<bool> &done) throw () {
                    if (!ShouldStop (done)) {
                        THEKOGANS_UTIL_TRY {
                            stream::GlobalAsyncIoEventQueue::Instance ().DeleteStream (
                                *DiscoveryMgr::Instance ().serverTCPSocket);
                            DiscoveryMgr::Instance ().serverTCPSocket.Reset ();
                            DiscoveryMgr::Instance ().CreateListener ();
                        }
                        THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (LOGITECH_MARCONI)
                    }
                }
            };
            if (&stream == serverTCPSocket.Get ()) {
                jobQueue.EnqJob (util::RunLoop::Job::SharedPtr (new CreateListenerJob));
            }
        }

        stream::TCPSocket::SharedPtr DiscoveryMgr::GetTCPSocket (
                THEKOGANS_UTIL_HANDLE handle) {
            return stream::TCPSocket::SharedPtr (new Tunnel (handle));
        }

    } // namespace marconi
} // namespace logitech
