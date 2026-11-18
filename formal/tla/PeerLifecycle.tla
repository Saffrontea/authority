--------------------------- MODULE PeerLifecycle ---------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Decisions, None, Early, LateDeadline
Deadline(d) == IF d = Early THEN 2 ELSE LateDeadline
VARIABLES now, ready, kernel, registry, consumed, tombstones, published,
          completed, timers, badCleanup
vars == <<now, ready, kernel, registry, consumed, tombstones, published,
          completed, timers, badCleanup>>
Live(d) == now < Deadline(d)
Init == /\ now = 0 /\ ready = TRUE /\ kernel = None /\ registry = None
        /\ consumed = {} /\ tombstones = {} /\ published = {}
        /\ completed = {} /\ timers = {} /\ badCleanup = FALSE

\* One peer key can be replaced by another immutable decision. The real
\* policy mutex spans the tombstone check, consumption, kernel set and registry.
Apply(d) == /\ ready /\ Live(d) /\ d \notin consumed /\ d \notin tombstones
            /\ consumed' = consumed \cup {d}
            /\ kernel' = d /\ registry' = d /\ timers' = timers \cup {d}
            /\ UNCHANGED <<now, ready, tombstones, published, completed, badCleanup>>
\* An unsuccessful install may burn a nonce, without changing kernel state.
Burn(d) == /\ ready /\ Live(d) /\ d \notin consumed /\ d \notin tombstones
           /\ consumed' = consumed \cup {d}
           /\ UNCHANGED <<now, ready, kernel, registry, tombstones, published,
                          completed, timers, badCleanup>>
Publish(d) == /\ d \notin published /\ published' = published \cup {d}
              /\ UNCHANGED <<now, ready, kernel, registry, consumed, tombstones,
                             completed, timers, badCleanup>>
Persist(d) == /\ ready /\ d \in published /\ Live(d)
              /\ tombstones' = tombstones \cup {d}
              /\ UNCHANGED <<now, ready, kernel, registry, consumed, published,
                             completed, timers, badCleanup>>
Complete(d) == /\ ready /\ d \in published
               /\ (d \in tombstones \/ ~Live(d))
               /\ kernel' = IF registry = d THEN None ELSE kernel
               /\ registry' = IF registry = d THEN None ELSE registry
               /\ completed' = completed \cup {d}
               /\ UNCHANGED <<now, ready, consumed, tombstones, published, timers, badCleanup>>

\* Cleanup succeeds atomically under the same mutex as Apply. Failed kernel
\* operations stutter and retain registry/timer for retry. A stale timer must
\* not remove a replacement, including when both decisions share a deadline.
Expire(d) == /\ ready /\ d \in timers /\ ~Live(d)
             /\ kernel' = IF registry = d THEN None ELSE kernel
             /\ registry' = IF registry = d THEN None ELSE registry
             /\ badCleanup' = badCleanup \/ (registry # d /\ kernel' # kernel)
             /\ timers' = timers \ {d}
             /\ UNCHANGED <<now, ready, consumed, tombstones, published, completed>>
\* A failed external command keeps the installed peer tracked. This explicit
\* stuttering action lets mutation checks reject losing the retry obligation.
FailExpire(d) == /\ ready /\ d \in timers /\ ~Live(d) /\ registry = d
                 /\ UNCHANGED vars
Tick == /\ now < 3 /\ now' = now + 1
        /\ UNCHANGED <<ready, kernel, registry, consumed, tombstones, published,
                       completed, timers, badCleanup>>
GC == /\ consumed' = {d \in consumed: Live(d)}
      /\ tombstones' = {d \in tombstones: Live(d)}
      /\ UNCHANGED <<now, ready, kernel, registry, published, completed, timers, badCleanup>>
Crash == /\ ready /\ ready' = FALSE /\ registry' = None /\ timers' = {}
         /\ UNCHANGED <<now, kernel, consumed, tombstones, published, completed, badCleanup>>
\* Both WG peers and the owned nft table are cleared before the HTTP listener
\* starts. A failed startup cleanup leaves the receiver unavailable.
Restart == /\ ~ready /\ ready' = TRUE /\ kernel' = None
           /\ UNCHANGED <<now, registry, consumed, tombstones, published, completed, timers, badCleanup>>
Next == \/ \E d \in Decisions: Apply(d) \/ Burn(d) \/ Publish(d) \/ Persist(d)
                                   \/ Complete(d) \/ Expire(d) \/ FailExpire(d)
        \/ Tick \/ GC \/ Crash \/ Restart
TypeOK == /\ now \in 0..3 /\ ready \in BOOLEAN
          /\ kernel \in Decisions \cup {None} /\ registry \in Decisions \cup {None}
          /\ consumed \subseteq Decisions /\ tombstones \subseteq Decisions
          /\ published \subseteq Decisions /\ completed \subseteq Decisions
          /\ timers \subseteq Decisions /\ badCleanup \in BOOLEAN
RegistryTracksKernel == ready => registry = kernel
NoCrossDecisionCleanup == ~badCleanup
NoResurrection == kernel \notin completed
DurableWhileLive == \A d \in completed: Live(d) => d \in tombstones
Spec == Init /\ [][Next]_vars
\* Conditional progress: logical time advances, failed receivers eventually
\* restart, and an enabled expiry cleanup eventually succeeds. No bound on
\* failures, scheduler delay or packet delivery follows from these assumptions.
SpecFair == Spec /\ WF_vars(Tick) /\ WF_vars(Restart)
                 /\ \A d \in Decisions: WF_vars(Expire(d))
EventuallyExpiredPeerRemoved == <> (now = 3 /\ kernel = None)
=============================================================================
