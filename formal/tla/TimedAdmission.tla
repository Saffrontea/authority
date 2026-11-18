--------------------------- MODULE TimedAdmission ---------------------------
EXTENDS PeerLifecycle
CONSTANTS TcpDecisions, TcpExpiries, TcpPorts
VARIABLES tcpConsumed, tcpActive, tcpPublished, tcpTombstones, tcpCompleted
tcpvars == <<tcpConsumed, tcpActive, tcpPublished, tcpTombstones, tcpCompleted>>
joint == <<vars, tcpvars>>
TcpLive(d) == now < TcpExpiries[d]
\* A notice covers the complete issued bundle even when it selects only TCP.
\* Its tombstone may outlive the TCP grant when the WG lease is longer.
TcpNoticeDeadline(d) == IF d \in Decisions
                       THEN IF Expiries[d] > TcpExpiries[d] THEN Expiries[d] ELSE TcpExpiries[d]
                       ELSE TcpExpiries[d]
DemoTcpExpiries == [d \in TcpDecisions |-> IF d = Early THEN 2 ELSE LateDeadline]
DemoTcpPorts == [d \in TcpDecisions |-> IF d = Early THEN {8080} ELSE {8081}]
InitTimed == /\ Init /\ tcpConsumed = {} /\ tcpActive = {}
             /\ tcpPublished = {} /\ tcpTombstones = {} /\ tcpCompleted = {}
PeerOnly(action) == action /\ UNCHANGED tcpvars
TimeStep == /\ Tick
            /\ tcpActive' = {d \in tcpActive: now' < TcpExpiries[d]}
            /\ UNCHANGED <<tcpConsumed, tcpPublished, tcpTombstones, tcpCompleted>>
Collect == /\ GC
           /\ tcpConsumed' = {d \in tcpConsumed: TcpLive(d)}
           /\ tcpTombstones' = {d \in tcpTombstones: now < TcpNoticeDeadline(d)}
           /\ UNCHANGED <<tcpActive, tcpPublished, tcpCompleted>>
Recover == /\ Restart /\ tcpActive' = {}
           /\ UNCHANGED <<tcpConsumed, tcpPublished, tcpTombstones, tcpCompleted>>
TcpApply(d) == /\ ready /\ TcpLive(d) /\ d \notin tcpConsumed /\ d \notin tcpTombstones
               /\ tcpConsumed' = tcpConsumed \cup {d} /\ tcpActive' = tcpActive \cup {d}
               /\ UNCHANGED <<vars, tcpPublished, tcpTombstones, tcpCompleted>>
TcpPublish(d) == /\ d \notin tcpPublished /\ tcpPublished' = tcpPublished \cup {d}
                 /\ UNCHANGED <<vars, tcpConsumed, tcpActive, tcpTombstones, tcpCompleted>>
TcpPersist(d) == /\ ready /\ d \in tcpPublished /\ now < TcpNoticeDeadline(d)
                 /\ tcpTombstones' = tcpTombstones \cup {d}
                 /\ UNCHANGED <<vars, tcpConsumed, tcpActive, tcpPublished, tcpCompleted>>
TcpComplete(d) == /\ ready /\ d \in tcpPublished /\ (d \in tcpTombstones \/ now >= TcpNoticeDeadline(d))
                  /\ tcpActive' = tcpActive \ {d} /\ tcpCompleted' = tcpCompleted \cup {d}
                  /\ UNCHANGED <<vars, tcpConsumed, tcpPublished, tcpTombstones>>
NextTimed == \/ PeerOnly(\E d \in Decisions: Apply(d) \/ Burn(d) \/ Publish(d) \/ Persist(d)
                                              \/ Complete(d) \/ Expire(d) \/ FailExpire(d))
             \/ PeerOnly(Crash) \/ TimeStep \/ Collect \/ Recover
             \/ \E d \in TcpDecisions: TcpApply(d) \/ TcpPublish(d) \/ TcpPersist(d) \/ TcpComplete(d)
TypeTimed == /\ TypeOK /\ tcpConsumed \subseteq TcpDecisions /\ tcpActive \subseteq TcpDecisions
             /\ tcpPublished \subseteq TcpDecisions /\ tcpTombstones \subseteq TcpDecisions
             /\ tcpCompleted \subseteq TcpDecisions
NoExpiredTcp == \A d \in tcpActive: TcpLive(d)
NoTcpResurrection == tcpActive \cap tcpCompleted = {}
TcpDurableWhileLive == \A d \in tcpCompleted: now < TcpNoticeDeadline(d) => d \in tcpTombstones
TcpAuthenticatedRevocations == tcpTombstones \subseteq tcpPublished
Admitted(port) == kernel # None /\ \E d \in tcpActive: port \in TcpPorts[d]
SpecTimed == InitTimed /\ [][NextTimed]_joint
=============================================================================
