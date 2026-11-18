--------------------------- MODULE Revocation ---------------------------
EXTENDS FiniteSets

CONSTANTS Decisions, Adapters
Pairs == Decisions \X Adapters

\* One pair is one authenticated, unexpired decision/adapter binding. There is
\* no global sequence watermark: delivering a newer notice cannot hide an older
\* notice for another decision or adapter. Signed notices are durable at source.
VARIABLES published, tombstones, active, consumed, acknowledged, completed
vars == <<published, tombstones, active, consumed, acknowledged, completed>>

Init == /\ published = {}
        /\ tombstones = {}
        /\ active = {}
        /\ consumed = {}
        /\ acknowledged = {}
        /\ completed = {}

Publish(p) == /\ p \notin published
              /\ published' = published \cup {p}
              /\ UNCHANGED <<tombstones, active, consumed, acknowledged, completed>>

\* Consumption is durable before adapter installation. A failed install burns
\* the grant, which is safe but may sacrifice availability.
Consume(p) == /\ p \notin consumed
              /\ p \notin tombstones
              /\ consumed' = consumed \cup {p}
              /\ UNCHANGED <<published, tombstones, active, acknowledged, completed>>
Install(p) == /\ p \in consumed
              /\ p \notin tombstones
              /\ p \notin active
              /\ active' = active \cup {p}
              /\ UNCHANGED <<published, tombstones, consumed, acknowledged, completed>>

\* The receiver persists its adapter-specific tombstone before kernel cleanup.
\* Retrying a notice already persisted MUST still run cleanup.
Persist(p) == /\ p \in published
              /\ p \notin tombstones
              /\ tombstones' = tombstones \cup {p}
              /\ UNCHANGED <<published, active, consumed, acknowledged, completed>>
Complete(p) == /\ p \in published \cap tombstones
               /\ p \notin acknowledged
               /\ active' = active \ {p}
               /\ acknowledged' = acknowledged \cup {p}
               /\ completed' = completed \cup {p}
               /\ UNCHANGED <<published, tombstones, consumed>>

\* HTTP failure, packet loss, duplicates and kernel failures are stuttering
\* steps. A dispatcher restart loses only its delivery cache, not durable state.
DispatcherRestart == /\ acknowledged # {}
                     /\ acknowledged' = {}
                     /\ UNCHANGED <<published, tombstones, active, consumed, completed>>

\* A receiver restart clears installed state before becoming ready. Durable
\* consume/tombstone records survive. Installation remains an overapproximation:
\* the actual receiver additionally rejects reuse of already consumed nonces.
ReceiverRestart == /\ active # {}
                   /\ active' = {}
                   /\ UNCHANGED <<published, tombstones, consumed, acknowledged, completed>>

Next == \/ \E p \in Pairs: Publish(p) \/ Consume(p) \/ Install(p) \/ Persist(p) \/ Complete(p)
        \/ DispatcherRestart \/ ReceiverRestart

TypeOK == /\ published \subseteq Pairs /\ tombstones \subseteq Pairs
          /\ active \subseteq Pairs /\ consumed \subseteq Pairs
          /\ acknowledged \subseteq Pairs /\ completed \subseteq Pairs
DurableBeforeAck == acknowledged \subseteq tombstones
NoResurrection == active \cap completed = {}
AuthenticatedRevocations == tombstones \subseteq published
InstalledWasConsumed == active \subseteq consumed

\* Liveness is conditional: each live notice is eventually delivered and its
\* cleanup eventually succeeds. No finite delivery bound or network fairness is
\* inferred from safety. Expiry and pending cleanup across crash are in the
\* separate peer lifecycle model.
Spec == Init /\ [][Next]_vars
        /\ \A p \in Pairs: WF_vars(Persist(p)) /\ WF_vars(Complete(p))
EventuallyRevoked == \A p \in Pairs: (p \in published) ~> (p \in completed)
=============================================================================
