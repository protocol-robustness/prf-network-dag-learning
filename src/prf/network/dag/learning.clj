(ns prf.network.dag.learning
  "Executable teaching example: a portable network-scoped evidence DAG packet.

   This is a local verification model, not a transport or consensus protocol."
  (:require [clojure.set :as cset]
            [resolver-sim.evidence.attestation :as att]
            [resolver-sim.evidence.attestation-dag :as att-dag]
            [resolver-sim.evidence.node :as node]
            [resolver-sim.evidence.reachability :as reach]
            [resolver-sim.hash.canonical :as canonical]))

(def graph-domain "prf-learning-network-evidence-graph.v1")

(defn- canonical-safe [value]
  (cond
    (map? value) (into (empty value) (map (fn [[k v]] [k (canonical-safe v)]) value))
    (set? value) (->> value (map canonical-safe) (sort-by pr-str) vec)
    (sequential? value) (mapv canonical-safe value)
    :else value))

(defn- content-root [domain value]
  (str "sha256:" (canonical/domain-hash domain (canonical-safe value))))

(defn network-context
  "Build the immutable identity and policy context shared by packet nodes."
  []
  (let [body {:schema "prf-learning-network-context.v1"
              :network-id "urn:prf-learning:researchers"
              :membership {:schema "prf-learning-membership.v1"
                           :members ["researcher:ada" "researcher:grace" "researcher:lin"]}
              :policy {:schema "prf-learning-ratification-policy.v1"
                       :eligible-count 3 :approval-threshold 2
                       :dissent-preserved? true}}]
    (assoc body :network/root (content-root "prf-learning-network-context.v1" body))))

(defn- attestation-node [context actor subject claim timestamp parents]
  (let [a (att/build-attestation actor subject claim {:signed-at timestamp})]
    (att-dag/build-attestation-dag-node
     a {:parent-hashes (vec parents)
        :timestamp timestamp
        :extensions {:learning/network-root (:network/root context)
                     :learning/network-id (:network-id context)}})))

(defn example-packet
  "Create a deterministic example with an approval branch and an explicit dissent.

   The shared question and evidence basis is the fork point. Ada and Grace approve;
   Lin records dissent. All three nodes point to the same basis node."
  []
  (let [context (network-context)
        subject {:type :claim :claim-id "claim:reachability-is-not-ratification"}
        basis (attestation-node context {:type :researcher :id "researcher:ada"} subject :verified
                                "2026-01-01T00:00:00Z" [])
        basis-hash (:node-hash basis)
        ada (attestation-node context {:type :researcher :id "researcher:ada"} subject :approved
                              "2026-01-02T00:00:00Z" [basis-hash])
        grace (attestation-node context {:type :researcher :id "researcher:grace"} subject :approved
                                "2026-01-02T01:00:00Z" [basis-hash])
        lin (attestation-node context {:type :researcher :id "researcher:lin"} subject :rejected
                              "2026-01-02T02:00:00Z" [basis-hash])
        nodes [basis ada grace lin]
        body {:schema "prf-learning-network-evidence-graph.v1"
              :network context
              :subject subject
              :nodes nodes
              :heads (mapv :node-hash (rest nodes))}]
    (assoc body :graph/root (content-root graph-domain (dissoc body :graph/root)))))

(defn verify-packet
  "Independently verify context binding, each PRF node and graph root.

   `expected-network-root` represents the replica's locally trusted network
   context. It is not learned from the packet being checked."
  [packet expected-network-root]
  (let [context (:network packet)
        nodes (:nodes packet)
        errors (cond-> []
                 (not= "prf-learning-network-evidence-graph.v1" (:schema packet))
                 (conj :graph/unsupported-schema)
                 (not= expected-network-root (:network/root context))
                 (conj :network/untrusted-context)
                 (not (every? #(= expected-network-root
                                  (get-in % [:extensions :learning/network-root])) nodes))
                 (conj :node/network-binding-mismatch)
                 (not= (:graph/root packet)
                       (content-root graph-domain (dissoc packet :graph/root)))
                 (conj :graph/root-mismatch))
        dag-check (node/validate-node-dag nodes :strict-dag? true)
        graph {:dag/nodes (mapv #(hash-map :node/id (:node-hash %)) nodes)
               :dag/edges (vec (mapcat (fn [n]
                                        (map #(hash-map :edge/from % :edge/to (:node-hash n))
                                             (:parent-hashes n))) nodes))}
        dag-errors (reach/dag-structural-errors graph)
        node-hashes (set (map :node-hash nodes))
        derived-heads (set (remove (set (map :edge/from (:dag/edges graph)))
                                   (map :node/id (:dag/nodes graph))))
        supplied-heads (set (:heads packet))
        all-errors (vec (concat errors
                                (when-not (:valid? dag-check) [:dag/prf-node-validation-failed])
                                (when (seq dag-errors) [:dag/invalid-network-edges])
                                (when (or (empty? supplied-heads)
                                          (not= (count supplied-heads) (count (:heads packet)))
                                          (not (cset/subset? supplied-heads node-hashes)))
                                  [:graph/invalid-heads])
                                (when (not= supplied-heads derived-heads)
                                  [:graph/head-set-mismatch])))]
    {:valid? (empty? all-errors)
     :errors all-errors
     :network/root (:network/root context)
     :graph/root (:graph/root packet)
     :node-count (count nodes)
     :heads (:heads packet)
     :prf/node-validation dag-check
     :reachability/structural-errors dag-errors}))

(defn replica-read
  "Model a replica receiving a portable packet and checking its expected root."
  [replica-id packet trusted-network-root]
  {:replica replica-id
   :received-root (:graph/root packet)
   :verification (verify-packet packet trusted-network-root)})

(defn demo []
  (let [packet (example-packet)
        trusted-root (get-in packet [:network :network/root])
        replicas [(replica-read :replica/alpha packet trusted-root)
                  (replica-read :replica/beta packet trusted-root)]
        summary {:example "network-scoped evidence DAG"
                 :network-root trusted-root
                 :graph-root (:graph/root packet)
                 :nodes (count (:nodes packet))
                 :heads (count (:heads packet))
                 :replicas-agree? (and (every? #(get-in % [:verification :valid?]) replicas)
                                       (= 1 (count (set (map :received-root replicas)))))
                 :interpretation "Local independent verification only; no transport, consensus, or global latestness."}]
    (println (pr-str summary))
    summary))

(defn -main [& _]
  (demo))
