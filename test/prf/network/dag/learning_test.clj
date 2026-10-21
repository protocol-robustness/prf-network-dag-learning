(ns prf.network.dag.learning-test
  (:require [clojure.test :refer [deftest is]]
            [resolver-sim.evidence.reachability :as reach]
            [prf.network.dag.head-observation :as head]
            [prf.network.dag.learning :as learning]))

(deftest replicas-independently-verify-the-same-network-packet
  (let [packet (learning/example-packet)
        root (get-in packet [:network :network/root])
        a (learning/replica-read :a packet root)
        b (learning/replica-read :b packet root)]
    (is (get-in a [:verification :valid?]))
    (is (get-in b [:verification :valid?]))
    (is (= (:received-root a) (:received-root b)))
    (is (= 4 (get-in a [:verification :node-count])))))

(deftest packet-fails-closed-on-network-substitution
  (let [packet (learning/example-packet)
        result (learning/verify-packet packet "sha256:untrusted-network")]
    (is (false? (:valid? result)))
    (is (some #{:network/untrusted-context} (:errors result)))))

(deftest packet-fails-closed-on-node-tampering
  (let [packet (learning/example-packet)
        tampered (update-in packet [:nodes 1 :outputs] assoc :attestation/claim-result :dissent)
        result (learning/verify-packet tampered (get-in packet [:network :network/root]))]
    (is (false? (:valid? result)))
    (is (some #{:graph/root-mismatch} (:errors result)))))

(deftest packet-fails-closed-on-cross-network-node-transplant
  (let [packet (learning/example-packet)
        transplanted (assoc-in packet [:nodes 1 :extensions :learning/network-root] "sha256:other")
        result (learning/verify-packet transplanted (get-in packet [:network :network/root]))]
    (is (false? (:valid? result)))
    (is (some #{:node/network-binding-mismatch} (:errors result)))))

(deftest approvals-and-dissent-form-a-fork-from-one-basis
  (let [packet (learning/example-packet)
        nodes (:nodes packet)
        basis (:node-hash (first nodes))
        leaves (mapv :node-hash (rest nodes))
        graph {:dag/nodes (mapv #(hash-map :node/id (:node-hash %)) nodes)
               :dag/edges (vec (mapcat (fn [n]
                                        (map #(hash-map :edge/from % :edge/to (:node-hash n))
                                             (:parent-hashes n))) nodes))}]
    (is (every? #(reach/dag-reachable? graph basis %) leaves))
    (is (not (reach/dag-reachable? graph (first leaves) (second leaves))))
    (is (= (set leaves) (set (:heads packet))))))

(deftest read-only-http-source-echoes-client-nonce-without-claiming-validity
  (let [source (head/start-source!
                {:observation-fn (fn [nonce]
                                   {:observation/schema "head-observation.v1"
                                    :observation/client-nonce nonce})})]
    (try
      (let [{:keys [nonce observation]} (head/fetch-observation! (:url source))]
        (is (= nonce (:observation/client-nonce observation)))
        (is (= "head-observation.v1" (:observation/schema observation))))
      (finally (head/stop-source! source)))))

(deftest two-source-http-adapter-preserves-conflict-result-from-verifier
  (let [a (head/start-source! {:observation-fn (fn [nonce]
                                                 {:source/id "a" :nonce nonce
                                                  :checkpoint/root "fork:a"})})
        b (head/start-source! {:observation-fn (fn [nonce]
                                                 {:source/id "b" :nonce nonce
                                                  :checkpoint/root "fork:b"})})]
    (try
      (let [result (head/observe-two-sources!
                    [{:url (:url a)} {:url (:url b)}]
                    (fn [observations nonces]
                      (is (= 2 (count observations)))
                      (is (= (mapv :nonce observations) nonces))
                      {:status :conflicting :valid? false
                       :roots (mapv :checkpoint/root observations)}))]
        (is (= :conflicting (get-in result [:verification :status])))
        (is (= #{"fork:a" "fork:b"}
               (set (get-in result [:verification :roots])))))
      (finally
        (head/stop-source! a)
        (head/stop-source! b)))))

(deftest prf-verifier-adapter-delegates-when-checkpoint-api-is-available
  (let [api (try
              (requiring-resolve 'resolver-sim.network.checkpoint/verify-observed-heads)
              (catch Exception _ nil))]
    (if api
      (let [verify (head/prf-verifier {:sources []
                                      :verification-context {}
                                      :clock #(java.time.Instant/now)})
            result (verify [] [])]
        (is (= :stale-or-unknown (:status result)))
        (is (false? (:valid? result))))
      (is true "The default pinned PRF revision predates PRO-93; local override covers delegation."))))
