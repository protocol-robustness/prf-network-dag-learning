(ns prf.network.dag.learning-test
  (:require [clojure.test :refer [deftest is]]
            [resolver-sim.evidence.reachability :as reach]
            [prf.network.dag.head-observation :as head]
            [prf.network.dag.head-observation-demo :as head-demo]
            [prf.network.dag.learning :as learning])
  (:import [java.security KeyPairGenerator]))

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
        (is (= "head-observation.v1" (:observation/schema observation)))
        (let [request (-> (java.net.http.HttpRequest/newBuilder
                           (java.net.URI/create (:url source)))
                          (.POST (java.net.http.HttpRequest$BodyPublishers/noBody))
                          .build)
              response (.send (java.net.http.HttpClient/newHttpClient)
                              request
                              (java.net.http.HttpResponse$BodyHandlers/ofString))]
          (is (= 405 (.statusCode response))
              "the observation endpoint rejects write methods")
          (is (= "no-store"
                 (.orElse (.firstValue (.headers response) "Cache-Control") ""))
              "observation responses are not cached")))
      (finally (head/stop-source! source)))))

(deftest read-only-http-source-exposes-content-addressed-reconstruction-routes
  (let [root "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        package {:checkpoint {:checkpoint/root root} :certificate {:certificate/root "cert"}}
        successors [{:checkpoint {:checkpoint/root root}}]
        source (head/start-source!
                {:observation-fn (fn [nonce] {:observation/client-nonce nonce})
                 :checkpoint-fn (fn [requested] (when (= root requested) package))
                 :successors-fn (fn [anchor]
                                  (cond
                                    (= "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" anchor) successors
                                    (= "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" anchor) []
                                    :else nil))})]
    (try
      (is (= package (head/fetch-checkpoint-package! (:url source) root)))
      (is (= successors
             (head/fetch-successors!
              (:base-url source)
              "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")))
      (if (try (requiring-resolve 'resolver-sim.network.checkpoint/verify-history)
               true
               (catch Exception _ false))
        (let [reconstructed (head/reconstruct-history!
                             (:base-url source)
                             {:network/genesis-root "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                              :checkpoint/root "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
                             {})]
          (is (= [] (:entries reconstructed)))
          (is (= :stale-or-unknown (get-in reconstructed [:verification :status]))
              "an absent trusted anchor cannot be treated as a valid empty history"))
        (is true "Run with the local PRF override to exercise history reconstruction."))
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

(deftest two-http-sources-are-checked-by-prf-signature-and-head-verifier
  (if-let [sign-observation (try
                             (requiring-resolve 'resolver-sim.network.checkpoint/sign-head-observation)
                             (catch Exception _ nil))]
    (let [network-root (str "sha256:" (apply str (repeat 64 "a")))
          root-a (str "sha256:" (apply str (repeat 64 "b")))
          root-b (str "sha256:" (apply str (repeat 64 "c")))
          pairs (mapv (fn [_] (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))) [0 1])
          sources (mapv (fn [i]
                          {:source/id (str "source:" i)
                           :source/key-id (str "key:" i)
                           :network/genesis-root network-root
                           :source/public-key (.getPublic (nth pairs i))
                           :source/independence-group (keyword (str "operator-" i))})
                        [0 1])
          run-observation-check
          (fn [roots certified-head]
            (let [servers (mapv (fn [i]
                                  (head/start-source!
                                   {:observation-fn
                                    (fn [nonce]
                                      (sign-observation
                                       {:genesis-root network-root
                                        :source-id (str "source:" i)
                                        :key-id (str "key:" i)
                                        :checkpoint {:checkpoint/root (nth roots i)
                                                     :checkpoint/sequence 7}
                                        :client-nonce nonce
                                        :issued-at (.toString (java.time.Instant/now))
                                        :private-key (.getPrivate (nth pairs i))}))}))
                                [0 1])]
              (try
                (head/observe-two-sources!
                 (mapv (fn [server] {:url (:url server)}) servers)
                 (head/prf-verifier
                  {:sources sources
                   :verification-context {:network/genesis-root network-root
                                          :certified-head certified-head}
                   :clock #(java.time.Instant/now)}))
                (finally (run! head/stop-source! servers)))))
          current (run-observation-check
                   [root-a root-a]
                   {:status :certified
                    :head {:checkpoint/root root-a :checkpoint/sequence 7}
                    :checkpoints [{:status :certified :checkpoint/root root-a
                                   :checkpoint/sequence 7}]})
          conflict (run-observation-check
                    [root-a root-b]
                    {:status :conflicting
                     :conflict/evidence
                     [{:checkpoint {:checkpoint/root root-a :checkpoint/sequence 7
                                    :checkpoint/previous-root "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
                       :verification {:status :certified}}
                      {:checkpoint {:checkpoint/root root-b :checkpoint/sequence 7
                                    :checkpoint/previous-root "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
                       :verification {:status :certified}}]})]
      (is (= :current-observed (get-in current [:verification :status])))
      (is (= :conflicting (get-in conflict [:verification :status])))
      (is (false? (get-in conflict [:verification :valid?]))))
    (is true "Run with a reviewed PRF revision or local-root override to exercise signed HTTP observations.")))

(deftest older-two-source-head-is-not-reported-current
  (if-let [sign-observation (try
                             (requiring-resolve 'resolver-sim.network.checkpoint/sign-head-observation)
                             (catch Exception _ nil))]
    (let [network-root (str "sha256:" (apply str (repeat 64 "a")))
        older-root (str "sha256:" (apply str (repeat 64 "b")))
        newer-root (str "sha256:" (apply str (repeat 64 "c")))
        now (java.time.Instant/now)
        pairs (mapv (fn [_] (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))) [0 1])
        sources (mapv (fn [i]
                        {:source/id (str "stale-source:" i)
                         :source/key-id (str "stale-key:" i)
                         :network/genesis-root network-root
                         :source/public-key (.getPublic (nth pairs i))
                         :source/independence-group (keyword (str "stale-operator-" i))})
                      [0 1])
        certified-head {:status :certified
                        :head {:checkpoint/root newer-root :checkpoint/sequence 8}
                        :checkpoints [{:status :certified
                                       :checkpoint/root older-root :checkpoint/sequence 7}
                                      {:status :certified
                                       :checkpoint/root newer-root :checkpoint/sequence 8}]}
        run (fn [roots]
              (let [servers (mapv (fn [i]
                              (head/start-source!
                               {:observation-fn
                                (fn [nonce]
                                  (sign-observation
                                   {:genesis-root network-root
                                    :source-id (str "stale-source:" i)
                                    :key-id (str "stale-key:" i)
                                    :checkpoint {:checkpoint/root (nth roots i)
                                                 :checkpoint/sequence (if (= older-root (nth roots i)) 7 8)}
                                    :client-nonce nonce
                                    :issued-at (.toString now)
                                    :private-key (.getPrivate (nth pairs i))}))}))
                            [0 1])]
          (try
            (head/observe-two-sources!
             (mapv (fn [server] {:url (:url server)}) servers)
               (head/prf-verifier
                {:sources sources
                 :verification-context {:network/genesis-root network-root
                                        :certified-head certified-head}
                 :clock (constantly now)}))
              (finally (run! head/stop-source! servers)))))
        both-behind (run [older-root older-root])
        one-source-behind (run [older-root newer-root])]
      (doseq [result [both-behind one-source-behind]]
        (is (= :stale-or-unknown (get-in result [:verification :status])))
        (is (false? (get-in result [:verification :valid?])))))
    (is true "Run with the local PRF checkpoint API override to exercise stale signed heads.")))

(deftest replayed-expired-and-invalid-signed-heads-do-not-count-as-current
  (if-let [sign-observation (try
                             (requiring-resolve 'resolver-sim.network.checkpoint/sign-head-observation)
                             (catch Exception _ nil))]
    (let [network-root (str "sha256:" (apply str (repeat 64 "a")))
          other-network (str "sha256:" (apply str (repeat 64 "e")))
          checkpoint-root (str "sha256:" (apply str (repeat 64 "b")))
          now (java.time.Instant/now)
          pairs (mapv (fn [_] (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))) [0 1])
          sources (mapv (fn [i]
                          {:source/id (str "fresh-source:" i)
                           :source/key-id (str "fresh-key:" i)
                           :network/genesis-root network-root
                           :source/public-key (.getPublic (nth pairs i))
                           :source/independence-group (keyword (str "fresh-operator-" i))})
                        [0 1])
          certified-head {:status :certified
                          :head {:checkpoint/root checkpoint-root :checkpoint/sequence 7}
                          :checkpoints [{:status :certified :checkpoint/root checkpoint-root
                                         :checkpoint/sequence 7}]}
          observe (fn [mode]
                    (let [servers (mapv (fn [i]
                                (head/start-source!
                                 {:observation-fn
                                  (fn [request-nonce]
                                    (let [body {:genesis-root (if (= mode :wrong-network)
                                                                other-network network-root)
                                               :source-id (str "fresh-source:" i)
                                               :key-id (str "fresh-key:" i)
                                               :checkpoint {:checkpoint/root checkpoint-root
                                                            :checkpoint/sequence 7}
                                               :client-nonce (if (= mode :replayed-nonce)
                                                               "previous-request-nonce-0001"
                                                               request-nonce)
                                               :issued-at (.toString
                                                           (case mode
                                                             :expired (.minusSeconds now 31)
                                                             :future (.plusSeconds now 2)
                                                             now))
                                               :private-key (.getPrivate (nth pairs i))}
                                          signed (sign-observation body)]
                                      (if (= mode :invalid-signature)
                                        (assoc-in signed [:observation/signature :signature :value]
                                                  "invalid-signature")
                                        signed)))}))
                              [0 1])]
            (try
              (head/observe-two-sources!
               (mapv (fn [server] {:url (:url server)}) servers)
               (head/prf-verifier
                {:sources sources
                 :verification-context {:network/genesis-root network-root
                                        :certified-head certified-head
                                        :max-age-seconds 30
                                        :max-future-skew-seconds 1}
                 :clock (constantly now)}))
                    (finally (run! head/stop-source! servers)))))]
      (doseq [mode [:replayed-nonce :expired :future]]
        (is (= :stale-or-unknown (get-in (observe mode) [:verification :status]))))
      (doseq [mode [:invalid-signature :wrong-network]]
        (is (= :invalid (get-in (observe mode) [:verification :status])))))
    (is true "Run with the local PRF checkpoint API override to exercise signed-head rejection cases.")))

(deftest runnable-demo-reconstructs-two-certified-fork-successors-and-retains-evidence
  (if (try (requiring-resolve 'resolver-sim.network.checkpoint/verify-history)
           true
           (catch Exception _ false))
    (let [dir (java.nio.file.Files/createTempDirectory
               "prf-head-demo-test" (make-array java.nio.file.attribute.FileAttribute 0))
          path (.resolve dir "conflict.edn")
          result (head-demo/demo (.toString path))
          evidence (:evidence result)]
      (is (= :conflicting (:status result)))
      (is (= 2 (count (:checkpoint/packages evidence))))
      (is (= 2 (count (:source/processes evidence))))
      (is (= 2 (count (distinct (map :source/id (:source/processes evidence))))))
      (is (every? #(= :certified (get-in % [:verification :status]))
                  (get-in evidence [:observation/evidence :histories])))
      (is (every? #(and (= :certified (:status %)) (:valid? %))
                  (:checkpoint/independent-process-verifications evidence)))
      (is (every? false?
                  (map #(get-in % [:verification :checkpoints 0 :quorum-safety
                                   :intersection-bound-satisfied?])
                       (get-in evidence [:observation/evidence :histories]))))
      (is (java.nio.file.Files/exists path (make-array java.nio.file.LinkOption 0))))
    (is true "Run with the local PRF override to execute the certificate-backed head demo.")))
