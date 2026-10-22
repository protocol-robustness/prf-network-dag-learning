(ns prf.network.dag.head-observation-demo
  "Runnable localhost demonstration of two certified, conflicting checkpoint heads.

   Keys and source processes are generated locally. This demonstrates protocol
   mechanics, not operator independence or global latestness."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [prf.network.dag.head-observation :as head]
            [resolver-sim.hash.canonical :as canonical])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file Files OpenOption Path Paths StandardOpenOption]
           [java.security KeyPair KeyPairGenerator]
           [java.time Instant]
           [java.util Base64]))

(defn- hash-ref [domain value]
  (str "sha256:" (canonical/domain-hash domain value)))

(defn- prf-checkpoint-api [name]
  (or (try (requiring-resolve (symbol "resolver-sim.network.checkpoint" name))
           (catch Exception _ nil))
      (throw (ex-info "Pinned PRF revision does not expose checkpoint certification"
                      {:reason :prf/checkpoint-api-unavailable :function name}))))

(defn- public-key-content [key]
  (str "-----BEGIN PUBLIC KEY-----\n"
       (.encodeToString (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII))
                        (.getEncoded key))
       "\n-----END PUBLIC KEY-----\n"))

(defn- persist-new! [path artifact]
  (let [^Path path (Paths/get path (make-array String 0))
        parent (.getParent (.toAbsolutePath path))]
    (when parent (Files/createDirectories parent (make-array java.nio.file.attribute.FileAttribute 0)))
    (Files/write path (.getBytes (pr-str artifact) StandardCharsets/UTF_8)
                 (into-array OpenOption [StandardOpenOption/CREATE_NEW
                                         StandardOpenOption/WRITE]))
    (.toString (.toAbsolutePath path))))

(defn- independent-process-verify! [source-url trusted-genesis policy membership state-root]
  (let [entries (head/fetch-successors! source-url (:checkpoint/root trusted-genesis))
        dir (Files/createTempDirectory "prf-head-independent-verifier"
                                       (make-array java.nio.file.attribute.FileAttribute 0))
        bundle (.resolve dir "verification-input.edn")
        _ (Files/write bundle
                       (.getBytes (pr-str {:trusted-genesis trusted-genesis
                                           :policy policy :membership membership
                                           :entries entries :state-root state-root})
                                  StandardCharsets/UTF_8)
                       (into-array OpenOption [StandardOpenOption/CREATE_NEW
                                               StandardOpenOption/WRITE]))
        java-bin (str (System/getProperty "java.home") "/bin/java")
        command [java-bin "-cp" (System/getProperty "java.class.path")
                 "clojure.main" "-m"
                 "prf.network.dag.head-checkpoint-verifier-process"
                 (.toString bundle)]
        process (.start (ProcessBuilder. ^java.util.List command))
        output (with-open [reader (io/reader (.getInputStream process))]
                 (slurp reader))
        exit-code (.waitFor process)]
    (when-not (zero? exit-code)
      (throw (ex-info "Independent checkpoint verifier process rejected the source history"
                      {:reason :demo/independent-verifier-failed
                       :exit-code exit-code :output output})))
    (edn/read-string output)))

(defn- keypair []
  (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519")))

(defn- signer-member [i ^KeyPair pair]
  {:principal/id (str "witness:" i)
   :key/id (str "witness-key:" i)
   :key/public-key (public-key-content (.getPublic pair))
   :member/roles [:witness]
   :member/active? true
   :key/valid-from-epoch 0
   :key/revoked-at-epoch nil})

(defn- local-context [network-root policy membership genesis state-root]
  {:network/genesis-root network-root
   :predecessor genesis
   :policy policy
   :membership membership
   :events []
   :verify-event (fn [_] {:valid? true})
   :verify-completeness (fn [_ _ _] {:valid? true})
   :replay (fn [_ _ _ _]
             {:valid? true
              :dag-state-root state-root
              :frontier-roots []
              :resulting-policy-root (:policy/root policy)
              :resulting-membership-root (:membership/root membership)
              :resulting-epoch 0
              :state {:accepted-event-roots #{}}})})

(defn- signed-successor [branch network-root genesis policy membership state-root
                        pairs signer-indexes lock-dir]
  (let [cp ((prf-checkpoint-api "build-checkpoint")
            {:network/genesis-root network-root
             :checkpoint/epoch 0
             :checkpoint/resulting-epoch 0
             :checkpoint/sequence 1
             :checkpoint/previous-root (:checkpoint/root genesis)
             :checkpoint/accepted-event-manifest-root ((prf-checkpoint-api "event-manifest-root") [])
             :checkpoint/accepted-event-count 0
             :checkpoint/dag-state-root state-root
             :checkpoint/frontier-roots []
             :checkpoint/governing-policy-root (:policy/root policy)
             :checkpoint/governing-membership-root (:membership/root membership)
             :checkpoint/resulting-policy-root (:policy/root policy)
             :checkpoint/resulting-membership-root (:membership/root membership)
             :checkpoint/proposer-id (str "publisher:" branch)
             :checkpoint/claimed-time nil})
        context (local-context network-root policy membership genesis state-root)
        endorsements (mapv (fn [i]
                            (let [^KeyPair pair (nth pairs i)]
                              ((prf-checkpoint-api "endorse-checkpoint!")
                               cp context
                               {:principal/id (str "witness:" i)
                                :key/id (str "witness-key:" i)
                                :private-key (.getPrivate pair)
                                :public-key (.getPublic pair)
                                :store-path (.resolve lock-dir (str branch "-witness-" i ".edn"))})))
                          signer-indexes)
        certificate ((prf-checkpoint-api "build-certificate") cp endorsements)]
    {:checkpoint cp :certificate certificate :events []}))

(defn demo [output-path]
  (let [network-root (hash-ref "prf-learning-demo-network.v1" {:id "split-head"})
        signer-pairs (mapv (fn [_] (keypair)) (range 4))
        observer-pairs (mapv (fn [_] (keypair)) (range 2))
        members (mapv signer-member (range 4) signer-pairs)
        policy-root (hash-ref "prf-learning-demo-policy.v1" {:threshold 2})
        membership-root (hash-ref "prf-learning-demo-membership.v1"
                                  {:members (mapv :principal/id members)})
        policy {:policy/root policy-root :policy/threshold 2 :policy/fault-bound 0
                :policy/role-thresholds {}}
        membership {:membership/root membership-root :membership/members members}
        genesis-root (hash-ref "prf-learning-demo-genesis.v1" {:network network-root})
        genesis {:network/genesis-root network-root
                 :checkpoint/root genesis-root
                 :checkpoint/sequence 0
                 :checkpoint/resulting-epoch 0
                 :checkpoint/resulting-policy-root policy-root
                 :checkpoint/resulting-membership-root membership-root
                 :state {:accepted-event-roots #{}}
                 :state/accepted-event-roots #{}}
        state-root (hash-ref "prf-learning-demo-state.v1" {:accepted-events []})
        lock-dir (Files/createTempDirectory "prf-head-demo-locks"
                                            (make-array java.nio.file.attribute.FileAttribute 0))
        packages [(signed-successor "left" network-root genesis policy membership
                                     state-root signer-pairs [0 1] lock-dir)
                   (signed-successor "right" network-root genesis policy membership
                                     state-root signer-pairs [2 3] lock-dir)]
        observer-sources (mapv (fn [i]
                                {:source/id (str "local-source:" i)
                                 :source/key-id (str "local-key:" i)
                                 :network/genesis-root network-root
                                 :source/public-key (.getPublic ^KeyPair (nth observer-pairs i))
                                 :source/independence-group (keyword (str "local-operator-" i))})
                              [0 1])
        adapters {:resolve-authority (fn [_ _ _] {:policy policy :membership membership})
                  :verify-event (fn [_] {:valid? true})
                  :verify-completeness (fn [_ _ _] {:valid? true})
                  :replay (fn [_ _ _ _]
                            {:valid? true :dag-state-root state-root :frontier-roots []
                             :resulting-policy-root policy-root
                             :resulting-membership-root membership-root
                             :resulting-epoch 0 :state {:accepted-event-roots #{}}})}
        servers (mapv (fn [i]
                        (let [{:keys [checkpoint]} (nth packages i)
                              ^KeyPair pair (nth observer-pairs i)]
                          (head/start-source!
                           {:observation-fn
                            (fn [nonce]
                              ((prf-checkpoint-api "sign-head-observation")
                               {:genesis-root network-root
                                :source-id (str "local-source:" i)
                                :key-id (str "local-key:" i)
                                :checkpoint checkpoint
                                :client-nonce nonce
                                :issued-at (.toString (Instant/now))
                                :private-key (.getPrivate pair)}))
                            :checkpoint-fn (fn [root]
                                             (first (filter #(= root (get-in % [:checkpoint :checkpoint/root]))
                                                            packages)))
                            :successors-fn (fn [anchor]
                                             (when (= anchor genesis-root)
                                               [(nth packages i)]))})))
                      [0 1])]
    (try
      (let [trusted-genesis (assoc genesis :checkpoint/root genesis-root)
            independent-verifications
            (mapv (fn [server]
                    (independent-process-verify! (:base-url server) trusted-genesis
                                                 policy membership state-root))
                  servers)
            result (head/observe-two-sources!
                    (mapv (fn [server] {:url (:url server)}) servers)
                    {:trusted-genesis trusted-genesis
                     :adapters adapters
                     :trusted-sources observer-sources
                     :verification-context {:threshold 2}
                     :clock #(Instant/now)})
            artifact {:artifact/schema "prf-learning-head-conflict-demonstration.v1"
                      :network/genesis-root network-root
                      :trusted-genesis trusted-genesis
                      :authority/policy policy
                      :authority/membership membership
                      :observer/source-trust
                      (mapv (fn [source ^KeyPair pair]
                              (-> source
                                  (dissoc :source/public-key)
                                  (assoc :source/public-key-content
                                         (public-key-content (.getPublic pair)))))
                            observer-sources observer-pairs)
                      :checkpoint/packages packages
                      :checkpoint/independent-process-verifications independent-verifications
                      :observation/evidence result}
            evidence-path (persist-new! output-path artifact)
            summary {:demo "two-source authenticated checkpoint head conflict"
                     :status (get-in result [:verification :status])
                     :valid? (get-in result [:verification :valid?])
                     :checkpoint-roots (mapv :checkpoint/root (:observations result))
                     :certificate-roots (mapv #(get-in % [:certificate :certificate/root]) packages)
                     :independent-process-results independent-verifications
                     :evidence-path evidence-path
                     :limitation "Both checkpoint histories and head statements are locally verified. The sources share one JVM and do not establish operator independence or global latestness."}]
        (println (pr-str summary))
        (assoc summary :evidence artifact))
      (finally (run! head/stop-source! servers)))))

(defn -main [& [output-path]]
  (demo (or output-path
            (str "target/head-observation-conflict-" (System/currentTimeMillis) ".edn"))))
