(ns prf.network.dag.head-observation-demo
  "Runnable localhost demonstration of two certified, conflicting checkpoint heads.

   Keys and source processes are generated locally. This demonstrates protocol
   mechanics, not operator independence or global latestness."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [prf.network.dag.head-observation :as head]
            [resolver-sim.hash.canonical :as canonical])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file Files OpenOption Path Paths StandardOpenOption]
           [java.security KeyFactory KeyPair KeyPairGenerator]
           [java.time Instant]
           [java.util Base64]
           [java.util.concurrent TimeUnit]
           [java.security.spec X509EncodedKeySpec]
           [java.io BufferedReader InputStreamReader]))

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

(defn- parse-public-key-content [content]
  (let [encoded (-> content
                    (str/replace #"-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s" ""))
        bytes (.decode (Base64/getDecoder) ^String encoded)]
    (.generatePublic (KeyFactory/getInstance "Ed25519")
                     (X509EncodedKeySpec. bytes))))

(defn- start-source-process! [directory index network-root package]
  (let [configuration (Files/createTempFile directory (str "source-" index "-") ".edn"
                                                  (make-array java.nio.file.attribute.FileAttribute 0))
        config {:network-root network-root
                :source-id (str "local-source:" index)
                :key-id (str "local-key:" index)
                :package package}
        _ (Files/write configuration (.getBytes (pr-str config) StandardCharsets/UTF_8)
                        (into-array OpenOption [StandardOpenOption/WRITE
                                                StandardOpenOption/TRUNCATE_EXISTING]))
        java-bin (str (System/getProperty "java.home") "/bin/java")
        command [java-bin "-cp" (System/getProperty "java.class.path")
                 "clojure.main" "-m"
                 "prf.network.dag.head-observation-source-process"
                 (.toString configuration)]
        process (.start (ProcessBuilder. ^java.util.List command))
        reader (BufferedReader. (InputStreamReader. (.getInputStream process)
                                                   StandardCharsets/UTF_8))
        ready-line (.readLine reader)
        ready (when ready-line (edn/read-string ready-line))]
    (when-not (and (:ready? ready) (:url ready))
      (.destroyForcibly process)
      (throw (ex-info "Checkpoint source process failed to start"
                      {:reason :demo/source-process-start-failed
                       :source/index index :output ready-line})))
    {:process process
     :reader reader
     :configuration configuration
     :ready ready
     :url (:url ready)
     :base-url (str/replace (:url ready) #"/head$" "")}))

(defn- stop-source-process! [{:keys [^Process process ^BufferedReader reader configuration]}]
  (when process
    (try (.close (.getOutputStream process)) (catch Exception _ nil))
    (when-not (.waitFor process 5 TimeUnit/SECONDS)
      (.destroyForcibly process)
      (.waitFor process 5 TimeUnit/SECONDS)))
  (when reader (try (.close reader) (catch Exception _ nil)))
  (when configuration (Files/deleteIfExists configuration))
  nil)

(defn- portable-edn [value]
  (cond
    (instance? Instant value) (.toString ^Instant value)
    (map? value) (into (empty value) (map (fn [[k v]] [(portable-edn k) (portable-edn v)])) value)
    (vector? value) (mapv portable-edn value)
    (set? value) (into #{} (map portable-edn) value)
    (sequential? value) (mapv portable-edn value)
    :else value))

(defn- persist-new! [path artifact]
  (let [^Path path (Paths/get path (make-array String 0))
        parent (.getParent (.toAbsolutePath path))]
    (when parent (Files/createDirectories parent (make-array java.nio.file.attribute.FileAttribute 0)))
    (Files/write path (.getBytes (pr-str (portable-edn artifact)) StandardCharsets/UTF_8)
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
        adapters {:resolve-authority (fn [_ _ _] {:policy policy :membership membership})
                  :verify-event (fn [_] {:valid? true})
                  :verify-completeness (fn [_ _ _] {:valid? true})
                  :replay (fn [_ _ _ _]
                            {:valid? true :dag-state-root state-root :frontier-roots []
                             :resulting-policy-root policy-root
                             :resulting-membership-root membership-root
                             :resulting-epoch 0 :state {:accepted-event-roots #{}}})}
        source-directory (Files/createTempDirectory "prf-head-source-processes"
                                                    (make-array java.nio.file.attribute.FileAttribute 0))
        servers (mapv (fn [i]
                        (start-source-process! source-directory i network-root (nth packages i)))
                      [0 1])
        observer-sources (mapv (fn [{:keys [ready]} i]
                                {:source/id (:source/id ready)
                                 :source/key-id (:source/key-id ready)
                                 :network/genesis-root network-root
                                 :source/public-key (parse-public-key-content
                                                     (:source/public-key-content ready))
                                 ;; These are separately configured process labels for this
                                 ;; one-machine exercise, not claims of operator independence.
                                 :source/independence-group (keyword (str "local-process-" i))})
                              servers [0 1])]
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
            artifact {:artifact/schema "prf-learning-head-conflict-demonstration.v2"
                      :prf/source-revision (let [revision (System/getenv "PRF_CHECKPOINT_SOURCE_REVISION")]
                                             (if (seq revision) revision "not-supplied"))
                      :prf/source-dirty? (case (System/getenv "PRF_CHECKPOINT_SOURCE_DIRTY")
                                           "true" true
                                           "false" false
                                           nil)
                      :network/genesis-root network-root
                      :trusted-genesis trusted-genesis
                      :authority/policy policy
                      :authority/membership membership
                      :observer/source-trust
                      (mapv (fn [source]
                              (-> source
                                  (dissoc :source/public-key)
                                  (assoc :source/public-key-content
                                         (public-key-content (:source/public-key source)))))
                            observer-sources)
                      :source/processes
                      (mapv (fn [{:keys [ready]}]
                              (select-keys ready [:source/id :source/key-id :url]))
                            servers)
                      :checkpoint/packages packages
                      :checkpoint/independent-process-verifications independent-verifications
                      :observation/threshold 2
                      :observation/evidence result}
            evidence-path (persist-new! output-path artifact)
            summary {:demo "two-source authenticated checkpoint head conflict"
                     :status (get-in result [:verification :status])
                     :valid? (get-in result [:verification :valid?])
                     :checkpoint-roots (mapv :checkpoint/root (:observations result))
                     :certificate-roots (mapv #(get-in % [:certificate :certificate/root]) packages)
                     :independent-process-results independent-verifications
                     :evidence-path evidence-path
                     :limitation "Head sources run in separate local processes and are independently keyed for this run. They share one host and demo coordinator; this does not establish independent operators, persistent identity, or global latestness."}]
        (println (pr-str summary))
        (assoc summary :evidence artifact))
      (finally
        (run! stop-source-process! servers)
        (Files/deleteIfExists source-directory)))))

(defn -main [& [output-path]]
  (demo (or output-path
            (str "target/head-observation-conflict-" (System/currentTimeMillis) ".edn"))))
