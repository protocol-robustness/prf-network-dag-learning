(ns prf.network.dag.head-observation-source-process
  "One local network-source process for the checkpoint head demonstration."
  (:require [clojure.edn :as edn]
            [prf.network.dag.head-observation :as head])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file Files OpenOption Paths StandardOpenOption]
           [java.security KeyPairGenerator]
           [java.time Instant]
           [java.util Base64]))

(defn- public-key-content [key]
  (str "-----BEGIN PUBLIC KEY-----\n"
       (.encodeToString (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII))
                        (.getEncoded key))
       "\n-----END PUBLIC KEY-----\n"))

(defn- prf-checkpoint-api [name]
  (or (try (requiring-resolve (symbol "resolver-sim.network.checkpoint" name))
           (catch Exception _ nil))
      (throw (ex-info "Pinned PRF revision lacks the checkpoint API"
                      {:reason :prf/checkpoint-api-unavailable :function name}))))

(defn -main [configuration-path]
  (let [{:keys [network-root source-id key-id package]}
        (edn/read-string (slurp configuration-path))
        checkpoint (:checkpoint package)
        pair (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519"))
        sign-observation (prf-checkpoint-api "sign-head-observation")
        _ (sign-observation {:genesis-root network-root
                             :source-id source-id
                             :key-id key-id
                             :checkpoint checkpoint
                             :client-nonce "warmup-nonce-1234"
                             :issued-at (.toString (Instant/now))
                             :private-key (.getPrivate pair)})
        source (head/start-source!
                {:observation-fn
                 (fn [nonce]
                   (sign-observation {:genesis-root network-root
                                      :source-id source-id
                                      :key-id key-id
                                      :checkpoint checkpoint
                                      :client-nonce nonce
                                      :issued-at (.toString (Instant/now))
                                      :private-key (.getPrivate pair)}))
                 :checkpoint-fn (fn [root]
                                  (when (= root (:checkpoint/root checkpoint)) package))
                 :successors-fn (fn [anchor]
                                  (when (= anchor (:checkpoint/previous-root checkpoint))
                                    [package]))})]
    (try
      ;; The parent pins this key in its verifier configuration for this local
      ;; exercise. It is ephemeral bootstrap, not a production trust ceremony.
      (println (pr-str {:ready? true
                        :source/id source-id
                        :source/key-id key-id
                        :network/genesis-root network-root
                        :source/public-key-content (public-key-content (.getPublic pair))
                        :url (:url source)}))
      (flush)
      (while (not= -1 (.read System/in)))
      (finally (head/stop-source! source)))))
