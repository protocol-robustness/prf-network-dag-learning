(ns prf.network.dag.head-observation
  "Small read-only HTTP adapter for the PRF checkpoint head-observation API.

   This namespace owns transport only. Canonical validation, signatures,
   freshness policy and conflict classification remain in PRF."
  (:require [clojure.edn :as edn]
            [clojure.string :as str])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.net InetSocketAddress URI]
           [java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers]
           [java.time Duration]
           [java.nio.charset StandardCharsets]
           [java.security SecureRandom]
           [java.util Base64]
           [java.util.concurrent Executors]))

(defn- send-edn! [^HttpExchange exchange status value]
  (let [body (.getBytes (str (pr-str value) "\n") StandardCharsets/UTF_8)]
    (.set (.getResponseHeaders exchange) "Content-Type" "application/edn; charset=utf-8")
    (.set (.getResponseHeaders exchange) "Cache-Control" "no-store")
    (.sendResponseHeaders exchange status (alength body))
    (with-open [out (.getResponseBody exchange)] (.write out body))))

(defn- query-parameters [^HttpExchange exchange]
  (let [query (.getRawQuery (.getRequestURI exchange))]
    (reduce (fn [result pair]
              (let [[k v] (str/split pair #"=" 2)
                    k (java.net.URLDecoder/decode (or k "") "UTF-8")
                    v (java.net.URLDecoder/decode (or v "") "UTF-8")]
                (update result k (fnil conj []) v)))
            {} (remove str/blank? (str/split (or query "") #"&")))))

(defn- one-query-value [exchange name]
  (let [values (get (query-parameters exchange) name)]
    (when (= 1 (count values)) (first values))))

(def ^:private checkpoint-root-pattern #"^sha256:[0-9a-f]{64}$")

(defn start-source!
  "Start one read-only source bound to loopback by default.

   `observation-fn` receives the client nonce and returns a signed canonical
   head-observation.v1 artifact. Optional package callbacks expose immutable
   reconstruction data. The HTTP layer never stores signing keys."
  [{:keys [port bind-address observation-fn checkpoint-fn successors-fn]
    :or {port 0 bind-address "127.0.0.1"}}]
  (when-not (fn? observation-fn)
    (throw (ex-info "A signed observation provider is required"
                    {:reason :http/missing-observation-provider})))
  (let [server (HttpServer/create (InetSocketAddress. bind-address port) 0)
        executor (Executors/newFixedThreadPool 2)]
    (.createContext server "/head"
                    (reify HttpHandler
                      (handle [_ exchange]
                        (try
                          (cond
                            (not= "GET" (.getRequestMethod exchange))
                            (send-edn! exchange 405 {:error :http/method-not-allowed})

                            (not= "/head" (.getPath (.getRequestURI exchange)))
                            (send-edn! exchange 404 {:error :http/not-found})

                            (or (nil? (one-query-value exchange "nonce"))
                                (not (re-matches #"[A-Za-z0-9_-]{16,128}"
                                                 (one-query-value exchange "nonce"))))
                            (send-edn! exchange 400 {:error :http/nonce-required})

                            :else
                            (let [observation (observation-fn (one-query-value exchange "nonce"))]
                              (send-edn! exchange 200 observation)))
                          (catch Exception _
                            (send-edn! exchange 500 {:error :http/source-failure}))
                          (finally (.close exchange))))))
    (.createContext server "/checkpoints"
                    (reify HttpHandler
                      (handle [_ exchange]
                        (try
                          (let [path (.getPath (.getRequestURI exchange))
                                query (query-parameters exchange)]
                            (cond
                              (not= "GET" (.getRequestMethod exchange))
                              (send-edn! exchange 405 {:error :http/method-not-allowed})

                              (= path "/checkpoints")
                              (let [since (get query "since")]
                                (cond
                                  (or (nil? since) (not= 1 (count since)))
                                  (send-edn! exchange 400 {:error :http/single-since-root-required})

                                  (not (re-matches checkpoint-root-pattern (first since)))
                                  (send-edn! exchange 400 {:error :http/invalid-checkpoint-root})

                                  (not (fn? successors-fn))
                                  (send-edn! exchange 501 {:error :http/successor-history-unavailable})

                                  :else
                                  (if-let [entries (successors-fn (first since))]
                                    (send-edn! exchange 200 entries)
                                    (send-edn! exchange 404 {:error :http/anchor-not-found}))))

                              (str/starts-with? path "/checkpoints/")
                              (let [root (subs path (count "/checkpoints/"))]
                                (cond
                                  (or (str/includes? root "/")
                                      (not (re-matches checkpoint-root-pattern root)))
                                  (send-edn! exchange 400 {:error :http/invalid-checkpoint-root})

                                  (not (fn? checkpoint-fn))
                                  (send-edn! exchange 501 {:error :http/checkpoint-package-unavailable})

                                  :else
                                  (if-let [package (checkpoint-fn root)]
                                    (send-edn! exchange 200 package)
                                    (send-edn! exchange 404 {:error :http/checkpoint-not-found}))))

                              :else (send-edn! exchange 404 {:error :http/not-found})))
                          (catch Exception _
                            (send-edn! exchange 500 {:error :http/source-failure}))
                          (finally (.close exchange))))))
    (.setExecutor server executor)
    (.start server)
    {:server server
     :executor executor
     :base-url (str "http://" bind-address ":" (.getPort (.getAddress server)))
     :url (str "http://" bind-address ":" (.getPort (.getAddress server)) "/head")}))

(defn stop-source! [{:keys [^HttpServer server executor]}]
  (when server (.stop server 0))
  (when executor (.shutdownNow executor))
  nil)

(defn- fresh-nonce []
  (let [bytes (byte-array 24)]
    (.nextBytes (SecureRandom.) bytes)
    (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes)))

(defn fetch-observation!
  "Fetch one EDN observation with a fresh client nonce. Returns the nonce next
   to the untrusted response so the caller can pass both to the PRF verifier."
  ([url]
   (fetch-observation! (HttpClient/newHttpClient) url
                       (Duration/ofSeconds 3) (fresh-nonce)))
  ([^HttpClient client url timeout nonce]
   (let [request (-> (HttpRequest/newBuilder
                      (URI/create (str url "?nonce=" nonce)))
                     (.timeout timeout)
                     (.header "Accept" "application/edn")
                     (.GET)
                     (.build))
         response (.send client request (HttpResponse$BodyHandlers/ofString))]
     (when-not (= 200 (.statusCode response))
       (throw (ex-info "Head source returned a non-success status"
                       {:reason :http/source-response-failed
                        :status (.statusCode response)})))
     {:nonce nonce
      :observation (edn/read-string
                    {:readers {}
                     :default (fn [tag _]
                                (throw (ex-info "Tagged EDN is not accepted from a head source"
                                                {:tag tag})))}
                    (.body response))})))

(defn- fetch-edn!
  [^HttpClient client uri timeout]
  (let [request (-> (HttpRequest/newBuilder (URI/create (str uri)))
                    (.timeout timeout)
                    (.header "Accept" "application/edn")
                    (.GET)
                    (.build))
        response (.send client request (HttpResponse$BodyHandlers/ofString))]
    (when-not (= 200 (.statusCode response))
      (throw (ex-info "Checkpoint source returned a non-success status"
                      {:reason :http/checkpoint-response-failed
                       :status (.statusCode response)})))
    (edn/read-string
     {:readers {}
      :default (fn [tag _]
                 (throw (ex-info "Tagged EDN is not accepted from a checkpoint source"
                                 {:tag tag})))}
     (.body response))))

(defn- source-base-url [url]
  (str/replace url #"/head/?$" ""))

(defn fetch-checkpoint-package!
  "Fetch an immutable checkpoint/certificate/reconstruction package by root."
  ([base-url root]
   (fetch-checkpoint-package! (HttpClient/newHttpClient) base-url root
                              (Duration/ofSeconds 3)))
  ([^HttpClient client base-url root timeout]
   (when-not (re-matches checkpoint-root-pattern root)
     (throw (ex-info "Invalid checkpoint root" {:reason :http/invalid-checkpoint-root})))
   (fetch-edn! client (str (str/replace (source-base-url base-url) #"/$" "")
                           "/checkpoints/" root) timeout)))

(defn fetch-successors!
  "Fetch ordered successor packages after a pinned checkpoint root."
  ([base-url root]
   (fetch-successors! (HttpClient/newHttpClient) base-url root
                      (Duration/ofSeconds 3)))
  ([^HttpClient client base-url root timeout]
   (when-not (re-matches checkpoint-root-pattern root)
     (throw (ex-info "Invalid checkpoint root" {:reason :http/invalid-checkpoint-root})))
   (fetch-edn! client
               (str (str/replace (source-base-url base-url) #"/$" "")
                    "/checkpoints?since=" root)
               timeout)))

(declare reconstruct-history!)

(defn reconstruct-history!
  "Fetch successor packages from a pinned checkpoint and replay them through
   PRF's verifier. The adapters and trusted genesis are local verifier inputs;
   they are never accepted from the source response."
  [base-url trusted-genesis adapters]
  (let [verify-var (try
                     (requiring-resolve 'resolver-sim.network.checkpoint/verify-history)
                     (catch Exception _ nil))]
    (when-not verify-var
      (throw (ex-info "Pinned PRF dependency does not expose checkpoint history verification"
                      {:reason :prf/checkpoint-api-unavailable})))
    (let [entries (fetch-successors! base-url (:checkpoint/root trusted-genesis))
          verification (verify-var trusted-genesis entries adapters)]
      {:entries entries :verification verification})))

(defn- observe-two-sources-with-verifier! [sources verify-fn]
  (when-not (and (= 2 (count sources)) (fn? verify-fn))
    (throw (ex-info "Exactly two sources and a PRF verifier are required"
                    {:reason :http/two-source-configuration-required})))
  (let [responses (mapv (fn [{:keys [url]}] (fetch-observation! url)) sources)
        observations (mapv :observation responses)
        expected-nonces (mapv :nonce responses)
        result (verify-fn observations expected-nonces)]
    {:observations observations
     :expected-nonces expected-nonces
     :verification result}))

(defn- observe-two-sources-with-reconstruction!
  [sources {:keys [trusted-genesis adapters trusted-sources verification-context clock]}]
   (when-not (and (= 2 (count sources))
                  (map? trusted-genesis)
                  (vector? trusted-sources)
                  (fn? clock))
     (throw (ex-info "Two sources, trusted genesis, trusted source keys and clock are required"
                     {:reason :http/incomplete-trusted-context})))
   (let [responses (mapv (fn [{:keys [url]}] (fetch-observation! url)) sources)
         observations (mapv :observation responses)
         expected-nonces (into {}
                               (map (fn [observation response]
                                      [(:source/id observation) (:nonce response)])
                                    observations responses))
         histories (mapv (fn [{:keys [url]}]
                           (reconstruct-history! url trusted-genesis adapters))
                         sources)
         verifications (mapv :verification histories)
         certified (filter #(= :certified (:status %)) verifications)
         heads (mapv :head certified)
         latest-verification (when (seq certified)
                               (apply max-key #(get-in % [:head :checkpoint/sequence]) certified))
         conflict? (and (= 2 (count certified))
                        (let [[a b] heads]
                          (and (not= (:checkpoint/root a) (:checkpoint/root b))
                               (= (:checkpoint/sequence a) (:checkpoint/sequence b))
                               (= (:checkpoint/previous-root a) (:checkpoint/previous-root b)))))
         certified-head (cond
                          conflict?
                          {:status :conflicting
                           :conflict/evidence
                           (mapv (fn [verification]
                                   (let [head (:head verification)
                                         terminal (last (:checkpoints verification))]
                                     {:checkpoint {:checkpoint/root (:checkpoint/root head)
                                                   :checkpoint/sequence (:checkpoint/sequence head)
                                                   :checkpoint/previous-root (:checkpoint/previous-root terminal)}
                                      :verification {:status :certified}}))
                                 certified)}

                          latest-verification latest-verification
                          :else {:status :locally-valid})
         verify-var (try
                      (requiring-resolve 'resolver-sim.network.checkpoint/verify-observed-heads)
                      (catch Exception _ nil))]
     (when-not verify-var
       (throw (ex-info "Pinned PRF dependency does not expose head verification"
                       {:reason :prf/checkpoint-api-unavailable})))
     {:observations observations
      :expected-nonces expected-nonces
      :histories histories
      :verification
      (verify-var observations trusted-sources
                  (assoc verification-context
                         :network/genesis-root (:network/genesis-root trusted-genesis)
                         :certified-head certified-head
                         :expected-nonce expected-nonces
                         :now (clock)))}))

(defn observe-two-sources!
  "Fetch two sources. Pass a verifier function for observation-only use, or a
   trusted context map to reconstruct both checkpoint histories through PRF."
  [sources verifier-or-context]
  (if (fn? verifier-or-context)
    (observe-two-sources-with-verifier! sources verifier-or-context)
    (observe-two-sources-with-reconstruction! sources verifier-or-context)))

(defn prf-verifier
  "Resolve the verifier from the pinned PRF dependency at runtime. This gives a
   clear error if the dependency revision predates PRO-93's head API."
  [trusted-context]
  (let [verify-var (try
                     (requiring-resolve 'resolver-sim.network.checkpoint/verify-observed-heads)
                     (catch Exception _ nil))]
    (when-not verify-var
      (throw (ex-info "Pinned PRF dependency does not expose checkpoint head verification"
                      {:reason :prf/checkpoint-api-unavailable})))
    (fn [observations nonces]
      (let [sources (:sources trusted-context)
            expected-nonce (into {}
                                 (map (fn [observation nonce]
                                        [(:source/id observation) nonce])
                                      observations nonces))]
        (verify-var observations sources
                    (assoc (:verification-context trusted-context)
                           :expected-nonce expected-nonce
                           :now ((:clock trusted-context))))))))

