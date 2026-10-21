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

(defn- request-nonce [^HttpExchange exchange]
  (let [query (.getRawQuery (.getRequestURI exchange))]
    (some (fn [pair]
            (let [[k v] (str/split pair #"=" 2)]
              (when (= "nonce" k) v)))
          (str/split (or query "") #"&"))))

(defn start-source!
  "Start one GET-only source bound to loopback by default.

   `observation-fn` receives the client nonce and returns a signed canonical
   head-observation.v1 artifact. The HTTP layer never stores signing keys."
  [{:keys [port bind-address observation-fn]
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

                            (nil? (request-nonce exchange))
                            (send-edn! exchange 400 {:error :http/nonce-required})

                            :else
                            (let [observation (observation-fn (request-nonce exchange))]
                              (send-edn! exchange 200 observation)))
                          (catch Exception _
                            (send-edn! exchange 500 {:error :http/source-failure}))
                          (finally (.close exchange))))))
    (.setExecutor server executor)
    (.start server)
    {:server server
     :executor executor
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

(defn observe-two-sources!
  "Retrieve two separately configured sources and pass their observations to
   PRF's `verify-observed-heads` function. `verify-fn` is the PRF API partially
   applied to trusted source, history and freshness configuration."
  [sources verify-fn]
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

