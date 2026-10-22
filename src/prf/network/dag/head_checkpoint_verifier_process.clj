(ns prf.network.dag.head-checkpoint-verifier-process
  "Fresh-process verifier for the local PRO-94 demonstration fixture."
  (:require [clojure.edn :as edn]
            [resolver-sim.hash.canonical :as canonical]
            [resolver-sim.network.checkpoint :as checkpoint]))

(defn- hash-ref [domain value]
  (str "sha256:" (canonical/domain-hash domain value)))

(defn -main [bundle-path]
  (let [{:keys [trusted-genesis policy membership entries state-root]}
        (edn/read-string (slurp bundle-path))
        adapters {:resolve-authority (fn [_ _ _] {:policy policy :membership membership})
                  :verify-event (fn [event]
                                  {:valid? (= (:event/root event)
                                              (hash-ref (:event/schema event)
                                                        (dissoc event :event/root)))})
                  :verify-completeness (fn [_ _ _] {:valid? true})
                  :replay (fn [_ events _ _]
                            {:valid? true
                             :dag-state-root (hash-ref "prf-learning-demo-state.v1"
                                                       {:accepted-events (mapv :event/root events)})
                             :frontier-roots (mapv :event/root events)
                             :resulting-policy-root (:policy/root policy)
                             :resulting-membership-root (:membership/root membership)
                             :resulting-epoch (:checkpoint/resulting-epoch trusted-genesis)
                             :state {:accepted-event-roots (set (map :event/root events))}})}
        result (checkpoint/verify-history trusted-genesis entries adapters)
        reconstructed-state-root (get-in result [:checkpoints 0 :local-verification :state :dag-state-root])
        report {:status (:status result)
                :valid? (:valid? result)
                :checkpoint/root (get-in result [:head :checkpoint/root])
                :checkpoint/sequence (get-in result [:head :checkpoint/sequence])
                :reconstructed-state-root reconstructed-state-root}]
    (when-not (= state-root reconstructed-state-root)
      (throw (ex-info "Fresh-process replay produced an unexpected DAG state root"
                      {:expected state-root
                       :actual reconstructed-state-root})))
    (println (pr-str report))
    (when-not (and (:valid? result) (= :certified (:status result)))
      (System/exit 1))))
