(ns prf.network.dag.test-runner
  (:require [clojure.test :as test]
            [prf.network.dag.learning-test]))

(defn -main [& _]
  (let [result (test/run-tests 'prf.network.dag.learning-test)]
    (when (pos? (+ (:fail result) (:error result)))
      (System/exit 1))))
