/**
 * @name MVEL Expression Injection
 * @description User-controlled data flows into MVEL.eval or MVEL.executeExpression.
 * @kind problem
 * @problem.severity error
 * @id java/mvel-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private predicate isMvelExpressionEvaluatorCall(MethodCall mc) {
  mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "eval") or
  mc.getMethod().hasQualifiedName("org.mvel2", "MVEL", "executeExpression")
}

private class MvelSink extends DataFlow::Node {
  MvelSink() {
    exists(MethodCall mc |
      isMvelExpressionEvaluatorCall(mc) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module MvelInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof MvelSink }
}

module MvelInjectionFlow = TaintTracking::Global<MvelInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where MvelInjectionFlow::flow(source, sink)
select sink,
  "MVEL injection: user-controlled data from $@ flows into MVEL expression evaluator.",
  source, "user-controlled input"