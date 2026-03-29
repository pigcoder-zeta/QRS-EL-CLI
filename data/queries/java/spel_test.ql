/**
 * @name Spring Expression Language Injection
 * @description User-controlled data flows into a Spring EL parseExpression call.
 * @kind problem
 * @problem.severity error
 * @id java/spring-el-injection
 * @tags security
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class ParseExpressionSink extends DataFlow::Node {
  ParseExpressionSink() {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module SpElInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof ParseExpressionSink }
}

module SpElInjectionFlow = TaintTracking::Global<SpElInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SpElInjectionFlow::flow(source, sink)
select sink, "Spring EL injection: data from $@ reaches parseExpression.", source, "user-controlled input"
