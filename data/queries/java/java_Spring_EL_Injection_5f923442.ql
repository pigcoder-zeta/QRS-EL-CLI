/**
 * @name Spring Expression Language Injection
 * @description User-controlled data flows into ExpressionParser.parseExpression,
 *              enabling arbitrary code execution via Spring EL.
 * @kind problem
 * @problem.severity error
 * @id java/spring-el-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SpelParseExpressionSink extends DataFlow::Node {
  SpelParseExpressionSink() {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName(
        "org.springframework.expression", "ExpressionParser", "parseExpression"
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module SpelInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SpelParseExpressionSink }
}

module SpelInjectionFlow = TaintTracking::Global<SpelInjectionConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SpelInjectionFlow::flow(source, sink)
select sink,
  "Spring EL injection: user-controlled data from $@ flows into parseExpression.",
  source, "user-controlled input"