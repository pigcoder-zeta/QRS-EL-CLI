/****
 * @name Server-Side Template Injection
 * @description User-controlled data flows into template engine processing/evaluation APIs (FreeMarker, Velocity, Thymeleaf), potentially enabling code execution.
 * @kind problem
 * @problem.severity error
 * @id java/server-side-template-injection
 * @tags security external/cwe/cwe-094
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SstiSink extends DataFlow::Node {
  SstiSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("freemarker.template", "Template", "process") or
        mc.getMethod().hasQualifiedName("org.apache.velocity.app", "VelocityEngine", "evaluate") or
        mc.getMethod().hasQualifiedName("org.thymeleaf", "TemplateEngine", "process")
      ) and
      (
        this.asExpr() = mc.getArgument(0) or
        this.asExpr() = mc.getArgument(1)
      )
    )
  }
}

module SstiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SstiSink }
}

module SstiFlow = TaintTracking::Global<SstiConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SstiFlow::flow(source, sink)
select sink,
  "Server-side template injection: user-controlled data from $@ flows into a template processing/evaluation API.",
  source, "user-controlled input"