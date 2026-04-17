/**
 * @name Server-Side Request Forgery (SSRF)
 * @description User-controlled URL flows into HTTP request without validation.
 * @kind problem
 * @problem.severity error
 * @id java/ssrf
 * @tags security external/cwe/cwe-918
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class SsrfSink extends DataFlow::Node {
  SsrfSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("java.net", "URL", "openConnection") or
        mc.getMethod().hasQualifiedName("java.net", "URL", "openStream") or
        mc.getMethod().hasQualifiedName("org.springframework.web.client", "RestTemplate", "getForObject") or
        mc.getMethod().hasQualifiedName("org.springframework.web.client", "RestTemplate", "postForObject")
      ) and
      this.asExpr() = mc.getQualifier()
    )
    or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = cc.getArgument(0)
    )
  }
}

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof SsrfSink }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from DataFlow::Node source, DataFlow::Node sink
where SsrfFlow::flow(source, sink)
select sink, "SSRF: user-controlled URL from $@ flows into HTTP request.", source, "user input"
