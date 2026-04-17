/**
 * @name Open Redirect
 * @description User-controlled data flows into URL redirection APIs, which may enable redirection to an untrusted site (CWE-601).
 * @kind problem
 * @problem.severity error
 * @id java/open-redirect
 * @tags security external/cwe/cwe-601
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class OpenRedirectSink extends DataFlow::Node {
  OpenRedirectSink() {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName("javax.servlet.http", "HttpServletResponse", "sendRedirect") and
      this.asExpr() = mc.getArgument(0)
    )
    or
    exists(ClassInstanceExpr cie |
      cie.getConstructor().getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "RedirectView") and
      this.asExpr() = cie.getArgument(0)
    )
  }
}

module OpenRedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof OpenRedirectSink }
}

module OpenRedirectFlow = TaintTracking::Global<OpenRedirectConfig>;

from DataFlow::Node source, DataFlow::Node sink
where OpenRedirectFlow::flow(source, sink)
select sink, "Open redirect: user-controlled data from $@ flows into a redirect URL.", source, "user-controlled input"