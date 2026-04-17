/**
 * @name XML External Entity Injection (Java)
 * @description User-controlled XML is parsed without disabling external entities,
 *              enabling file disclosure or SSRF.
 * @kind problem
 * @problem.severity error
 * @id java/xxe
 * @tags security external/cwe/cwe-611
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

private class XxeSink extends DataFlow::Node {
  XxeSink() {
    exists(MethodCall mc |
      (
        mc.getMethod().hasQualifiedName("javax.xml.parsers", "DocumentBuilder", "parse") or
        mc.getMethod().hasQualifiedName("javax.xml.parsers", "SAXParser", "parse") or
        mc.getMethod().hasQualifiedName("org.xml.sax", "XMLReader", "parse") or
        mc.getMethod().hasQualifiedName("javax.xml.transform", "Transformer", "transform")
      ) and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

module XxeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof XxeSink }
}

module XxeFlow = TaintTracking::Global<XxeConfig>;

from DataFlow::Node source, DataFlow::Node sink
where XxeFlow::flow(source, sink)
select sink, "XXE: user-controlled XML from $@ flows into XML parser without disabling external entities.", source, "user input"