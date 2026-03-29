/**
 * @name Expression Language Injection
 * @description Detects Expression Language (EL) injection vulnerabilities where user-controlled input is directly used in expression evaluation.
 * @kind problem
 * @problem.severity error
 * @id java/el-injection
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow

/**
 * A data flow node that represents a user-controlled input source.
 */
class Source extends DataFlow::Node {
  Source() {
    // Common Servlet API methods for retrieving user input
    exists(MethodCall mc |
      (
        mc.getCallee().hasQualifiedName("javax.servlet.http", "HttpServletRequest", "getParameter") or
        mc.getCallee().hasQualifiedName("javax.servlet.http", "HttpServletRequest", "getParameterValues") or
        mc.getCallee().hasQualifiedName("javax.servlet", "ServletRequest", "getParameter")
      ) and
      this = DataFlow::exprNode(mc)
    )
    or
    // HttpServletRequest.getParameterMap() returns a Map whose values are user-controlled
    exists(MethodCall mc |
      mc.getCallee().hasQualifiedName("javax.servlet.http", "HttpServletRequest", "getParameterMap") and
      this = DataFlow::exprNode(mc)
    )
    or
    // Spring Framework annotations for method parameters
    exists(Parameter p |
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        (p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") and p.getType().hasQualifiedName("java.lang", "String"))
      ) and
      this = DataFlow::parameterNode(p)
    )
  }
}

/**
 * A data flow node that represents a sink for Expression Language evaluation.
 */
class Sink extends DataFlow::Node {
  Sink() {
    exists(MethodCall mc |
      // Spring Expression Language (SpEL)
      (
        mc.getCallee().hasQualifiedName("org.springframework.expression", "ExpressionParser", "parseExpression") and
        this = DataFlow::exprNode(mc.getArgument(0)) // The expression string is the first argument
      )
      or
      // OGNL (Object-Graph Navigation Language)
      (
        mc.getCallee().hasQualifiedName("ognl", "Ognl", "getValue") and
        this = DataFlow::exprNode(mc.getArgument(0)) // The expression string is the first argument
      )
      or
      // MVEL (MVFLEX Expression Language)
      (
        mc.getCallee().hasQualifiedName("org.mvel2", "MVEL", "eval") and
        this = DataFlow::exprNode(mc.getArgument(0)) // The expression string is the first argument
      )
      or
      // Standard Java Expression Language (JSP/JSF EL)
      (
        mc.getCallee().hasQualifiedName("javax.el", "ExpressionFactory", "createValueExpression") and
        this = DataFlow::exprNode(mc.getArgument(1)) // The expression string is the second argument
      )
    )
  }
}

/**
 * Defines the taint tracking configuration for EL injection.
 */
module ElInjectionFlowConfig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }
}

/**
 * Performs a global taint tracking analysis using the defined configuration.
 */
module ElInjectionFlow = TaintTracking::Global<ElInjectionFlowConfig>;

from DataFlow::Node src, DataFlow::Node sink
where ElInjectionFlow::flow(src, sink)
select sink, "User-controlled data from $@ flows into an Expression Language evaluation sink, leading to potential EL injection.", src, "this user input"