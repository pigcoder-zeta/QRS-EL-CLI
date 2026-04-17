/**
 * @name Information Exposure via HTTP response output or stack trace
 * @description Detects writing potentially sensitive data (including stack traces) to an HTTP response writer, or printing stack traces in web handlers, which may expose internal information (CWE-200).
 * @kind problem
 * @problem.severity warning
 * @id java/information-exposure
 * @tags security external/cwe/cwe-200
 */
import java
import semmle.code.java.dataflow.DataFlow

predicate isResponseGetWriterCall(MethodCall mc) {
  mc.getMethod().hasQualifiedName("javax.servlet.http", "HttpServletResponse", "getWriter")
}

predicate flowsFromResponseWriter(Expr e) {
  exists(MethodCall gw |
    isResponseGetWriterCall(gw) and
    (e = gw or DataFlow::localFlow(DataFlow::exprNode(gw), DataFlow::exprNode(e)))
  )
}

predicate isPrintWriterPrintln(MethodCall mc) {
  mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "println")
}

predicate isPrintStackTraceMethod(Method m) {
  m.hasQualifiedName("java.lang", "Throwable", "printStackTrace") or
  m.hasQualifiedName("java.lang", "Exception", "printStackTrace")
}

predicate isPrintlnToHttpResponse(MethodCall mc) {
  isPrintWriterPrintln(mc) and
  exists(Expr q | q = mc.getQualifier() and flowsFromResponseWriter(q))
}

predicate isPrintStackTraceToHttpResponse(MethodCall mc) {
  isPrintStackTraceMethod(mc.getMethod()) and
  exists(Expr arg0 | arg0 = mc.getArgument(0) and flowsFromResponseWriter(arg0)) and
  not exists(Expr arg1 | arg1 = mc.getArgument(1))
}

predicate isInMethodWithHttpServletResponseParam(Callable c) {
  exists(Method m, Parameter p, RefType rt |
    c = m and
    p = m.getParameter(_) and
    rt = p.getType() and
    rt.getDecl().hasQualifiedName("javax.servlet.http", "HttpServletResponse")
  )
}

predicate isWebContextPrintStackTrace(MethodCall mc) {
  isPrintStackTraceMethod(mc.getMethod()) and
  isInMethodWithHttpServletResponseParam(mc.getEnclosingCallable())
}

from MethodCall mc
where
  isPrintStackTraceToHttpResponse(mc) or
  isPrintlnToHttpResponse(mc) or
  isWebContextPrintStackTrace(mc)
select mc,
  case
    when isPrintStackTraceToHttpResponse(mc)
    then "Potential information exposure (CWE-200): stack trace written to HTTP response via printStackTrace."
    when isPrintlnToHttpResponse(mc)
    then "Potential information exposure (CWE-200): data written to HTTP response via PrintWriter.println."
    else "Potential information exposure (CWE-200): printStackTrace in a web handler may leak internal details."
  end