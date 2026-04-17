/**
 * @name 可能的信息泄露：向响应输出/打印堆栈
 * @description 检测可能导致敏感信息暴露给未授权方的危险 API 使用（如向 HttpServletResponse 输出内容、使用 PrintWriter.println、或打印异常堆栈）。
 * @kind problem
 * @problem.severity warning
 * @id java/information-exposure
 * @tags security
 *       external/cwe/cwe-200
 */
import java

from MethodCall mc
where
  mc.getMethod().hasQualifiedName("javax.servlet.http", "HttpServletResponse", "getWriter") or
  mc.getMethod().hasQualifiedName("java.io", "PrintWriter", "println") or
  mc.getMethod().hasQualifiedName("java.lang", "Exception", "printStackTrace") or
  mc.getMethod().hasQualifiedName("java.lang", "Throwable", "printStackTrace")
select mc,
  "可能的信息泄露（CWE-200）：调用了潜在危险的输出/堆栈打印方法 '" +
    mc.getMethod().getDeclaringType().getQualifiedName() + "." + mc.getMethod().getName() +
  "'，可能将敏感信息暴露给未授权方。"