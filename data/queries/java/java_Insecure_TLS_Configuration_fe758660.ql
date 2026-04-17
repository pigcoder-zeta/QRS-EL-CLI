/**
 * @name Insecure TLS configuration (improper certificate validation)
 * @description Detects code patterns that disable hostname verification or install a permissive TrustManager in TLS configuration (CWE-295).
 * @kind problem
 * @problem.severity warning
 * @id java/insecure-tls-configuration
 * @tags security
 *       external/cwe/cwe-295
 *       cryptography
 */
import java

private predicate isNoopHostnameVerifierExpr(Expr e) {
  exists(FieldAccess fa |
    fa.getField().hasQualifiedName("org.apache.http.conn.ssl", "NoopHostnameVerifier", "INSTANCE") and
    e = fa
  )
  or
  exists(ClassInstanceExpr cie |
    cie.getConstructedType().hasQualifiedName("org.apache.http.conn.ssl", "NoopHostnameVerifier") and
    e = cie
  )
}

private predicate isAlwaysTrueHostnameVerifierExpr(Expr e) {
  exists(ClassInstanceExpr cie, AnonymousClass ac, Method verify, ReturnStmt rs, BooleanLiteral bl |
    e = cie and
    cie.getConstructedType().hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
    cie.getAnonymousClass() = ac and
    verify = ac.getAMethod() and
    verify.getName() = "verify" and
    rs.getEnclosingCallable() = verify and
    bl = rs.getExpr() and
    bl.getBooleanValue() = true
  )
}

private predicate hasEmptyBlockBody(Method m) {
  exists(BlockStmt b |
    b = m.getBody() and
    b.getNumStmt() = 0
  )
}

private predicate isTrustAllX509TrustManagerExpr(Expr e) {
  exists(ClassInstanceExpr cie, AnonymousClass ac, Method m1, Method m2, Method m3, ReturnStmt rs |
    e = cie and
    cie.getConstructedType().hasQualifiedName("javax.net.ssl", "X509TrustManager") and
    cie.getAnonymousClass() = ac and
    m1 = ac.getAMethod() and m1.getName() = "checkServerTrusted" and hasEmptyBlockBody(m1) and
    m2 = ac.getAMethod() and m2.getName() = "checkClientTrusted" and hasEmptyBlockBody(m2) and
    m3 = ac.getAMethod() and m3.getName() = "getAcceptedIssuers" and
    rs.getEnclosingCallable() = m3 and
    rs.getExpr() instanceof NullLiteral
  )
}

private predicate isTrustManagerArrayWithTrustAll(Expr trustManagersArg) {
  exists(ArrayCreationExpr ace, ArrayInitializer ai, int i, Expr init |
    trustManagersArg = ace and
    ai = ace.getAChild() and
    i >= 0 and i < ai.getNumInit() and
    init = ai.getInit(i) and
    isTrustAllX509TrustManagerExpr(init)
  )
}

from Expr e
where
  exists(MethodCall mc |
    mc.getMethod().hasQualifiedName("javax.net.ssl", "HttpsURLConnection", "setHostnameVerifier") and
    mc.getNumArgument() >= 1 and
    (
      isNoopHostnameVerifierExpr(mc.getArgument(0)) or
      isAlwaysTrueHostnameVerifierExpr(mc.getArgument(0))
    ) and
    e = mc
  )
  or
  exists(MethodCall mc |
    mc.getMethod().hasQualifiedName("javax.net.ssl", "SSLContext", "init") and
    mc.getNumArgument() >= 2 and
    isTrustManagerArrayWithTrustAll(mc.getArgument(1)) and
    e = mc
  )
  or
  isNoopHostnameVerifierExpr(e)
select e, "Potentially insecure TLS configuration (CWE-295): hostname verification disabled or a permissive TrustManager is used."