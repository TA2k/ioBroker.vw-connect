.class final Lio/opentelemetry/instrumentation/okhttp/v3_0/ContextInterceptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public intercept(Ld01/b0;)Ld01/t0;
    .locals 1

    .line 1
    move-object p0, p1

    .line 2
    check-cast p0, Li01/f;

    .line 3
    .line 4
    iget-object p0, p0, Li01/f;->e:Ld01/k0;

    .line 5
    .line 6
    invoke-static {p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->getCallingContextForRequest(Ld01/k0;)Lio/opentelemetry/context/Context;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :cond_0
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->initialize(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-interface {v0}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :try_start_0
    check-cast p1, Li01/f;

    .line 25
    .line 26
    invoke-virtual {p1, p0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 27
    .line 28
    .line 29
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V

    .line 33
    .line 34
    .line 35
    :cond_1
    return-object p0

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    :try_start_1
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catchall_1
    move-exception p1

    .line 44
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    :goto_0
    throw p0
.end method
