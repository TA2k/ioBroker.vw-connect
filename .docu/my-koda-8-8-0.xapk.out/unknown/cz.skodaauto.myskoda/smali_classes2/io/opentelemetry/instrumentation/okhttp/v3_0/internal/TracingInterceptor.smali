.class public final Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field private final instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "Ld01/b0;",
            "Ld01/t0;",
            ">;"
        }
    .end annotation
.end field

.field private final propagators:Lio/opentelemetry/context/propagation/ContextPropagators;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/propagation/ContextPropagators;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "Ld01/b0;",
            "Ld01/t0;",
            ">;",
            "Lio/opentelemetry/context/propagation/ContextPropagators;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 7
    .line 8
    return-void
.end method

.method private injectContextToRequest(Ld01/k0;Lio/opentelemetry/context/Context;)Ld01/k0;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ld01/k0;->b()Ld01/j0;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 6
    .line 7
    invoke-interface {p0}, Lio/opentelemetry/context/propagation/ContextPropagators;->getTextMapPropagator()Lio/opentelemetry/context/propagation/TextMapPropagator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    sget-object v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/RequestHeaderSetter;->INSTANCE:Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/RequestHeaderSetter;

    .line 12
    .line 13
    invoke-interface {p0, p2, p1, v0}, Lio/opentelemetry/context/propagation/TextMapPropagator;->inject(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapSetter;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ld01/k0;

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method


# virtual methods
.method public intercept(Ld01/b0;)Ld01/t0;
    .locals 5

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Li01/f;

    .line 3
    .line 4
    iget-object v0, v0, Li01/f;->e:Ld01/k0;

    .line 5
    .line 6
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-object v2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 11
    .line 12
    invoke-virtual {v2, v1, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->shouldStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_0

    .line 17
    .line 18
    check-cast p1, Li01/f;

    .line 19
    .line 20
    iget-object p0, p1, Li01/f;->e:Ld01/k0;

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    iget-object v2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 28
    .line 29
    invoke-virtual {v2, v1, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->start(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-direct {p0, v0, v1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->injectContextToRequest(Ld01/k0;Lio/opentelemetry/context/Context;)Ld01/k0;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const/4 v2, 0x0

    .line 38
    :try_start_0
    invoke-interface {v1}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    .line 39
    .line 40
    .line 41
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    :try_start_1
    move-object v4, p1

    .line 43
    check-cast v4, Li01/f;

    .line 44
    .line 45
    invoke-virtual {v4, v0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 46
    .line 47
    .line 48
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 49
    if-eqz v3, :cond_1

    .line 50
    .line 51
    :try_start_2
    invoke-interface {v3}, Lio/opentelemetry/context/Scope;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catchall_0
    move-exception v0

    .line 56
    goto :goto_2

    .line 57
    :cond_1
    :goto_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 58
    .line 59
    invoke-virtual {p0, v1, p1, v0, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->end(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 60
    .line 61
    .line 62
    return-object v0

    .line 63
    :catchall_1
    move-exception v0

    .line 64
    if-eqz v3, :cond_2

    .line 65
    .line 66
    :try_start_3
    invoke-interface {v3}, Lio/opentelemetry/context/Scope;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :catchall_2
    move-exception v3

    .line 71
    :try_start_4
    invoke-virtual {v0, v3}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 72
    .line 73
    .line 74
    :cond_2
    :goto_1
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 75
    :goto_2
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 76
    .line 77
    invoke-virtual {p0, v1, p1, v2, v0}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->end(Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 78
    .line 79
    .line 80
    throw v0
.end method
