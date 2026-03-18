.class public final Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;
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


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter<",
            "Ld01/b0;",
            "Ld01/t0;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public intercept(Ld01/b0;)Ld01/t0;
    .locals 8

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
    move-result-object v2

    .line 10
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 11
    .line 12
    .line 13
    move-result-object v6

    .line 14
    :try_start_0
    move-object v1, p1

    .line 15
    check-cast v1, Li01/f;

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 18
    .line 19
    .line 20
    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-static {v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->get(Lio/opentelemetry/context/Context;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 28
    .line 29
    invoke-virtual {v0, v2, p1}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->shouldStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    iget-object v1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 36
    .line 37
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 38
    .line 39
    .line 40
    move-result-object v7

    .line 41
    const/4 v5, 0x0

    .line 42
    move-object v3, p1

    .line 43
    invoke-static/range {v1 .. v7}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->startAndEnd(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 44
    .line 45
    .line 46
    :cond_0
    return-object v4

    .line 47
    :catchall_0
    move-exception v0

    .line 48
    move-object v3, p1

    .line 49
    move-object p1, v0

    .line 50
    move-object v5, p1

    .line 51
    :try_start_1
    throw v5
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 52
    :catchall_1
    move-exception v0

    .line 53
    move-object p1, v0

    .line 54
    invoke-static {v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientRequestResendCount;->get(Lio/opentelemetry/context/Context;)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_1

    .line 59
    .line 60
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 61
    .line 62
    invoke-virtual {v0, v2, v3}, Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;->shouldStart(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_1

    .line 67
    .line 68
    iget-object v1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 69
    .line 70
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    const/4 v4, 0x0

    .line 75
    invoke-static/range {v1 .. v7}, Lio/opentelemetry/instrumentation/api/internal/InstrumenterUtil;->startAndEnd(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;Ljava/time/Instant;Ljava/time/Instant;)Lio/opentelemetry/context/Context;

    .line 76
    .line 77
    .line 78
    :cond_1
    throw p1
.end method
