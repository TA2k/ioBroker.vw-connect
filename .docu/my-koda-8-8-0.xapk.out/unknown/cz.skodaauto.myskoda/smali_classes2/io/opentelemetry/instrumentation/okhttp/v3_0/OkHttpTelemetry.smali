.class public final Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 7
    .line 8
    return-void
.end method

.method public static builder(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;-><init>(Lio/opentelemetry/api/OpenTelemetry;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;->builder(Lio/opentelemetry/api/OpenTelemetry;)Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetryBuilder;->build()Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public newCallFactory(Ld01/h0;)Ld01/i;
    .locals 4

    .line 1
    invoke-virtual {p1}, Ld01/h0;->a()Ld01/g0;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p1, Ld01/g0;->c:Ljava/util/ArrayList;

    .line 6
    .line 7
    new-instance v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/ContextInterceptor;

    .line 8
    .line 9
    invoke-direct {v1}, Lio/opentelemetry/instrumentation/okhttp/v3_0/ContextInterceptor;-><init>()V

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-virtual {v0, v2, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;

    .line 17
    .line 18
    iget-object v3, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 19
    .line 20
    invoke-direct {v1, v3}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/ConnectionErrorSpanInterceptor;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;)V

    .line 21
    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    invoke-virtual {v0, v3, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, p1, Ld01/g0;->d:Ljava/util/ArrayList;

    .line 28
    .line 29
    new-instance v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;

    .line 30
    .line 31
    iget-object v3, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;->instrumenter:Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;

    .line 32
    .line 33
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/OkHttpTelemetry;->propagators:Lio/opentelemetry/context/propagation/ContextPropagators;

    .line 34
    .line 35
    invoke-direct {v1, v3, p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/internal/TracingInterceptor;-><init>(Lio/opentelemetry/instrumentation/api/instrumenter/Instrumenter;Lio/opentelemetry/context/propagation/ContextPropagators;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v2, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    new-instance p0, Ld01/h0;

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ld01/h0;-><init>(Ld01/g0;)V

    .line 44
    .line 45
    .line 46
    new-instance p1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;

    .line 47
    .line 48
    invoke-direct {p1, p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;-><init>(Ld01/h0;)V

    .line 49
    .line 50
    .line 51
    return-object p1
.end method
