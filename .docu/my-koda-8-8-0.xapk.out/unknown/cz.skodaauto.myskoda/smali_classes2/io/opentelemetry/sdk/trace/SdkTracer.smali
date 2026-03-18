.class Lio/opentelemetry/sdk/trace/SdkTracer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/trace/Tracer;


# static fields
.field static final FALLBACK_SPAN_NAME:Ljava/lang/String; = "<unspecified span name>"

.field private static final INCUBATOR_AVAILABLE:Z

.field private static final NOOP_TRACER:Lio/opentelemetry/api/trace/Tracer;


# instance fields
.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private final sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

.field protected volatile tracerEnabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/TracerProvider;->noop()Lio/opentelemetry/api/trace/TracerProvider;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "noop"

    .line 6
    .line 7
    invoke-interface {v0, v1}, Lio/opentelemetry/api/trace/TracerProvider;->get(Ljava/lang/String;)Lio/opentelemetry/api/trace/Tracer;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/trace/SdkTracer;->NOOP_TRACER:Lio/opentelemetry/api/trace/Tracer;

    .line 12
    .line 13
    :try_start_0
    sget v0, Lio/opentelemetry/api/incubator/trace/ExtendedDefaultTracerProvider;->d:I
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    goto :goto_0

    .line 17
    :catch_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    sput-boolean v0, Lio/opentelemetry/sdk/trace/SdkTracer;->INCUBATOR_AVAILABLE:Z

    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 7
    .line 8
    invoke-virtual {p3}, Lio/opentelemetry/sdk/trace/internal/TracerConfig;->isEnabled()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iput-boolean p1, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->tracerEnabled:Z

    .line 13
    .line 14
    return-void
.end method

.method public static create(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)Lio/opentelemetry/sdk/trace/SdkTracer;
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/sdk/trace/SdkTracer;->INCUBATOR_AVAILABLE:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/trace/IncubatingUtil;->createExtendedTracer(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)Lio/opentelemetry/sdk/trace/SdkTracer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/trace/SdkTracer;

    .line 11
    .line 12
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/trace/SdkTracer;-><init>(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method


# virtual methods
.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->tracerEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->tracerEnabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lio/opentelemetry/sdk/trace/SdkTracer;->NOOP_TRACER:Lio/opentelemetry/api/trace/Tracer;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Lio/opentelemetry/api/trace/Tracer;->spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    if-eqz p1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    :cond_1
    const-string p1, "<unspecified span name>"

    .line 25
    .line 26
    :cond_2
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 27
    .line 28
    invoke-virtual {v0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->hasBeenShutdown()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    sget-object p0, Lio/opentelemetry/sdk/trace/SdkTracer;->NOOP_TRACER:Lio/opentelemetry/api/trace/Tracer;

    .line 35
    .line 36
    invoke-interface {p0, p1}, Lio/opentelemetry/api/trace/Tracer;->spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_3
    sget-boolean v0, Lio/opentelemetry/sdk/trace/SdkTracer;->INCUBATOR_AVAILABLE:Z

    .line 42
    .line 43
    if-eqz v0, :cond_4

    .line 44
    .line 45
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 46
    .line 47
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 48
    .line 49
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSpanLimits()Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-static {p1, v0, p0, v1}, Lio/opentelemetry/sdk/trace/IncubatingUtil;->createExtendedSpanBuilder(Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/trace/SpanLimits;)Lio/opentelemetry/sdk/trace/SdkSpanBuilder;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :cond_4
    new-instance v0, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;

    .line 59
    .line 60
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 61
    .line 62
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->sharedState:Lio/opentelemetry/sdk/trace/TracerSharedState;

    .line 63
    .line 64
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/TracerSharedState;->getSpanLimits()Lio/opentelemetry/sdk/trace/SpanLimits;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    invoke-direct {v0, p1, v1, p0, v2}, Lio/opentelemetry/sdk/trace/SdkSpanBuilder;-><init>(Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/trace/SpanLimits;)V

    .line 69
    .line 70
    .line 71
    return-object v0
.end method

.method public updateTracerConfig(Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/internal/TracerConfig;->isEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput-boolean p1, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->tracerEnabled:Z

    .line 6
    .line 7
    return-void
.end method
