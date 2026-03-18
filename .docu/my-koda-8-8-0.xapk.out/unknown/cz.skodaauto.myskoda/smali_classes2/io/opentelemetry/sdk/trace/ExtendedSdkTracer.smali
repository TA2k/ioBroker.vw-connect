.class final Lio/opentelemetry/sdk/trace/ExtendedSdkTracer;
.super Lio/opentelemetry/sdk/trace/SdkTracer;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/incubator/trace/ExtendedTracer;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/sdk/trace/SdkTracer;-><init>(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public isEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/SdkTracer;->tracerEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;
    .locals 0

    .line 2
    invoke-super {p0, p1}, Lio/opentelemetry/sdk/trace/SdkTracer;->spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    return-object p0
.end method

.method public bridge synthetic spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/trace/SpanBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/trace/ExtendedSdkTracer;->spanBuilder(Ljava/lang/String;)Lio/opentelemetry/api/incubator/trace/ExtendedSpanBuilder;

    move-result-object p0

    return-object p0
.end method
