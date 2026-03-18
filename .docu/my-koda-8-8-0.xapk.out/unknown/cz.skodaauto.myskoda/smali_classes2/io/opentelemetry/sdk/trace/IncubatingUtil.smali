.class final Lio/opentelemetry/sdk/trace/IncubatingUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static createExtendedSpanBuilder(Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/trace/SpanLimits;)Lio/opentelemetry/sdk/trace/SdkSpanBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/ExtendedSdkSpanBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2, p3}, Lio/opentelemetry/sdk/trace/ExtendedSdkSpanBuilder;-><init>(Ljava/lang/String;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/trace/SpanLimits;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static createExtendedTracer(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)Lio/opentelemetry/sdk/trace/SdkTracer;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/ExtendedSdkTracer;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2}, Lio/opentelemetry/sdk/trace/ExtendedSdkTracer;-><init>(Lio/opentelemetry/sdk/trace/TracerSharedState;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;Lio/opentelemetry/sdk/trace/internal/TracerConfig;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
