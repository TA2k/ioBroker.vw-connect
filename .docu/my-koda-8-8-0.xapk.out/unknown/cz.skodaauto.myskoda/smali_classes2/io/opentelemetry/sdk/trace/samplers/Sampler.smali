.class public interface abstract Lio/opentelemetry/sdk/trace/samplers/Sampler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/ThreadSafe;
.end annotation


# direct methods
.method public static alwaysOff()Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->INSTANCE:Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 2
    .line 3
    return-object v0
.end method

.method public static alwaysOn()Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOnSampler;->INSTANCE:Lio/opentelemetry/sdk/trace/samplers/AlwaysOnSampler;

    .line 2
    .line 3
    return-object v0
.end method

.method public static parentBased(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->parentBasedBuilder(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;->build()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static parentBasedBuilder(Lio/opentelemetry/sdk/trace/samplers/Sampler;)Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSamplerBuilder;-><init>(Lio/opentelemetry/sdk/trace/samplers/Sampler;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static traceIdRatioBased(D)Lio/opentelemetry/sdk/trace/samplers/Sampler;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->create(D)Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getDescription()Ljava/lang/String;
.end method

.method public abstract shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/trace/SpanKind;",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;)",
            "Lio/opentelemetry/sdk/trace/samplers/SamplingResult;"
        }
    .end annotation
.end method
