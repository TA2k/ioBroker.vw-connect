.class abstract Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/samplers/SamplingResult;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field static final EMPTY_NOT_SAMPLED_OR_RECORDED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

.field static final EMPTY_RECORDED_AND_SAMPLED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

.field static final EMPTY_RECORDED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;->RECORD_AND_SAMPLE:Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->createWithoutAttributes(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->EMPTY_RECORDED_AND_SAMPLED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 8
    .line 9
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;->DROP:Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->createWithoutAttributes(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->EMPTY_NOT_SAMPLED_OR_RECORDED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 16
    .line 17
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;->RECORD_ONLY:Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->createWithoutAttributes(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->EMPTY_RECORDED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 24
    .line 25
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static createSamplingResult(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/samplers/AutoValue_ImmutableSamplingResult;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/sdk/trace/samplers/AutoValue_ImmutableSamplingResult;-><init>(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;Lio/opentelemetry/api/common/Attributes;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static createWithoutAttributes(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/samplers/AutoValue_ImmutableSamplingResult;

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/sdk/trace/samplers/AutoValue_ImmutableSamplingResult;-><init>(Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;Lio/opentelemetry/api/common/Attributes;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public abstract getAttributes()Lio/opentelemetry/api/common/Attributes;
.end method

.method public abstract getDecision()Lio/opentelemetry/sdk/trace/samplers/SamplingDecision;
.end method
