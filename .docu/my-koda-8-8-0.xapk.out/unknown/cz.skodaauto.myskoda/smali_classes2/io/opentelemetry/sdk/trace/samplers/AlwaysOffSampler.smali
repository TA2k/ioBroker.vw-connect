.class final enum Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/samplers/Sampler;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;",
        ">;",
        "Lio/opentelemetry/sdk/trace/samplers/Sampler;"
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

.field public static final enum INSTANCE:Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->INSTANCE:Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->INSTANCE:Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->$values()[Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->$VALUES:[Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 16
    .line 17
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->$VALUES:[Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public getDescription()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "AlwaysOffSampler"

    .line 2
    .line 3
    return-object p0
.end method

.method public shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;
    .locals 0
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

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/trace/samplers/ImmutableSamplingResult;->EMPTY_NOT_SAMPLED_OR_RECORDED_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/samplers/AlwaysOffSampler;->getDescription()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
