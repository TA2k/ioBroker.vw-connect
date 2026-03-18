.class final Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/samplers/Sampler;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final NEGATIVE_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

.field private static final POSITIVE_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;


# instance fields
.field private final description:Ljava/lang/String;

.field private final idUpperBound:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/SamplingResult;->recordAndSample()Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->POSITIVE_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/SamplingResult;->drop()Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->NEGATIVE_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(DJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p3, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->idUpperBound:J

    .line 5
    .line 6
    new-instance p3, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string p4, "TraceIdRatioBased{"

    .line 9
    .line 10
    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1, p2}, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->decimalFormat(D)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const-string p2, "}"

    .line 18
    .line 19
    invoke-static {p3, p1, p2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->description:Ljava/lang/String;

    .line 24
    .line 25
    return-void
.end method

.method public static create(D)Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmpg-double v2, p0, v0

    .line 4
    .line 5
    if-ltz v2, :cond_2

    .line 6
    .line 7
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 8
    .line 9
    cmpl-double v2, p0, v2

    .line 10
    .line 11
    if-gtz v2, :cond_2

    .line 12
    .line 13
    cmpl-double v0, p0, v0

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    const-wide/high16 v0, -0x8000000000000000L

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    if-nez v2, :cond_1

    .line 21
    .line 22
    const-wide v0, 0x7fffffffffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const-wide/high16 v0, 0x43e0000000000000L    # 9.223372036854776E18

    .line 29
    .line 30
    mul-double/2addr v0, p0

    .line 31
    double-to-long v0, v0

    .line 32
    :goto_0
    new-instance v2, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;

    .line 33
    .line 34
    invoke-direct {v2, p0, p1, v0, v1}, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;-><init>(DJ)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 39
    .line 40
    const-string p1, "ratio must be in range [0.0, 1.0]"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0
.end method

.method private static decimalFormat(D)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/text/DecimalFormatSymbols;->getInstance(Ljava/util/Locale;)Ljava/text/DecimalFormatSymbols;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/16 v1, 0x2e

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/text/DecimalFormatSymbols;->setDecimalSeparator(C)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Ljava/text/DecimalFormat;

    .line 13
    .line 14
    const-string v2, "0.000000"

    .line 15
    .line 16
    invoke-direct {v1, v2, v0}, Ljava/text/DecimalFormat;-><init>(Ljava/lang/String;Ljava/text/DecimalFormatSymbols;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, p0, p1}, Ljava/text/NumberFormat;->format(D)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method private static getTraceIdRandomPart(Ljava/lang/String;)J
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->longFromBase16String(Ljava/lang/CharSequence;I)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    instance-of v0, p1, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;

    .line 8
    .line 9
    iget-wide v2, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->idUpperBound:J

    .line 10
    .line 11
    iget-wide p0, p1, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->idUpperBound:J

    .line 12
    .line 13
    cmp-long p0, v2, p0

    .line 14
    .line 15
    if-nez p0, :cond_1

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_1
    return v1
.end method

.method public getDescription()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdUpperBound()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->idUpperBound:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->idUpperBound:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
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
    invoke-static {p2}, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->getTraceIdRandomPart(Ljava/lang/String;)J

    .line 2
    .line 3
    .line 4
    move-result-wide p1

    .line 5
    invoke-static {p1, p2}, Ljava/lang/Math;->abs(J)J

    .line 6
    .line 7
    .line 8
    move-result-wide p1

    .line 9
    iget-wide p3, p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->idUpperBound:J

    .line 10
    .line 11
    cmp-long p0, p1, p3

    .line 12
    .line 13
    if-gez p0, :cond_0

    .line 14
    .line 15
    sget-object p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->POSITIVE_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object p0, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->NEGATIVE_SAMPLING_RESULT:Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 19
    .line 20
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/samplers/TraceIdRatioBasedSampler;->getDescription()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
