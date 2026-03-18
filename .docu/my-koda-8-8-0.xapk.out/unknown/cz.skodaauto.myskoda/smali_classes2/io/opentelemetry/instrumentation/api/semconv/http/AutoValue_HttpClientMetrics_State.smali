.class final Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;
.super Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics$State;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final startAttributes:Lio/opentelemetry/api/common/Attributes;

.field private final startTimeNanos:J


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/common/Attributes;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics$State;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 7
    .line 8
    iput-wide p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startTimeNanos:J

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 12
    .line 13
    const-string p1, "Null startAttributes"

    .line 14
    .line 15
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics$State;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics$State;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics$State;->startAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-wide v3, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startTimeNanos:J

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientMetrics$State;->startTimeNanos()J

    .line 27
    .line 28
    .line 29
    move-result-wide p0

    .line 30
    cmp-long p0, v3, p0

    .line 31
    .line 32
    if-nez p0, :cond_1

    .line 33
    .line 34
    return v0

    .line 35
    :cond_1
    return v2
.end method

.method public hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-wide v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startTimeNanos:J

    .line 13
    .line 14
    const/16 p0, 0x20

    .line 15
    .line 16
    ushr-long v3, v1, p0

    .line 17
    .line 18
    xor-long/2addr v1, v3

    .line 19
    long-to-int p0, v1

    .line 20
    xor-int/2addr p0, v0

    .line 21
    return p0
.end method

.method public startAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public startTimeNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startTimeNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "State{startAttributes="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", startTimeNanos="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/AutoValue_HttpClientMetrics_State;->startTimeNanos:J

    .line 19
    .line 20
    const-string p0, "}"

    .line 21
    .line 22
    invoke-static {v1, v2, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
