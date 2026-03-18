.class final Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;
.super Lio/opentelemetry/sdk/logs/SdkLogRecordData;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# instance fields
.field private final attributes:Lio/opentelemetry/api/common/Attributes;

.field private final bodyValue:Lio/opentelemetry/api/common/Value;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final eventName:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

.field private final observedTimestampEpochNanos:J

.field private final resource:Lio/opentelemetry/sdk/resources/Resource;

.field private final severity:Lio/opentelemetry/api/logs/Severity;

.field private final severityText:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final spanContext:Lio/opentelemetry/api/trace/SpanContext;

.field private final timestampEpochNanos:J

.field private final totalAttributeCount:I


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJLio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;ILio/opentelemetry/api/common/Value;Ljava/lang/String;)V
    .locals 0
    .param p9    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p12    # Lio/opentelemetry/api/common/Value;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p13    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "JJ",
            "Lio/opentelemetry/api/trace/SpanContext;",
            "Lio/opentelemetry/api/logs/Severity;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Attributes;",
            "I",
            "Lio/opentelemetry/api/common/Value<",
            "*>;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/SdkLogRecordData;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_4

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 7
    .line 8
    if-eqz p2, :cond_3

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 11
    .line 12
    iput-wide p3, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->timestampEpochNanos:J

    .line 13
    .line 14
    iput-wide p5, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->observedTimestampEpochNanos:J

    .line 15
    .line 16
    if-eqz p7, :cond_2

    .line 17
    .line 18
    iput-object p7, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 19
    .line 20
    if-eqz p8, :cond_1

    .line 21
    .line 22
    iput-object p8, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 23
    .line 24
    iput-object p9, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severityText:Ljava/lang/String;

    .line 25
    .line 26
    if-eqz p10, :cond_0

    .line 27
    .line 28
    iput-object p10, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 29
    .line 30
    iput p11, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->totalAttributeCount:I

    .line 31
    .line 32
    iput-object p12, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->bodyValue:Lio/opentelemetry/api/common/Value;

    .line 33
    .line 34
    iput-object p13, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->eventName:Ljava/lang/String;

    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 38
    .line 39
    const-string p1, "Null attributes"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 46
    .line 47
    const-string p1, "Null severity"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 54
    .line 55
    const-string p1, "Null spanContext"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 62
    .line 63
    const-string p1, "Null instrumentationScopeInfo"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    .line 70
    .line 71
    const-string p1, "Null resource"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/logs/SdkLogRecordData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/logs/SdkLogRecordData;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getResource()Lio/opentelemetry/sdk/resources/Resource;

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
    if-eqz v1, :cond_4

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 25
    .line 26
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_4

    .line 35
    .line 36
    iget-wide v3, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->timestampEpochNanos:J

    .line 37
    .line 38
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTimestampEpochNanos()J

    .line 39
    .line 40
    .line 41
    move-result-wide v5

    .line 42
    cmp-long v1, v3, v5

    .line 43
    .line 44
    if-nez v1, :cond_4

    .line 45
    .line 46
    iget-wide v3, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->observedTimestampEpochNanos:J

    .line 47
    .line 48
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getObservedTimestampEpochNanos()J

    .line 49
    .line 50
    .line 51
    move-result-wide v5

    .line 52
    cmp-long v1, v3, v5

    .line 53
    .line 54
    if-nez v1, :cond_4

    .line 55
    .line 56
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 57
    .line 58
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_4

    .line 67
    .line 68
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 69
    .line 70
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverity()Lio/opentelemetry/api/logs/Severity;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_4

    .line 79
    .line 80
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severityText:Ljava/lang/String;

    .line 81
    .line 82
    if-nez v1, :cond_1

    .line 83
    .line 84
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverityText()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    if-nez v1, :cond_4

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_1
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getSeverityText()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-eqz v1, :cond_4

    .line 100
    .line 101
    :goto_0
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 102
    .line 103
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_4

    .line 112
    .line 113
    iget v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->totalAttributeCount:I

    .line 114
    .line 115
    invoke-interface {p1}, Lio/opentelemetry/sdk/logs/data/LogRecordData;->getTotalAttributeCount()I

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    if-ne v1, v3, :cond_4

    .line 120
    .line 121
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->bodyValue:Lio/opentelemetry/api/common/Value;

    .line 122
    .line 123
    if-nez v1, :cond_2

    .line 124
    .line 125
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    if-nez v1, :cond_4

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_2
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordData;->getBodyValue()Lio/opentelemetry/api/common/Value;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    if-eqz v1, :cond_4

    .line 141
    .line 142
    :goto_1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->eventName:Ljava/lang/String;

    .line 143
    .line 144
    if-nez p0, :cond_3

    .line 145
    .line 146
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordData;->getEventName()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    if-nez p0, :cond_4

    .line 151
    .line 152
    goto :goto_2

    .line 153
    :cond_3
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/SdkLogRecordData;->getEventName()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result p0

    .line 161
    if-eqz p0, :cond_4

    .line 162
    .line 163
    :goto_2
    return v0

    .line 164
    :cond_4
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getBodyValue()Lio/opentelemetry/api/common/Value;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/api/common/Value<",
            "*>;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->bodyValue:Lio/opentelemetry/api/common/Value;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEventName()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->eventName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInstrumentationScopeInfo()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public getObservedTimestampEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->observedTimestampEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSeverity()Lio/opentelemetry/api/logs/Severity;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSeverityText()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severityText:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTimestampEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->timestampEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getTotalAttributeCount()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->totalAttributeCount:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 7

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->resource:Lio/opentelemetry/sdk/resources/Resource;

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
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-wide v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->timestampEpochNanos:J

    .line 21
    .line 22
    const/16 v4, 0x20

    .line 23
    .line 24
    ushr-long v5, v2, v4

    .line 25
    .line 26
    xor-long/2addr v2, v5

    .line 27
    long-to-int v2, v2

    .line 28
    xor-int/2addr v0, v2

    .line 29
    mul-int/2addr v0, v1

    .line 30
    iget-wide v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->observedTimestampEpochNanos:J

    .line 31
    .line 32
    ushr-long v4, v2, v4

    .line 33
    .line 34
    xor-long/2addr v2, v4

    .line 35
    long-to-int v2, v2

    .line 36
    xor-int/2addr v0, v2

    .line 37
    mul-int/2addr v0, v1

    .line 38
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    xor-int/2addr v0, v2

    .line 45
    mul-int/2addr v0, v1

    .line 46
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    xor-int/2addr v0, v2

    .line 53
    mul-int/2addr v0, v1

    .line 54
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severityText:Ljava/lang/String;

    .line 55
    .line 56
    const/4 v3, 0x0

    .line 57
    if-nez v2, :cond_0

    .line 58
    .line 59
    move v2, v3

    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    :goto_0
    xor-int/2addr v0, v2

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    xor-int/2addr v0, v2

    .line 74
    mul-int/2addr v0, v1

    .line 75
    iget v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->totalAttributeCount:I

    .line 76
    .line 77
    xor-int/2addr v0, v2

    .line 78
    mul-int/2addr v0, v1

    .line 79
    iget-object v2, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->bodyValue:Lio/opentelemetry/api/common/Value;

    .line 80
    .line 81
    if-nez v2, :cond_1

    .line 82
    .line 83
    move v2, v3

    .line 84
    goto :goto_1

    .line 85
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    :goto_1
    xor-int/2addr v0, v2

    .line 90
    mul-int/2addr v0, v1

    .line 91
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->eventName:Ljava/lang/String;

    .line 92
    .line 93
    if-nez p0, :cond_2

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    :goto_2
    xor-int p0, v0, v3

    .line 101
    .line 102
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SdkLogRecordData{resource="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", instrumentationScopeInfo="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->instrumentationScopeInfo:Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", timestampEpochNanos="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-wide v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->timestampEpochNanos:J

    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", observedTimestampEpochNanos="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->observedTimestampEpochNanos:J

    .line 39
    .line 40
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", spanContext="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", severity="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severity:Lio/opentelemetry/api/logs/Severity;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", severityText="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->severityText:Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", attributes="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", totalAttributeCount="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->totalAttributeCount:I

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", bodyValue="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->bodyValue:Lio/opentelemetry/api/common/Value;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", eventName="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object p0, p0, Lio/opentelemetry/sdk/logs/AutoValue_SdkLogRecordData;->eventName:Ljava/lang/String;

    .line 109
    .line 110
    const-string v1, "}"

    .line 111
    .line 112
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0
.end method
