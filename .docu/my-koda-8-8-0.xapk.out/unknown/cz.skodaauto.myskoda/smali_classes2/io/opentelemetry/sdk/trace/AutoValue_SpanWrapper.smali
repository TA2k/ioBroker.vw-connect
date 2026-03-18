.class final Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;
.super Lio/opentelemetry/sdk/trace/SpanWrapper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final attributes:Lio/opentelemetry/api/common/Attributes;

.field private final delegate:Lio/opentelemetry/sdk/trace/SdkSpan;

.field private final endEpochNanos:J

.field private final internalHasEnded:Z

.field private final name:Ljava/lang/String;

.field private final resolvedEvents:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;"
        }
    .end annotation
.end field

.field private final resolvedLinks:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;"
        }
    .end annotation
.end field

.field private final status:Lio/opentelemetry/sdk/trace/data/StatusData;

.field private final totalAttributeCount:I

.field private final totalRecordedEvents:I

.field private final totalRecordedLinks:I


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/trace/SdkSpan;Ljava/util/List;Ljava/util/List;Lio/opentelemetry/api/common/Attributes;IIILio/opentelemetry/sdk/trace/data/StatusData;Ljava/lang/String;JZ)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/trace/SdkSpan;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;",
            "Lio/opentelemetry/api/common/Attributes;",
            "III",
            "Lio/opentelemetry/sdk/trace/data/StatusData;",
            "Ljava/lang/String;",
            "JZ)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SpanWrapper;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_5

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->delegate:Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 7
    .line 8
    if-eqz p2, :cond_4

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedLinks:Ljava/util/List;

    .line 11
    .line 12
    if-eqz p3, :cond_3

    .line 13
    .line 14
    iput-object p3, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedEvents:Ljava/util/List;

    .line 15
    .line 16
    if-eqz p4, :cond_2

    .line 17
    .line 18
    iput-object p4, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 19
    .line 20
    iput p5, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalAttributeCount:I

    .line 21
    .line 22
    iput p6, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedEvents:I

    .line 23
    .line 24
    iput p7, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedLinks:I

    .line 25
    .line 26
    if-eqz p8, :cond_1

    .line 27
    .line 28
    iput-object p8, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 29
    .line 30
    if-eqz p9, :cond_0

    .line 31
    .line 32
    iput-object p9, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->name:Ljava/lang/String;

    .line 33
    .line 34
    iput-wide p10, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->endEpochNanos:J

    .line 35
    .line 36
    iput-boolean p12, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->internalHasEnded:Z

    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 40
    .line 41
    const-string p1, "Null name"

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 48
    .line 49
    const-string p1, "Null status"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 56
    .line 57
    const-string p1, "Null attributes"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 64
    .line 65
    const-string p1, "Null resolvedEvents"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    .line 72
    .line 73
    const-string p1, "Null resolvedLinks"

    .line 74
    .line 75
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :cond_5
    new-instance p0, Ljava/lang/NullPointerException;

    .line 80
    .line 81
    const-string p1, "Null delegate"

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0
.end method


# virtual methods
.method public attributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public delegate()Lio/opentelemetry/sdk/trace/SdkSpan;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->delegate:Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 2
    .line 3
    return-object p0
.end method

.method public endEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->endEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

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
    instance-of v1, p1, Lio/opentelemetry/sdk/trace/SpanWrapper;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/trace/SpanWrapper;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->delegate:Lio/opentelemetry/sdk/trace/SdkSpan;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->delegate()Lio/opentelemetry/sdk/trace/SdkSpan;

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
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedLinks:Ljava/util/List;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->resolvedLinks()Ljava/util/List;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-interface {v1, v3}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedEvents:Ljava/util/List;

    .line 37
    .line 38
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->resolvedEvents()Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-interface {v1, v3}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 49
    .line 50
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->attributes()Lio/opentelemetry/api/common/Attributes;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalAttributeCount:I

    .line 61
    .line 62
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->totalAttributeCount()I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-ne v1, v3, :cond_1

    .line 67
    .line 68
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedEvents:I

    .line 69
    .line 70
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->totalRecordedEvents()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-ne v1, v3, :cond_1

    .line 75
    .line 76
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedLinks:I

    .line 77
    .line 78
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->totalRecordedLinks()I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    if-ne v1, v3, :cond_1

    .line 83
    .line 84
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 85
    .line 86
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->status()Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-eqz v1, :cond_1

    .line 95
    .line 96
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->name:Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->name()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    if-eqz v1, :cond_1

    .line 107
    .line 108
    iget-wide v3, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->endEpochNanos:J

    .line 109
    .line 110
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->endEpochNanos()J

    .line 111
    .line 112
    .line 113
    move-result-wide v5

    .line 114
    cmp-long v1, v3, v5

    .line 115
    .line 116
    if-nez v1, :cond_1

    .line 117
    .line 118
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->internalHasEnded:Z

    .line 119
    .line 120
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanWrapper;->internalHasEnded()Z

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-ne p0, p1, :cond_1

    .line 125
    .line 126
    return v0

    .line 127
    :cond_1
    return v2
.end method

.method public hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->delegate:Lio/opentelemetry/sdk/trace/SdkSpan;

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
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedLinks:Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {v2}, Ljava/util/List;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedEvents:Ljava/util/List;

    .line 21
    .line 22
    invoke-interface {v2}, Ljava/util/List;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    xor-int/2addr v0, v2

    .line 27
    mul-int/2addr v0, v1

    .line 28
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    xor-int/2addr v0, v2

    .line 35
    mul-int/2addr v0, v1

    .line 36
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalAttributeCount:I

    .line 37
    .line 38
    xor-int/2addr v0, v2

    .line 39
    mul-int/2addr v0, v1

    .line 40
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedEvents:I

    .line 41
    .line 42
    xor-int/2addr v0, v2

    .line 43
    mul-int/2addr v0, v1

    .line 44
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedLinks:I

    .line 45
    .line 46
    xor-int/2addr v0, v2

    .line 47
    mul-int/2addr v0, v1

    .line 48
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    xor-int/2addr v0, v2

    .line 55
    mul-int/2addr v0, v1

    .line 56
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->name:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    xor-int/2addr v0, v2

    .line 63
    mul-int/2addr v0, v1

    .line 64
    iget-wide v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->endEpochNanos:J

    .line 65
    .line 66
    const/16 v4, 0x20

    .line 67
    .line 68
    ushr-long v4, v2, v4

    .line 69
    .line 70
    xor-long/2addr v2, v4

    .line 71
    long-to-int v2, v2

    .line 72
    xor-int/2addr v0, v2

    .line 73
    mul-int/2addr v0, v1

    .line 74
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->internalHasEnded:Z

    .line 75
    .line 76
    if-eqz p0, :cond_0

    .line 77
    .line 78
    const/16 p0, 0x4cf

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_0
    const/16 p0, 0x4d5

    .line 82
    .line 83
    :goto_0
    xor-int/2addr p0, v0

    .line 84
    return p0
.end method

.method public internalHasEnded()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->internalHasEnded:Z

    .line 2
    .line 3
    return p0
.end method

.method public name()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public resolvedEvents()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/EventData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedEvents:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public resolvedLinks()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->resolvedLinks:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public status()Lio/opentelemetry/sdk/trace/data/StatusData;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->status:Lio/opentelemetry/sdk/trace/data/StatusData;

    .line 2
    .line 3
    return-object p0
.end method

.method public totalAttributeCount()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalAttributeCount:I

    .line 2
    .line 3
    return p0
.end method

.method public totalRecordedEvents()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedEvents:I

    .line 2
    .line 3
    return p0
.end method

.method public totalRecordedLinks()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanWrapper;->totalRecordedLinks:I

    .line 2
    .line 3
    return p0
.end method
