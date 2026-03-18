.class public final Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;


# instance fields
.field private attributes:Lio/opentelemetry/api/common/Attributes;

.field private count:J

.field private epochNanos:J

.field private exemplars:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;"
        }
    .end annotation
.end field

.field private hasMax:Z

.field private hasMin:Z

.field private max:D

.field private min:D

.field private negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

.field private positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

.field private scale:I

.field private startEpochNanos:J

.field private sum:D

.field private zeroCount:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;->get(I)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 16
    .line 17
    invoke-static {v0}, Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;->get(I)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 22
    .line 23
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 24
    .line 25
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->exemplars:Ljava/util/List;

    .line 26
    .line 27
    return-void
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
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    .line 11
    .line 12
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->startEpochNanos:J

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    .line 15
    .line 16
    .line 17
    move-result-wide v5

    .line 18
    cmp-long v1, v3, v5

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->epochNanos:J

    .line 23
    .line 24
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    .line 25
    .line 26
    .line 27
    move-result-wide v5

    .line 28
    cmp-long v1, v3, v5

    .line 29
    .line 30
    if-nez v1, :cond_1

    .line 31
    .line 32
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 33
    .line 34
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->scale:I

    .line 45
    .line 46
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getScale()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-ne v1, v3, :cond_1

    .line 51
    .line 52
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->sum:D

    .line 53
    .line 54
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 55
    .line 56
    .line 57
    move-result-wide v3

    .line 58
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getSum()D

    .line 59
    .line 60
    .line 61
    move-result-wide v5

    .line 62
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 63
    .line 64
    .line 65
    move-result-wide v5

    .line 66
    cmp-long v1, v3, v5

    .line 67
    .line 68
    if-nez v1, :cond_1

    .line 69
    .line 70
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->count:J

    .line 71
    .line 72
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getCount()J

    .line 73
    .line 74
    .line 75
    move-result-wide v5

    .line 76
    cmp-long v1, v3, v5

    .line 77
    .line 78
    if-nez v1, :cond_1

    .line 79
    .line 80
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->zeroCount:J

    .line 81
    .line 82
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getZeroCount()J

    .line 83
    .line 84
    .line 85
    move-result-wide v5

    .line 86
    cmp-long v1, v3, v5

    .line 87
    .line 88
    if-nez v1, :cond_1

    .line 89
    .line 90
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMin:Z

    .line 91
    .line 92
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMin()Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    if-ne v1, v3, :cond_1

    .line 97
    .line 98
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->min:D

    .line 99
    .line 100
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 101
    .line 102
    .line 103
    move-result-wide v3

    .line 104
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMin()D

    .line 105
    .line 106
    .line 107
    move-result-wide v5

    .line 108
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 109
    .line 110
    .line 111
    move-result-wide v5

    .line 112
    cmp-long v1, v3, v5

    .line 113
    .line 114
    if-nez v1, :cond_1

    .line 115
    .line 116
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMax:Z

    .line 117
    .line 118
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->hasMax()Z

    .line 119
    .line 120
    .line 121
    move-result v3

    .line 122
    if-ne v1, v3, :cond_1

    .line 123
    .line 124
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->max:D

    .line 125
    .line 126
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 127
    .line 128
    .line 129
    move-result-wide v3

    .line 130
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getMax()D

    .line 131
    .line 132
    .line 133
    move-result-wide v5

    .line 134
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 135
    .line 136
    .line 137
    move-result-wide v5

    .line 138
    cmp-long v1, v3, v5

    .line 139
    .line 140
    if-nez v1, :cond_1

    .line 141
    .line 142
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 143
    .line 144
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-eqz v1, :cond_1

    .line 153
    .line 154
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 155
    .line 156
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-eqz v1, :cond_1

    .line 165
    .line 166
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->exemplars:Ljava/util/List;

    .line 167
    .line 168
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;->getExemplars()Ljava/util/List;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    invoke-interface {p0, p1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result p0

    .line 176
    if-eqz p0, :cond_1

    .line 177
    .line 178
    return v0

    .line 179
    :cond_1
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCount()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->count:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->epochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getExemplars()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->exemplars:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMax()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->max:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public getMin()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->min:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScale()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->scale:I

    .line 2
    .line 3
    return p0
.end method

.method public getStartEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->startEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getSum()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->sum:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public getZeroCount()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->zeroCount:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hasMax()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMax:Z

    .line 2
    .line 3
    return p0
.end method

.method public hasMin()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMin:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 10

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->startEpochNanos:J

    .line 2
    .line 3
    const/16 v2, 0x20

    .line 4
    .line 5
    ushr-long v3, v0, v2

    .line 6
    .line 7
    xor-long/2addr v0, v3

    .line 8
    long-to-int v0, v0

    .line 9
    const v1, 0xf4243

    .line 10
    .line 11
    .line 12
    xor-int/2addr v0, v1

    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->epochNanos:J

    .line 15
    .line 16
    ushr-long v5, v3, v2

    .line 17
    .line 18
    xor-long/2addr v3, v5

    .line 19
    long-to-int v3, v3

    .line 20
    xor-int/2addr v0, v3

    .line 21
    mul-int/2addr v0, v1

    .line 22
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    xor-int/2addr v0, v3

    .line 29
    mul-int/2addr v0, v1

    .line 30
    iget v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->scale:I

    .line 31
    .line 32
    xor-int/2addr v0, v3

    .line 33
    mul-int/2addr v0, v1

    .line 34
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->sum:D

    .line 35
    .line 36
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 37
    .line 38
    .line 39
    move-result-wide v3

    .line 40
    ushr-long/2addr v3, v2

    .line 41
    iget-wide v5, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->sum:D

    .line 42
    .line 43
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 44
    .line 45
    .line 46
    move-result-wide v5

    .line 47
    xor-long/2addr v3, v5

    .line 48
    long-to-int v3, v3

    .line 49
    xor-int/2addr v0, v3

    .line 50
    mul-int/2addr v0, v1

    .line 51
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->count:J

    .line 52
    .line 53
    ushr-long v5, v3, v2

    .line 54
    .line 55
    xor-long/2addr v3, v5

    .line 56
    long-to-int v3, v3

    .line 57
    xor-int/2addr v0, v3

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->zeroCount:J

    .line 60
    .line 61
    ushr-long v5, v3, v2

    .line 62
    .line 63
    xor-long/2addr v3, v5

    .line 64
    long-to-int v3, v3

    .line 65
    xor-int/2addr v0, v3

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-boolean v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMin:Z

    .line 68
    .line 69
    const/16 v4, 0x4d5

    .line 70
    .line 71
    const/16 v5, 0x4cf

    .line 72
    .line 73
    if-eqz v3, :cond_0

    .line 74
    .line 75
    move v3, v5

    .line 76
    goto :goto_0

    .line 77
    :cond_0
    move v3, v4

    .line 78
    :goto_0
    xor-int/2addr v0, v3

    .line 79
    mul-int/2addr v0, v1

    .line 80
    iget-wide v6, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->min:D

    .line 81
    .line 82
    invoke-static {v6, v7}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 83
    .line 84
    .line 85
    move-result-wide v6

    .line 86
    ushr-long/2addr v6, v2

    .line 87
    iget-wide v8, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->min:D

    .line 88
    .line 89
    invoke-static {v8, v9}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 90
    .line 91
    .line 92
    move-result-wide v8

    .line 93
    xor-long/2addr v6, v8

    .line 94
    long-to-int v3, v6

    .line 95
    xor-int/2addr v0, v3

    .line 96
    mul-int/2addr v0, v1

    .line 97
    iget-boolean v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMax:Z

    .line 98
    .line 99
    if-eqz v3, :cond_1

    .line 100
    .line 101
    move v4, v5

    .line 102
    :cond_1
    xor-int/2addr v0, v4

    .line 103
    mul-int/2addr v0, v1

    .line 104
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->max:D

    .line 105
    .line 106
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 107
    .line 108
    .line 109
    move-result-wide v3

    .line 110
    ushr-long v2, v3, v2

    .line 111
    .line 112
    iget-wide v4, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->max:D

    .line 113
    .line 114
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 115
    .line 116
    .line 117
    move-result-wide v4

    .line 118
    xor-long/2addr v2, v4

    .line 119
    long-to-int v2, v2

    .line 120
    xor-int/2addr v0, v2

    .line 121
    mul-int/2addr v0, v1

    .line 122
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 123
    .line 124
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    xor-int/2addr v0, v2

    .line 129
    mul-int/2addr v0, v1

    .line 130
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 131
    .line 132
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    xor-int/2addr v0, v2

    .line 137
    mul-int/2addr v0, v1

    .line 138
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->exemplars:Ljava/util/List;

    .line 139
    .line 140
    invoke-interface {p0}, Ljava/util/List;->hashCode()I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    xor-int/2addr p0, v0

    .line 145
    return p0
.end method

.method public set(IDJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IDJZDZD",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            "JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;"
        }
    .end annotation

    .line 1
    invoke-interface/range {p12 .. p12}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getTotalCount()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    add-long/2addr v0, p4

    .line 6
    invoke-interface/range {p13 .. p13}, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;->getTotalCount()J

    .line 7
    .line 8
    .line 9
    move-result-wide v2

    .line 10
    add-long/2addr v2, v0

    .line 11
    iput-wide v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->count:J

    .line 12
    .line 13
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->scale:I

    .line 14
    .line 15
    iput-wide p2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->sum:D

    .line 16
    .line 17
    iput-wide p4, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->zeroCount:J

    .line 18
    .line 19
    iput-boolean p6, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMin:Z

    .line 20
    .line 21
    iput-wide p7, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->min:D

    .line 22
    .line 23
    iput-boolean p9, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMax:Z

    .line 24
    .line 25
    iput-wide p10, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->max:D

    .line 26
    .line 27
    move-object/from16 p1, p12

    .line 28
    .line 29
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 30
    .line 31
    move-object/from16 p1, p13

    .line 32
    .line 33
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 34
    .line 35
    move-wide/from16 p1, p14

    .line 36
    .line 37
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->startEpochNanos:J

    .line 38
    .line 39
    move-wide/from16 p1, p16

    .line 40
    .line 41
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->epochNanos:J

    .line 42
    .line 43
    move-object/from16 p1, p18

    .line 44
    .line 45
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 46
    .line 47
    move-object/from16 p1, p19

    .line 48
    .line 49
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->exemplars:Ljava/util/List;

    .line 50
    .line 51
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MutableExponentialHistogramPointData{startEpochNanos="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->startEpochNanos:J

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", epochNanos="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->epochNanos:J

    .line 19
    .line 20
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", attributes="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", scale="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->scale:I

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", sum="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->sum:D

    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", count="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->count:J

    .line 59
    .line 60
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", zeroCount="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->zeroCount:J

    .line 69
    .line 70
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", hasMin="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMin:Z

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", min="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->min:D

    .line 89
    .line 90
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", hasMax="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->hasMax:Z

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", max="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->max:D

    .line 109
    .line 110
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", positiveBuckets="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->positiveBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", negativeBuckets="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->negativeBuckets:Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v1, ", exemplars="

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableExponentialHistogramPointData;->exemplars:Ljava/util/List;

    .line 139
    .line 140
    const-string v1, "}"

    .line 141
    .line 142
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    return-object p0
.end method
