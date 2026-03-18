.class public final Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/HistogramPointData;


# instance fields
.field private attributes:Lio/opentelemetry/api/common/Attributes;

.field private boundaries:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation
.end field

.field private count:J

.field private final counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

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

.field private startEpochNanos:J

.field private sum:D


# direct methods
.method public constructor <init>(I)V
    .locals 1

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
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 11
    .line 12
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->boundaries:Ljava/util/List;

    .line 13
    .line 14
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->exemplars:Ljava/util/List;

    .line 15
    .line 16
    invoke-static {p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->ofSubArrayCapacity(I)Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->resizeAndClear(I)V

    .line 23
    .line 24
    .line 25
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
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;

    .line 11
    .line 12
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->startEpochNanos:J

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
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->epochNanos:J

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
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

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
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->sum:D

    .line 45
    .line 46
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 47
    .line 48
    .line 49
    move-result-wide v3

    .line 50
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getSum()D

    .line 51
    .line 52
    .line 53
    move-result-wide v5

    .line 54
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 55
    .line 56
    .line 57
    move-result-wide v5

    .line 58
    cmp-long v1, v3, v5

    .line 59
    .line 60
    if-nez v1, :cond_1

    .line 61
    .line 62
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->count:J

    .line 63
    .line 64
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getCount()J

    .line 65
    .line 66
    .line 67
    move-result-wide v5

    .line 68
    cmp-long v1, v3, v5

    .line 69
    .line 70
    if-nez v1, :cond_1

    .line 71
    .line 72
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMin:Z

    .line 73
    .line 74
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->hasMin()Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-ne v1, v3, :cond_1

    .line 79
    .line 80
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->min:D

    .line 81
    .line 82
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 83
    .line 84
    .line 85
    move-result-wide v3

    .line 86
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getMin()D

    .line 87
    .line 88
    .line 89
    move-result-wide v5

    .line 90
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 91
    .line 92
    .line 93
    move-result-wide v5

    .line 94
    cmp-long v1, v3, v5

    .line 95
    .line 96
    if-nez v1, :cond_1

    .line 97
    .line 98
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMax:Z

    .line 99
    .line 100
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->hasMax()Z

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    if-ne v1, v3, :cond_1

    .line 105
    .line 106
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->max:D

    .line 107
    .line 108
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 109
    .line 110
    .line 111
    move-result-wide v3

    .line 112
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getMax()D

    .line 113
    .line 114
    .line 115
    move-result-wide v5

    .line 116
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 117
    .line 118
    .line 119
    move-result-wide v5

    .line 120
    cmp-long v1, v3, v5

    .line 121
    .line 122
    if-nez v1, :cond_1

    .line 123
    .line 124
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->boundaries:Ljava/util/List;

    .line 125
    .line 126
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getBoundaries()Ljava/util/List;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-interface {v1, v3}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_1

    .line 135
    .line 136
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 137
    .line 138
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getCounts()Ljava/util/List;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    if-eqz v1, :cond_1

    .line 147
    .line 148
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->exemplars:Ljava/util/List;

    .line 149
    .line 150
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/HistogramPointData;->getExemplars()Ljava/util/List;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-interface {p0, p1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    if-eqz p0, :cond_1

    .line 159
    .line 160
    return v0

    .line 161
    :cond_1
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getBoundaries()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->boundaries:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCount()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->count:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getCounts()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->epochNanos:J

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
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->exemplars:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMax()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->max:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public getMin()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->min:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public getStartEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->startEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getSum()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->sum:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public hasMax()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMax:Z

    .line 2
    .line 3
    return p0
.end method

.method public hasMin()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMin:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 10

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->startEpochNanos:J

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
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->epochNanos:J

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
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

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
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->sum:D

    .line 31
    .line 32
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    ushr-long/2addr v3, v2

    .line 37
    iget-wide v5, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->sum:D

    .line 38
    .line 39
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 40
    .line 41
    .line 42
    move-result-wide v5

    .line 43
    xor-long/2addr v3, v5

    .line 44
    long-to-int v3, v3

    .line 45
    xor-int/2addr v0, v3

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->count:J

    .line 48
    .line 49
    ushr-long v5, v3, v2

    .line 50
    .line 51
    xor-long/2addr v3, v5

    .line 52
    long-to-int v3, v3

    .line 53
    xor-int/2addr v0, v3

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-boolean v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMin:Z

    .line 56
    .line 57
    const/16 v4, 0x4d5

    .line 58
    .line 59
    const/16 v5, 0x4cf

    .line 60
    .line 61
    if-eqz v3, :cond_0

    .line 62
    .line 63
    move v3, v5

    .line 64
    goto :goto_0

    .line 65
    :cond_0
    move v3, v4

    .line 66
    :goto_0
    xor-int/2addr v0, v3

    .line 67
    mul-int/2addr v0, v1

    .line 68
    iget-wide v6, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->min:D

    .line 69
    .line 70
    invoke-static {v6, v7}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 71
    .line 72
    .line 73
    move-result-wide v6

    .line 74
    ushr-long/2addr v6, v2

    .line 75
    iget-wide v8, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->min:D

    .line 76
    .line 77
    invoke-static {v8, v9}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 78
    .line 79
    .line 80
    move-result-wide v8

    .line 81
    xor-long/2addr v6, v8

    .line 82
    long-to-int v3, v6

    .line 83
    xor-int/2addr v0, v3

    .line 84
    mul-int/2addr v0, v1

    .line 85
    iget-boolean v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMax:Z

    .line 86
    .line 87
    if-eqz v3, :cond_1

    .line 88
    .line 89
    move v4, v5

    .line 90
    :cond_1
    xor-int/2addr v0, v4

    .line 91
    mul-int/2addr v0, v1

    .line 92
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->max:D

    .line 93
    .line 94
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 95
    .line 96
    .line 97
    move-result-wide v3

    .line 98
    ushr-long v2, v3, v2

    .line 99
    .line 100
    iget-wide v4, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->max:D

    .line 101
    .line 102
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 103
    .line 104
    .line 105
    move-result-wide v4

    .line 106
    xor-long/2addr v2, v4

    .line 107
    long-to-int v2, v2

    .line 108
    xor-int/2addr v0, v2

    .line 109
    mul-int/2addr v0, v1

    .line 110
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->boundaries:Ljava/util/List;

    .line 111
    .line 112
    invoke-interface {v2}, Ljava/util/List;->hashCode()I

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    xor-int/2addr v0, v2

    .line 117
    mul-int/2addr v0, v1

    .line 118
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 119
    .line 120
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    xor-int/2addr v0, v2

    .line 125
    mul-int/2addr v0, v1

    .line 126
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->exemplars:Ljava/util/List;

    .line 127
    .line 128
    invoke-interface {p0}, Ljava/util/List;->hashCode()I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    xor-int/2addr p0, v0

    .line 133
    return p0
.end method

.method public set(JJLio/opentelemetry/api/common/Attributes;DZDZDLjava/util/List;[JLjava/util/List;)Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "DZDZD",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;[J",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p15

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 4
    .line 5
    invoke-virtual {v1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-interface/range {p14 .. p14}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    add-int/lit8 v2, v2, 0x1

    .line 14
    .line 15
    const-string v3, " but was "

    .line 16
    .line 17
    if-ne v1, v2, :cond_3

    .line 18
    .line 19
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 20
    .line 21
    invoke-virtual {v1}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    array-length v2, v0

    .line 26
    if-ne v1, v2, :cond_2

    .line 27
    .line 28
    invoke-static/range {p14 .. p14}, Lio/opentelemetry/sdk/metrics/internal/data/HistogramPointDataValidations;->validateIsStrictlyIncreasing(Ljava/util/List;)V

    .line 29
    .line 30
    .line 31
    invoke-static/range {p14 .. p14}, Lio/opentelemetry/sdk/metrics/internal/data/HistogramPointDataValidations;->validateFiniteBoundaries(Ljava/util/List;)V

    .line 32
    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    const-wide/16 v2, 0x0

    .line 36
    .line 37
    move v4, v1

    .line 38
    :goto_0
    array-length v5, v0

    .line 39
    if-ge v4, v5, :cond_0

    .line 40
    .line 41
    aget-wide v5, v0, v4

    .line 42
    .line 43
    add-long/2addr v2, v5

    .line 44
    add-int/lit8 v4, v4, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->startEpochNanos:J

    .line 48
    .line 49
    iput-wide p3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->epochNanos:J

    .line 50
    .line 51
    iput-object p5, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 52
    .line 53
    iput-wide p6, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->sum:D

    .line 54
    .line 55
    iput-wide v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->count:J

    .line 56
    .line 57
    iput-boolean p8, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMin:Z

    .line 58
    .line 59
    move-wide/from16 p1, p9

    .line 60
    .line 61
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->min:D

    .line 62
    .line 63
    move/from16 p1, p11

    .line 64
    .line 65
    iput-boolean p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMax:Z

    .line 66
    .line 67
    move-wide/from16 p1, p12

    .line 68
    .line 69
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->max:D

    .line 70
    .line 71
    move-object/from16 p1, p14

    .line 72
    .line 73
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->boundaries:Ljava/util/List;

    .line 74
    .line 75
    :goto_1
    array-length p1, v0

    .line 76
    if-ge v1, p1, :cond_1

    .line 77
    .line 78
    iget-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 79
    .line 80
    aget-wide p2, v0, v1

    .line 81
    .line 82
    invoke-virtual {p1, v1, p2, p3}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->setLong(IJ)J

    .line 83
    .line 84
    .line 85
    add-int/lit8 v1, v1, 0x1

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_1
    move-object/from16 p1, p16

    .line 89
    .line 90
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->exemplars:Ljava/util/List;

    .line 91
    .line 92
    return-object p0

    .line 93
    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 94
    .line 95
    new-instance p2, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    const-string p3, "invalid counts: size should be "

    .line 98
    .line 99
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 103
    .line 104
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size()I

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    array-length p0, v0

    .line 115
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw p1

    .line 126
    :cond_3
    move-object/from16 p1, p14

    .line 127
    .line 128
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 129
    .line 130
    new-instance p3, Ljava/lang/StringBuilder;

    .line 131
    .line 132
    const-string p4, "invalid boundaries: size should be "

    .line 133
    .line 134
    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 138
    .line 139
    invoke-virtual {p0}, Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;->size()I

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    add-int/lit8 p0, p0, -0x1

    .line 144
    .line 145
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {p3, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw p2
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MutableHistogramPointData{startEpochNanos="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->startEpochNanos:J

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
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->epochNanos:J

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
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", sum="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->sum:D

    .line 39
    .line 40
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", count="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->count:J

    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", hasMin="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMin:Z

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", min="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->min:D

    .line 69
    .line 70
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", hasMax="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->hasMax:Z

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", max="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->max:D

    .line 89
    .line 90
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", boundaries="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->boundaries:Ljava/util/List;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", counts="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->counts:Lio/opentelemetry/sdk/internal/DynamicPrimitiveLongList;

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", exemplars="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableHistogramPointData;->exemplars:Ljava/util/List;

    .line 119
    .line 120
    const-string v1, "}"

    .line 121
    .line 122
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0
.end method
