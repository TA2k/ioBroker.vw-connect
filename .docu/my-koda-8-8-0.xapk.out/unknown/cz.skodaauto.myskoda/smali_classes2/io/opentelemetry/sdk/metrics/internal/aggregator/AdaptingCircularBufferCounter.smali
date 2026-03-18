.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final NULL_INDEX:I = -0x80000000


# instance fields
.field private final backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

.field private baseIndex:I

.field private endIndex:I

.field private startIndex:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, -0x80000000

    .line 2
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 3
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 4
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 5
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    invoke-direct {v0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;-><init>(I)V

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;)V
    .locals 1

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, -0x80000000

    .line 7
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 8
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 9
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 10
    iget-object v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->copy()Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 11
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexStart()I

    move-result v0

    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 12
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->getIndexEnd()I

    move-result v0

    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 13
    iget p1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    return-void
.end method

.method private toBufferIndex(I)I
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 2
    .line 3
    sub-int/2addr p1, v0

    .line 4
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 5
    .line 6
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->length()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-lt p1, v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 13
    .line 14
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->length()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    sub-int/2addr p1, p0

    .line 19
    return p1

    .line 20
    :cond_0
    if-gez p1, :cond_1

    .line 21
    .line 22
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 23
    .line 24
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->length()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p1, p0

    .line 29
    :cond_1
    return p1
.end method


# virtual methods
.method public clear()V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->clear()V

    .line 4
    .line 5
    .line 6
    const/high16 v0, -0x80000000

    .line 7
    .line 8
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 9
    .line 10
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 11
    .line 12
    iput v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 13
    .line 14
    return-void
.end method

.method public get(I)J
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 2
    .line 3
    if-lt p1, v0, :cond_1

    .line 4
    .line 5
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 6
    .line 7
    if-le p1, v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 11
    .line 12
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->toBufferIndex(I)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-virtual {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->get(I)J

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    return-wide p0

    .line 21
    :cond_1
    :goto_0
    const-wide/16 p0, 0x0

    .line 22
    .line 23
    return-wide p0
.end method

.method public getIndexEnd()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 2
    .line 3
    return p0
.end method

.method public getIndexStart()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxSize()I
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 2
    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->length()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public increment(IJ)Z
    .locals 8

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 2
    .line 3
    const/high16 v1, -0x80000000

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 10
    .line 11
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 12
    .line 13
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 14
    .line 15
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 16
    .line 17
    invoke-virtual {p0, v3, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->increment(IJ)V

    .line 18
    .line 19
    .line 20
    return v2

    .line 21
    :cond_0
    iget v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 22
    .line 23
    const-wide/16 v4, 0x1

    .line 24
    .line 25
    if-le p1, v0, :cond_2

    .line 26
    .line 27
    int-to-long v0, p1

    .line 28
    iget v6, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 29
    .line 30
    int-to-long v6, v6

    .line 31
    sub-long/2addr v0, v6

    .line 32
    add-long/2addr v0, v4

    .line 33
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 34
    .line 35
    invoke-virtual {v4}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->length()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    int-to-long v4, v4

    .line 40
    cmp-long v0, v0, v4

    .line 41
    .line 42
    if-lez v0, :cond_1

    .line 43
    .line 44
    return v3

    .line 45
    :cond_1
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 49
    .line 50
    if-ge p1, v1, :cond_4

    .line 51
    .line 52
    int-to-long v0, v0

    .line 53
    int-to-long v6, p1

    .line 54
    sub-long/2addr v0, v6

    .line 55
    add-long/2addr v0, v4

    .line 56
    iget-object v4, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 57
    .line 58
    invoke-virtual {v4}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->length()I

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    int-to-long v4, v4

    .line 63
    cmp-long v0, v0, v4

    .line 64
    .line 65
    if-lez v0, :cond_3

    .line 66
    .line 67
    return v3

    .line 68
    :cond_3
    iput p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 69
    .line 70
    :cond_4
    :goto_0
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->toBufferIndex(I)I

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->backing:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 75
    .line 76
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->increment(IJ)V

    .line 77
    .line 78
    .line 79
    return v2
.end method

.method public isEmpty()Z
    .locals 1

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->baseIndex:I

    .line 2
    .line 3
    const/high16 v0, -0x80000000

    .line 4
    .line 5
    if-ne p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "{"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 9
    .line 10
    :goto_0
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->endIndex:I

    .line 11
    .line 12
    if-gt v1, v2, :cond_1

    .line 13
    .line 14
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->startIndex:I

    .line 15
    .line 16
    const/high16 v3, -0x80000000

    .line 17
    .line 18
    if-eq v2, v3, :cond_1

    .line 19
    .line 20
    if-eq v1, v2, :cond_0

    .line 21
    .line 22
    const/16 v2, 0x2c

    .line 23
    .line 24
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const/16 v2, 0x3d

    .line 31
    .line 32
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingCircularBufferCounter;->get(I)J

    .line 36
    .line 37
    .line 38
    move-result-wide v2

    .line 39
    invoke-virtual {v0, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    add-int/lit8 v1, v1, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    const-string p0, "}"

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method
