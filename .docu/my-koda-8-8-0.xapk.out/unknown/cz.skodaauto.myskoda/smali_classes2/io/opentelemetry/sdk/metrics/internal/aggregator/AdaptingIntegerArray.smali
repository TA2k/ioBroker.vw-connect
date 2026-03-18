.class final Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;
    }
.end annotation


# instance fields
.field private byteBacking:[B
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

.field private intBacking:[I
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private longBacking:[J
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private shortBacking:[S
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;->BYTE:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 3
    new-array p1, p1, [B

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;)V
    .locals 2

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iget-object v0, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 6
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_3

    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    const/4 v1, 0x2

    if-eq v0, v1, :cond_1

    const/4 v1, 0x3

    if-eq v0, v1, :cond_0

    return-void

    .line 7
    :cond_0
    iget-object p1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    return-void

    .line 8
    :cond_1
    iget-object p1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    return-void

    .line 9
    :cond_2
    iget-object p1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([SI)[S

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    return-void

    .line 10
    :cond_3
    iget-object p1, p1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    return-void
.end method

.method private resizeToInt()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    new-array v0, v0, [I

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 8
    .line 9
    array-length v3, v2

    .line 10
    if-ge v1, v3, :cond_0

    .line 11
    .line 12
    aget-short v2, v2, v1

    .line 13
    .line 14
    aput v2, v0, v1

    .line 15
    .line 16
    add-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;->INT:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 20
    .line 21
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 22
    .line 23
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 27
    .line 28
    return-void
.end method

.method private resizeToLong()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    new-array v0, v0, [J

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 8
    .line 9
    array-length v3, v2

    .line 10
    if-ge v1, v3, :cond_0

    .line 11
    .line 12
    aget v2, v2, v1

    .line 13
    .line 14
    int-to-long v2, v2

    .line 15
    aput-wide v2, v0, v1

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;->LONG:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 21
    .line 22
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 23
    .line 24
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 28
    .line 29
    return-void
.end method

.method private resizeToShort()V
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    new-array v0, v0, [S

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 8
    .line 9
    array-length v3, v2

    .line 10
    if-ge v1, v3, :cond_0

    .line 11
    .line 12
    aget-byte v2, v2, v1

    .line 13
    .line 14
    int-to-short v2, v2

    .line 15
    aput-short v2, v0, v1

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    sget-object v1, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;->SHORT:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 21
    .line 22
    iput-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 23
    .line 24
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public clear()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eq v0, v2, :cond_2

    .line 12
    .line 13
    const/4 v2, 0x2

    .line 14
    if-eq v0, v2, :cond_1

    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    if-eq v0, v1, :cond_0

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    .line 21
    .line 22
    const-wide/16 v0, 0x0

    .line 23
    .line 24
    invoke-static {p0, v0, v1}, Ljava/util/Arrays;->fill([JJ)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 29
    .line 30
    invoke-static {p0, v1}, Ljava/util/Arrays;->fill([II)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_2
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 35
    .line 36
    invoke-static {p0, v1}, Ljava/util/Arrays;->fill([SS)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 41
    .line 42
    invoke-static {p0, v1}, Ljava/util/Arrays;->fill([BB)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public copy()Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;-><init>(Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public get(I)J
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_2

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq v0, v1, :cond_0

    .line 17
    .line 18
    const-wide/16 p0, 0x0

    .line 19
    .line 20
    return-wide p0

    .line 21
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    .line 22
    .line 23
    aget-wide p0, p0, p1

    .line 24
    .line 25
    return-wide p0

    .line 26
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 27
    .line 28
    aget p0, p0, p1

    .line 29
    .line 30
    int-to-long p0, p0

    .line 31
    return-wide p0

    .line 32
    :cond_2
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 33
    .line 34
    aget-short p0, p0, p1

    .line 35
    .line 36
    int-to-long p0, p0

    .line 37
    return-wide p0

    .line 38
    :cond_3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 39
    .line 40
    aget-byte p0, p0, p1

    .line 41
    .line 42
    int-to-long p0, p0

    .line 43
    return-wide p0
.end method

.method public increment(IJ)V
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_5

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_3

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq v0, v1, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    .line 20
    .line 21
    aget-wide v0, p0, p1

    .line 22
    .line 23
    add-long/2addr v0, p2

    .line 24
    aput-wide v0, p0, p1

    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 28
    .line 29
    aget v1, v0, p1

    .line 30
    .line 31
    int-to-long v1, v1

    .line 32
    add-long/2addr v1, p2

    .line 33
    const-wide/32 v3, 0x7fffffff

    .line 34
    .line 35
    .line 36
    cmp-long v3, v1, v3

    .line 37
    .line 38
    if-lez v3, :cond_2

    .line 39
    .line 40
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->resizeToLong()V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->increment(IJ)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_2
    long-to-int p0, v1

    .line 48
    aput p0, v0, p1

    .line 49
    .line 50
    return-void

    .line 51
    :cond_3
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 52
    .line 53
    aget-short v1, v0, p1

    .line 54
    .line 55
    int-to-long v1, v1

    .line 56
    add-long/2addr v1, p2

    .line 57
    const-wide/16 v3, 0x7fff

    .line 58
    .line 59
    cmp-long v3, v1, v3

    .line 60
    .line 61
    if-lez v3, :cond_4

    .line 62
    .line 63
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->resizeToInt()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->increment(IJ)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :cond_4
    long-to-int p0, v1

    .line 71
    int-to-short p0, p0

    .line 72
    aput-short p0, v0, p1

    .line 73
    .line 74
    return-void

    .line 75
    :cond_5
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 76
    .line 77
    aget-byte v1, v0, p1

    .line 78
    .line 79
    int-to-long v1, v1

    .line 80
    add-long/2addr v1, p2

    .line 81
    const-wide/16 v3, 0x7f

    .line 82
    .line 83
    cmp-long v3, v1, v3

    .line 84
    .line 85
    if-lez v3, :cond_6

    .line 86
    .line 87
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->resizeToShort()V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->increment(IJ)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_6
    long-to-int p0, v1

    .line 95
    int-to-byte p0, p0

    .line 96
    aput-byte p0, v0, p1

    .line 97
    .line 98
    return-void
.end method

.method public length()I
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->cellSize:Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray$ArrayCellSize;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eq v0, v1, :cond_2

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq v0, v1, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->longBacking:[J

    .line 21
    .line 22
    array-length p0, p0

    .line 23
    return p0

    .line 24
    :cond_1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->intBacking:[I

    .line 25
    .line 26
    array-length p0, p0

    .line 27
    return p0

    .line 28
    :cond_2
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->shortBacking:[S

    .line 29
    .line 30
    array-length p0, p0

    .line 31
    return p0

    .line 32
    :cond_3
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AdaptingIntegerArray;->byteBacking:[B

    .line 33
    .line 34
    array-length p0, p0

    .line 35
    return p0
.end method
