.class public final Lt2/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:[J

.field public final c:[Ljava/lang/Object;


# direct methods
.method public constructor <init>(I[J[Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lt2/h;->a:I

    .line 5
    .line 6
    iput-object p2, p0, Lt2/h;->b:[J

    .line 7
    .line 8
    iput-object p3, p0, Lt2/h;->c:[Ljava/lang/Object;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(J)I
    .locals 7

    .line 1
    iget v0, p0, Lt2/h;->a:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    if-eq v0, v1, :cond_5

    .line 7
    .line 8
    iget-object p0, p0, Lt2/h;->b:[J

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v0, :cond_3

    .line 12
    .line 13
    :goto_0
    if-gt v2, v0, :cond_2

    .line 14
    .line 15
    add-int v1, v2, v0

    .line 16
    .line 17
    ushr-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    aget-wide v3, p0, v1

    .line 20
    .line 21
    sub-long/2addr v3, p1

    .line 22
    const-wide/16 v5, 0x0

    .line 23
    .line 24
    cmp-long v3, v3, v5

    .line 25
    .line 26
    if-gez v3, :cond_0

    .line 27
    .line 28
    add-int/lit8 v2, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    if-lez v3, :cond_1

    .line 32
    .line 33
    add-int/lit8 v0, v1, -0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    return v1

    .line 37
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    neg-int p0, v2

    .line 40
    return p0

    .line 41
    :cond_3
    aget-wide v3, p0, v2

    .line 42
    .line 43
    cmp-long p0, v3, p1

    .line 44
    .line 45
    if-nez p0, :cond_4

    .line 46
    .line 47
    return v2

    .line 48
    :cond_4
    cmp-long p0, v3, p1

    .line 49
    .line 50
    if-lez p0, :cond_5

    .line 51
    .line 52
    const/4 p0, -0x2

    .line 53
    return p0

    .line 54
    :cond_5
    return v1
.end method

.method public final b(JLjava/lang/Object;)Lt2/h;
    .locals 13

    .line 1
    iget-object v0, p0, Lt2/h;->c:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    move v4, v3

    .line 7
    :goto_0
    if-ge v3, v1, :cond_1

    .line 8
    .line 9
    aget-object v5, v0, v3

    .line 10
    .line 11
    if-eqz v5, :cond_0

    .line 12
    .line 13
    add-int/lit8 v4, v4, 0x1

    .line 14
    .line 15
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    add-int/lit8 v1, v4, 0x1

    .line 19
    .line 20
    new-array v3, v1, [J

    .line 21
    .line 22
    new-array v5, v1, [Ljava/lang/Object;

    .line 23
    .line 24
    const/4 v6, 0x1

    .line 25
    if-le v1, v6, :cond_7

    .line 26
    .line 27
    move v6, v2

    .line 28
    :goto_1
    iget-object v7, p0, Lt2/h;->b:[J

    .line 29
    .line 30
    iget v8, p0, Lt2/h;->a:I

    .line 31
    .line 32
    if-ge v2, v1, :cond_4

    .line 33
    .line 34
    if-ge v6, v8, :cond_4

    .line 35
    .line 36
    aget-wide v9, v7, v6

    .line 37
    .line 38
    aget-object v11, v0, v6

    .line 39
    .line 40
    cmp-long v12, v9, p1

    .line 41
    .line 42
    if-lez v12, :cond_2

    .line 43
    .line 44
    aput-wide p1, v3, v2

    .line 45
    .line 46
    aput-object p3, v5, v2

    .line 47
    .line 48
    add-int/lit8 v2, v2, 0x1

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    if-eqz v11, :cond_3

    .line 52
    .line 53
    aput-wide v9, v3, v2

    .line 54
    .line 55
    aput-object v11, v5, v2

    .line 56
    .line 57
    add-int/lit8 v2, v2, 0x1

    .line 58
    .line 59
    :cond_3
    add-int/lit8 v6, v6, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_4
    :goto_2
    if-ne v6, v8, :cond_5

    .line 63
    .line 64
    aput-wide p1, v3, v4

    .line 65
    .line 66
    aput-object p3, v5, v4

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_5
    :goto_3
    if-ge v2, v1, :cond_8

    .line 70
    .line 71
    aget-wide v8, v7, v6

    .line 72
    .line 73
    aget-object p0, v0, v6

    .line 74
    .line 75
    if-eqz p0, :cond_6

    .line 76
    .line 77
    aput-wide v8, v3, v2

    .line 78
    .line 79
    aput-object p0, v5, v2

    .line 80
    .line 81
    add-int/lit8 v2, v2, 0x1

    .line 82
    .line 83
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_7
    aput-wide p1, v3, v2

    .line 87
    .line 88
    aput-object p3, v5, v2

    .line 89
    .line 90
    :cond_8
    :goto_4
    new-instance p0, Lt2/h;

    .line 91
    .line 92
    invoke-direct {p0, v1, v3, v5}, Lt2/h;-><init>(I[J[Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    return-object p0
.end method
