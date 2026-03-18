.class public abstract Ljp/zd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(DD)D
    .locals 10

    .line 1
    const/4 v0, -0x5

    .line 2
    int-to-double v0, v0

    .line 3
    const-wide/high16 v2, 0x4024000000000000L    # 10.0

    .line 4
    .line 5
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->pow(DD)D

    .line 6
    .line 7
    .line 8
    move-result-wide v8

    .line 9
    move-wide v4, p0

    .line 10
    move-wide v6, p2

    .line 11
    invoke-static/range {v4 .. v9}, Ljp/zd;->b(DDD)D

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    const/high16 p2, 0x41200000    # 10.0f

    .line 16
    .line 17
    float-to-double p2, p2

    .line 18
    const/4 v0, 0x4

    .line 19
    int-to-double v0, v0

    .line 20
    invoke-static {p2, p3, v0, v1}, Ljava/lang/Math;->pow(DD)D

    .line 21
    .line 22
    .line 23
    move-result-wide p2

    .line 24
    double-to-float p2, p2

    .line 25
    float-to-double p2, p2

    .line 26
    mul-double/2addr p0, p2

    .line 27
    invoke-static {p0, p1}, Ljava/lang/Math;->abs(D)D

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    invoke-static {p0, p1}, Ljava/lang/Math;->signum(D)D

    .line 32
    .line 33
    .line 34
    move-result-wide p0

    .line 35
    const/4 v2, 0x1

    .line 36
    int-to-double v2, v2

    .line 37
    rem-double v2, v0, v2

    .line 38
    .line 39
    const-wide/high16 v4, 0x3fe0000000000000L    # 0.5

    .line 40
    .line 41
    cmpl-double v2, v2, v4

    .line 42
    .line 43
    if-ltz v2, :cond_0

    .line 44
    .line 45
    invoke-static {v0, v1}, Ljava/lang/Math;->ceil(D)D

    .line 46
    .line 47
    .line 48
    move-result-wide v0

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-static {v0, v1}, Ljava/lang/Math;->floor(D)D

    .line 51
    .line 52
    .line 53
    move-result-wide v0

    .line 54
    :goto_0
    mul-double/2addr p0, v0

    .line 55
    div-double/2addr p0, p2

    .line 56
    return-wide p0
.end method

.method public static final b(DDD)D
    .locals 4

    .line 1
    cmpg-double v0, p0, p2

    .line 2
    .line 3
    if-gez v0, :cond_0

    .line 4
    .line 5
    move-wide v2, p2

    .line 6
    move-wide p2, p0

    .line 7
    move-wide p0, v2

    .line 8
    invoke-static/range {p0 .. p5}, Ljp/zd;->b(DDD)D

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :cond_0
    move-wide v2, p2

    .line 14
    move-wide p2, p0

    .line 15
    move-wide p0, v2

    .line 16
    invoke-static {p0, p1}, Ljava/lang/Math;->abs(D)D

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    cmpg-double v0, v0, p4

    .line 21
    .line 22
    if-gez v0, :cond_1

    .line 23
    .line 24
    return-wide p2

    .line 25
    :cond_1
    div-double v0, p2, p0

    .line 26
    .line 27
    invoke-static {v0, v1}, Ljava/lang/Math;->floor(D)D

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    mul-double/2addr v0, p0

    .line 32
    sub-double/2addr p2, v0

    .line 33
    invoke-static/range {p0 .. p5}, Ljp/zd;->b(DDD)D

    .line 34
    .line 35
    .line 36
    move-result-wide p0

    .line 37
    return-wide p0
.end method
