.class public abstract Ljp/ta;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a([BII)[B
    .locals 2

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    if-le p1, v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    array-length v0, p0

    .line 8
    sub-int/2addr v0, p1

    .line 9
    invoke-static {v0, p2}, Ljava/lang/Math;->min(II)I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    new-array v0, p2, [B

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-static {p0, p1, v0, v1, p2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 21
    return-object p0
.end method

.method public static final b(Lxj0/f;D)Lxj0/f;
    .locals 12

    .line 1
    const/high16 v0, 0x40000000    # 2.0f

    .line 2
    .line 3
    float-to-double v0, v0

    .line 4
    const-wide v2, 0x41584f6f66666666L    # 6372797.6

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    div-double/2addr v0, v2

    .line 10
    iget-wide v2, p0, Lxj0/f;->a:D

    .line 11
    .line 12
    invoke-static {v2, v3}, Ljava/lang/Math;->toRadians(D)D

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    iget-wide v4, p0, Lxj0/f;->b:D

    .line 17
    .line 18
    invoke-static {v4, v5}, Ljava/lang/Math;->toRadians(D)D

    .line 19
    .line 20
    .line 21
    move-result-wide v4

    .line 22
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 23
    .line 24
    .line 25
    move-result-wide v6

    .line 26
    invoke-static {v0, v1}, Ljava/lang/Math;->cos(D)D

    .line 27
    .line 28
    .line 29
    move-result-wide v8

    .line 30
    mul-double/2addr v8, v6

    .line 31
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 32
    .line 33
    .line 34
    move-result-wide v6

    .line 35
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 36
    .line 37
    .line 38
    move-result-wide v10

    .line 39
    mul-double/2addr v10, v6

    .line 40
    invoke-static {p1, p2}, Ljava/lang/Math;->cos(D)D

    .line 41
    .line 42
    .line 43
    move-result-wide v6

    .line 44
    mul-double/2addr v6, v10

    .line 45
    add-double/2addr v6, v8

    .line 46
    invoke-static {v6, v7}, Ljava/lang/Math;->asin(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v6

    .line 50
    invoke-static {p1, p2}, Ljava/lang/Math;->sin(D)D

    .line 51
    .line 52
    .line 53
    move-result-wide p0

    .line 54
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 55
    .line 56
    .line 57
    move-result-wide v8

    .line 58
    mul-double/2addr v8, p0

    .line 59
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 60
    .line 61
    .line 62
    move-result-wide p0

    .line 63
    mul-double/2addr p0, v8

    .line 64
    invoke-static {v0, v1}, Ljava/lang/Math;->cos(D)D

    .line 65
    .line 66
    .line 67
    move-result-wide v0

    .line 68
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 69
    .line 70
    .line 71
    move-result-wide v2

    .line 72
    invoke-static {v6, v7}, Ljava/lang/Math;->sin(D)D

    .line 73
    .line 74
    .line 75
    move-result-wide v8

    .line 76
    mul-double/2addr v8, v2

    .line 77
    sub-double/2addr v0, v8

    .line 78
    invoke-static {p0, p1, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    .line 79
    .line 80
    .line 81
    move-result-wide p0

    .line 82
    add-double/2addr p0, v4

    .line 83
    new-instance p2, Lxj0/f;

    .line 84
    .line 85
    invoke-static {v6, v7}, Ljava/lang/Math;->toDegrees(D)D

    .line 86
    .line 87
    .line 88
    move-result-wide v0

    .line 89
    invoke-static {p0, p1}, Ljava/lang/Math;->toDegrees(D)D

    .line 90
    .line 91
    .line 92
    move-result-wide p0

    .line 93
    invoke-direct {p2, v0, v1, p0, p1}, Lxj0/f;-><init>(DD)V

    .line 94
    .line 95
    .line 96
    return-object p2
.end method
