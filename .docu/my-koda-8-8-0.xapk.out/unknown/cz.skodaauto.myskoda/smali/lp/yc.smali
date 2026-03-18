.class public abstract Llp/yc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ID)D
    .locals 4

    .line 1
    const-wide/high16 v0, 0x4024000000000000L    # 10.0

    .line 2
    .line 3
    int-to-double v2, p0

    .line 4
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    mul-double/2addr p1, v0

    .line 9
    invoke-static {p1, p2}, Ljava/lang/Math;->rint(D)D

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    div-double/2addr p0, v0

    .line 14
    return-wide p0
.end method

.method public static final b(ILjava/lang/Object;Lk4/l;Lk4/x;I)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Landroid/graphics/Typeface;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-object p1

    .line 6
    :cond_0
    and-int/lit8 v0, p0, 0x1

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x1

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-interface {p2}, Lk4/l;->b()Lk4/x;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    sget-object v0, Lk4/x;->h:Lk4/x;

    .line 23
    .line 24
    invoke-virtual {p3, v0}, Lk4/x;->a(Lk4/x;)I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-ltz v3, :cond_1

    .line 29
    .line 30
    invoke-interface {p2}, Lk4/l;->b()Lk4/x;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    iget v3, v3, Lk4/x;->d:I

    .line 35
    .line 36
    iget v0, v0, Lk4/x;->d:I

    .line 37
    .line 38
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->g(II)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-gez v0, :cond_1

    .line 43
    .line 44
    move v0, v2

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    move v0, v1

    .line 47
    :goto_0
    and-int/lit8 p0, p0, 0x2

    .line 48
    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    invoke-interface {p2}, Lk4/l;->c()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-ne p4, p0, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    move p0, v2

    .line 59
    goto :goto_2

    .line 60
    :cond_3
    :goto_1
    move p0, v1

    .line 61
    :goto_2
    if-nez p0, :cond_4

    .line 62
    .line 63
    if-nez v0, :cond_4

    .line 64
    .line 65
    return-object p1

    .line 66
    :cond_4
    if-eqz v0, :cond_5

    .line 67
    .line 68
    iget p3, p3, Lk4/x;->d:I

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_5
    invoke-interface {p2}, Lk4/l;->b()Lk4/x;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    iget p3, p3, Lk4/x;->d:I

    .line 76
    .line 77
    :goto_3
    if-eqz p0, :cond_6

    .line 78
    .line 79
    if-ne p4, v2, :cond_7

    .line 80
    .line 81
    :goto_4
    move v1, v2

    .line 82
    goto :goto_5

    .line 83
    :cond_6
    invoke-interface {p2}, Lk4/l;->c()I

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    if-ne p0, v2, :cond_7

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_7
    :goto_5
    check-cast p1, Landroid/graphics/Typeface;

    .line 91
    .line 92
    invoke-static {p1, p3, v1}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method
