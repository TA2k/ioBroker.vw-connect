.class public final Lk1/a0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:Lk1/y;

.field public s:F


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 5

    .line 1
    invoke-static {p3, p4}, Lt4/a;->d(J)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    iget-object v0, p0, Lk1/a0;->r:Lk1/y;

    .line 8
    .line 9
    sget-object v1, Lk1/y;->d:Lk1/y;

    .line 10
    .line 11
    if-eq v0, v1, :cond_2

    .line 12
    .line 13
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    int-to-float v0, v0

    .line 18
    iget v1, p0, Lk1/a0;->s:F

    .line 19
    .line 20
    mul-float/2addr v0, v1

    .line 21
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-ge v0, v1, :cond_0

    .line 34
    .line 35
    move v0, v1

    .line 36
    :cond_0
    if-le v0, v2, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    move v2, v0

    .line 40
    :goto_0
    move v0, v2

    .line 41
    goto :goto_1

    .line 42
    :cond_2
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    :goto_1
    invoke-static {p3, p4}, Lt4/a;->c(J)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_5

    .line 55
    .line 56
    iget-object v1, p0, Lk1/a0;->r:Lk1/y;

    .line 57
    .line 58
    sget-object v3, Lk1/y;->e:Lk1/y;

    .line 59
    .line 60
    if-eq v1, v3, :cond_5

    .line 61
    .line 62
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    int-to-float v1, v1

    .line 67
    iget p0, p0, Lk1/a0;->s:F

    .line 68
    .line 69
    mul-float/2addr v1, p0

    .line 70
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 79
    .line 80
    .line 81
    move-result p3

    .line 82
    if-ge p0, v1, :cond_3

    .line 83
    .line 84
    move p0, v1

    .line 85
    :cond_3
    if-le p0, p3, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    move p3, p0

    .line 89
    :goto_2
    move p0, p3

    .line 90
    goto :goto_3

    .line 91
    :cond_5
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 96
    .line 97
    .line 98
    move-result p3

    .line 99
    move v4, p3

    .line 100
    move p3, p0

    .line 101
    move p0, v4

    .line 102
    :goto_3
    invoke-static {v2, v0, p3, p0}, Lt4/b;->a(IIII)J

    .line 103
    .line 104
    .line 105
    move-result-wide p3

    .line 106
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    iget p2, p0, Lt3/e1;->d:I

    .line 111
    .line 112
    iget p3, p0, Lt3/e1;->e:I

    .line 113
    .line 114
    new-instance p4, Lam/a;

    .line 115
    .line 116
    const/16 v0, 0xc

    .line 117
    .line 118
    invoke-direct {p4, p0, v0}, Lam/a;-><init>(Lt3/e1;I)V

    .line 119
    .line 120
    .line 121
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 122
    .line 123
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0
.end method
