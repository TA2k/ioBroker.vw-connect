.class public final Lm1/w;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:F

.field public s:Ll2/t2;

.field public t:Ll2/t2;


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 4

    .line 1
    iget-object v0, p0, Lm1/w;->s:Ll2/t2;

    .line 2
    .line 3
    const v1, 0x7fffffff

    .line 4
    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eq v2, v1, :cond_0

    .line 19
    .line 20
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Ljava/lang/Number;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget v2, p0, Lm1/w;->r:F

    .line 31
    .line 32
    mul-float/2addr v0, v2

    .line 33
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v0, v1

    .line 39
    :goto_0
    iget-object v2, p0, Lm1/w;->t:Ll2/t2;

    .line 40
    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Ljava/lang/Number;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eq v3, v1, :cond_1

    .line 54
    .line 55
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    check-cast v2, Ljava/lang/Number;

    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    iget p0, p0, Lm1/w;->r:F

    .line 66
    .line 67
    mul-float/2addr v2, p0

    .line 68
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    move p0, v1

    .line 74
    :goto_1
    if-eq v0, v1, :cond_2

    .line 75
    .line 76
    move v2, v0

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    :goto_2
    if-eq p0, v1, :cond_3

    .line 83
    .line 84
    move v3, p0

    .line 85
    goto :goto_3

    .line 86
    :cond_3
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    :goto_3
    if-eq v0, v1, :cond_4

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_4
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    :goto_4
    if-eq p0, v1, :cond_5

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_5
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    :goto_5
    invoke-static {v2, v0, v3, p0}, Lt4/b;->a(IIII)J

    .line 105
    .line 106
    .line 107
    move-result-wide p3

    .line 108
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    iget p2, p0, Lt3/e1;->d:I

    .line 113
    .line 114
    iget p3, p0, Lt3/e1;->e:I

    .line 115
    .line 116
    new-instance p4, Lam/a;

    .line 117
    .line 118
    const/16 v0, 0x10

    .line 119
    .line 120
    invoke-direct {p4, p0, v0}, Lam/a;-><init>(Lt3/e1;I)V

    .line 121
    .line 122
    .line 123
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 124
    .line 125
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0
.end method
