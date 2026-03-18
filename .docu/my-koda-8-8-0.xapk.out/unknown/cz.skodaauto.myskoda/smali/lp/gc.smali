.class public abstract Llp/gc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const v0, 0x61e19a63

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0xe

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move v0, v1

    .line 28
    :goto_0
    or-int/2addr v0, p2

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move v0, p2

    .line 31
    :goto_1
    and-int/lit8 v0, v0, 0xb

    .line 32
    .line 33
    if-ne v0, v1, :cond_3

    .line 34
    .line 35
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_2

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :cond_3
    :goto_2
    invoke-static {p0, p1}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    const v2, 0x3e4ccccd    # 0.2f

    .line 51
    .line 52
    .line 53
    invoke-static {v0, v1, v2}, Le3/s;->b(JF)J

    .line 54
    .line 55
    .line 56
    move-result-wide v0

    .line 57
    const v2, -0x5b3d6114

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1, v2}, Ll2/t;->Z(I)V

    .line 61
    .line 62
    .line 63
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 64
    .line 65
    invoke-virtual {p1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    check-cast v2, Lt4/c;

    .line 70
    .line 71
    invoke-static {p0, p1}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    invoke-static {v3}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    iget-object v3, v3, Lvv/n0;->a:Lt4/o;

    .line 80
    .line 81
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-wide v3, v3, Lt4/o;->a:J

    .line 85
    .line 86
    invoke-interface {v2, v3, v4}, Lt4/c;->s(J)F

    .line 87
    .line 88
    .line 89
    move-result v7

    .line 90
    const/4 v2, 0x0

    .line 91
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 92
    .line 93
    .line 94
    const/4 v8, 0x0

    .line 95
    const/4 v10, 0x5

    .line 96
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 97
    .line 98
    const/4 v6, 0x0

    .line 99
    move v9, v7

    .line 100
    invoke-static/range {v5 .. v10}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    const/high16 v4, 0x3f800000    # 1.0f

    .line 105
    .line 106
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    const/4 v4, 0x1

    .line 111
    int-to-float v4, v4

    .line 112
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 113
    .line 114
    .line 115
    move-result-object v3

    .line 116
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 117
    .line 118
    invoke-static {v3, v0, v1, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-static {v0, p1, v2}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    :goto_3
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    if-eqz p1, :cond_4

    .line 130
    .line 131
    new-instance v0, Lvv/z;

    .line 132
    .line 133
    const/4 v1, 0x0

    .line 134
    invoke-direct {v0, p0, p2, v1}, Lvv/z;-><init>(Ljava/lang/Object;II)V

    .line 135
    .line 136
    .line 137
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 138
    .line 139
    :cond_4
    return-void
.end method

.method public static b(I)I
    .locals 5

    .line 1
    const/4 v0, 0x6

    .line 2
    new-array v1, v0, [I

    .line 3
    .line 4
    fill-array-data v1, :array_0

    .line 5
    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :goto_0
    if-ge v2, v0, :cond_2

    .line 9
    .line 10
    aget v3, v1, v2

    .line 11
    .line 12
    add-int/lit8 v4, v3, -0x1

    .line 13
    .line 14
    if-eqz v3, :cond_1

    .line 15
    .line 16
    if-ne v4, p0, :cond_0

    .line 17
    .line 18
    return v3

    .line 19
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    const/4 p0, 0x0

    .line 23
    throw p0

    .line 24
    :cond_2
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    nop

    .line 27
    :array_0
    .array-data 4
        0x1
        0x2
        0x3
        0x4
        0x5
        0x6
    .end array-data
.end method
