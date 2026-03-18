.class public abstract Ljp/bd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 8

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x6c508fa6

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v0

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_4

    .line 23
    .line 24
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 25
    .line 26
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 27
    .line 28
    invoke-virtual {p0, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Lj91/e;

    .line 33
    .line 34
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 35
    .line 36
    .line 37
    move-result-wide v3

    .line 38
    sget-object v5, Le3/j0;->a:Le3/i0;

    .line 39
    .line 40
    invoke-static {v2, v3, v4, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 45
    .line 46
    invoke-static {v3, v0}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iget-wide v4, p0, Ll2/t;->T:J

    .line 51
    .line 52
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    invoke-virtual {p0}, Ll2/t;->m()Ll2/p1;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    invoke-static {p0, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 65
    .line 66
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 70
    .line 71
    invoke-virtual {p0}, Ll2/t;->c0()V

    .line 72
    .line 73
    .line 74
    iget-boolean v7, p0, Ll2/t;->S:Z

    .line 75
    .line 76
    if-eqz v7, :cond_1

    .line 77
    .line 78
    invoke-virtual {p0, v6}, Ll2/t;->l(Lay0/a;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_1
    invoke-virtual {p0}, Ll2/t;->m0()V

    .line 83
    .line 84
    .line 85
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 86
    .line 87
    invoke-static {v6, v3, p0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 88
    .line 89
    .line 90
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 91
    .line 92
    invoke-static {v3, v5, p0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 93
    .line 94
    .line 95
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 96
    .line 97
    iget-boolean v5, p0, Ll2/t;->S:Z

    .line 98
    .line 99
    if-nez v5, :cond_2

    .line 100
    .line 101
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v5

    .line 113
    if-nez v5, :cond_3

    .line 114
    .line 115
    :cond_2
    invoke-static {v4, p0, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 116
    .line 117
    .line 118
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 119
    .line 120
    invoke-static {v3, v2, p0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 121
    .line 122
    .line 123
    const/4 v2, 0x0

    .line 124
    invoke-static {v0, v1, p0, v2}, Li91/j0;->r(IILl2/o;Lx2/s;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 132
    .line 133
    .line 134
    :goto_2
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    if-eqz p0, :cond_5

    .line 139
    .line 140
    new-instance v0, Lb60/b;

    .line 141
    .line 142
    const/16 v1, 0x19

    .line 143
    .line 144
    invoke-direct {v0, p1, v1}, Lb60/b;-><init>(II)V

    .line 145
    .line 146
    .line 147
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 148
    .line 149
    :cond_5
    return-void
.end method

.method public static final b(Lp1/o;)I
    .locals 4

    .line 1
    iget-object v0, p0, Lp1/o;->e:Lg1/w1;

    .line 2
    .line 3
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lp1/o;->e()J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    const-wide v2, 0xffffffffL

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    and-long/2addr v0, v2

    .line 17
    :goto_0
    long-to-int p0, v0

    .line 18
    return p0

    .line 19
    :cond_0
    invoke-virtual {p0}, Lp1/o;->e()J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    const/16 p0, 0x20

    .line 24
    .line 25
    shr-long/2addr v0, p0

    .line 26
    goto :goto_0
.end method
