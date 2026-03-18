.class public abstract Ljp/ba;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/Object;Landroidx/lifecycle/x;Lay0/k;Ll2/o;I)V
    .locals 9

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, -0x53f12d2f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p4

    .line 19
    or-int/lit8 v0, v0, 0x10

    .line 20
    .line 21
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    const/16 v1, 0x100

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v1, 0x80

    .line 31
    .line 32
    :goto_1
    or-int/2addr v0, v1

    .line 33
    and-int/lit16 v1, v0, 0x93

    .line 34
    .line 35
    const/16 v2, 0x92

    .line 36
    .line 37
    if-eq v1, v2, :cond_2

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/4 v1, 0x0

    .line 42
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 43
    .line 44
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_7

    .line 49
    .line 50
    invoke-virtual {p3}, Ll2/t;->T()V

    .line 51
    .line 52
    .line 53
    and-int/lit8 v1, p4, 0x1

    .line 54
    .line 55
    if-eqz v1, :cond_4

    .line 56
    .line 57
    invoke-virtual {p3}, Ll2/t;->y()Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-eqz v1, :cond_3

    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 65
    .line 66
    .line 67
    :goto_3
    and-int/lit8 v0, v0, -0x71

    .line 68
    .line 69
    goto :goto_5

    .line 70
    :cond_4
    :goto_4
    sget-object p1, Ln7/c;->a:Ll2/s1;

    .line 71
    .line 72
    invoke-virtual {p3, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    check-cast p1, Landroidx/lifecycle/x;

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :goto_5
    invoke-virtual {p3}, Ll2/t;->r()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    or-int/2addr v1, v2

    .line 91
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    if-nez v1, :cond_5

    .line 96
    .line 97
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-ne v2, v1, :cond_6

    .line 100
    .line 101
    :cond_5
    new-instance v2, Ln7/b;

    .line 102
    .line 103
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-direct {v2, v1}, Ln7/b;-><init>(Landroidx/lifecycle/r;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p3, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_6
    check-cast v2, Ln7/b;

    .line 114
    .line 115
    and-int/lit16 v0, v0, 0x380

    .line 116
    .line 117
    invoke-static {p1, v2, p2, p3, v0}, Ljp/ba;->b(Landroidx/lifecycle/x;Ln7/b;Lay0/k;Ll2/o;I)V

    .line 118
    .line 119
    .line 120
    :goto_6
    move-object v7, p1

    .line 121
    goto :goto_7

    .line 122
    :cond_7
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    goto :goto_6

    .line 126
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    if-eqz p1, :cond_8

    .line 131
    .line 132
    new-instance v3, Li91/k3;

    .line 133
    .line 134
    const/16 v5, 0xd

    .line 135
    .line 136
    move-object v6, p0

    .line 137
    move-object v8, p2

    .line 138
    move v4, p4

    .line 139
    invoke-direct/range {v3 .. v8}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    iput-object v3, p1, Ll2/u1;->d:Lay0/n;

    .line 143
    .line 144
    :cond_8
    return-void
.end method

.method public static final b(Landroidx/lifecycle/x;Ln7/b;Lay0/k;Ll2/o;I)V
    .locals 6

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0xd9cac4e

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_2
    or-int/2addr v0, v1

    .line 41
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 42
    .line 43
    const/16 v2, 0x100

    .line 44
    .line 45
    if-nez v1, :cond_5

    .line 46
    .line 47
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_4

    .line 52
    .line 53
    move v1, v2

    .line 54
    goto :goto_3

    .line 55
    :cond_4
    const/16 v1, 0x80

    .line 56
    .line 57
    :goto_3
    or-int/2addr v0, v1

    .line 58
    :cond_5
    and-int/lit16 v1, v0, 0x93

    .line 59
    .line 60
    const/16 v3, 0x92

    .line 61
    .line 62
    const/4 v4, 0x0

    .line 63
    const/4 v5, 0x1

    .line 64
    if-eq v1, v3, :cond_6

    .line 65
    .line 66
    move v1, v5

    .line 67
    goto :goto_4

    .line 68
    :cond_6
    move v1, v4

    .line 69
    :goto_4
    and-int/lit8 v3, v0, 0x1

    .line 70
    .line 71
    invoke-virtual {p3, v3, v1}, Ll2/t;->O(IZ)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-eqz v1, :cond_a

    .line 76
    .line 77
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    and-int/lit16 v0, v0, 0x380

    .line 82
    .line 83
    if-ne v0, v2, :cond_7

    .line 84
    .line 85
    move v4, v5

    .line 86
    :cond_7
    or-int v0, v1, v4

    .line 87
    .line 88
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    or-int/2addr v0, v1

    .line 93
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    if-nez v0, :cond_8

    .line 98
    .line 99
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-ne v1, v0, :cond_9

    .line 102
    .line 103
    :cond_8
    new-instance v1, Lkv0/e;

    .line 104
    .line 105
    const/4 v0, 0x5

    .line 106
    invoke-direct {v1, p0, p1, p2, v0}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    :cond_9
    check-cast v1, Lay0/k;

    .line 113
    .line 114
    invoke-static {p0, p1, v1, p3}, Ll2/l0;->b(Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_a
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 119
    .line 120
    .line 121
    :goto_5
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 122
    .line 123
    .line 124
    move-result-object p3

    .line 125
    if-eqz p3, :cond_b

    .line 126
    .line 127
    new-instance v0, Li50/j0;

    .line 128
    .line 129
    const/16 v2, 0x11

    .line 130
    .line 131
    move-object v3, p0

    .line 132
    move-object v4, p1

    .line 133
    move-object v5, p2

    .line 134
    move v1, p4

    .line 135
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_b
    return-void
.end method

.method public static final c(Lx2/s;Le3/n0;)Lx2/s;
    .locals 7

    .line 1
    const/4 v4, 0x0

    .line 2
    const v6, 0x7e7ff

    .line 3
    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    move-object v0, p0

    .line 9
    move-object v5, p1

    .line 10
    invoke-static/range {v0 .. v6}, Landroidx/compose/ui/graphics/a;->c(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final d(Lx2/s;)Lx2/s;
    .locals 7

    .line 1
    const/4 v5, 0x0

    .line 2
    const v6, 0x7efff

    .line 3
    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v0, p0

    .line 10
    invoke-static/range {v0 .. v6}, Landroidx/compose/ui/graphics/a;->c(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
