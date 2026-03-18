.class public abstract Ljp/yc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/List;Lay0/k;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v7, p2

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const p2, -0x2f548d8

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p3, 0x6

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-nez p2, :cond_1

    .line 14
    .line 15
    invoke-virtual {v7, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    const/4 p2, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move p2, v0

    .line 24
    :goto_0
    or-int/2addr p2, p3

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move p2, p3

    .line 27
    :goto_1
    and-int/lit8 v1, p3, 0x30

    .line 28
    .line 29
    if-nez v1, :cond_3

    .line 30
    .line 31
    invoke-virtual {v7, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    const/16 v1, 0x20

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    const/16 v1, 0x10

    .line 41
    .line 42
    :goto_2
    or-int/2addr p2, v1

    .line 43
    :cond_3
    and-int/lit8 v1, p2, 0x13

    .line 44
    .line 45
    const/16 v2, 0x12

    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    const/4 v10, 0x1

    .line 49
    if-eq v1, v2, :cond_4

    .line 50
    .line 51
    move v1, v10

    .line 52
    goto :goto_3

    .line 53
    :cond_4
    move v1, v3

    .line 54
    :goto_3
    and-int/2addr p2, v10

    .line 55
    invoke-virtual {v7, p2, v1}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    if-eqz p2, :cond_6

    .line 60
    .line 61
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    if-eqz p2, :cond_5

    .line 66
    .line 67
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-eqz p2, :cond_7

    .line 72
    .line 73
    new-instance v0, Lc41/h;

    .line 74
    .line 75
    invoke-direct {v0, p3, v3, p1, p0}, Lc41/h;-><init>(IILay0/k;Ljava/util/List;)V

    .line 76
    .line 77
    .line 78
    :goto_4
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 79
    .line 80
    return-void

    .line 81
    :cond_5
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 82
    .line 83
    const/high16 v1, 0x3f800000    # 1.0f

    .line 84
    .line 85
    invoke-static {p2, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 90
    .line 91
    invoke-virtual {v7, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    check-cast v2, Lj91/c;

    .line 96
    .line 97
    iget v2, v2, Lj91/c;->d:F

    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    invoke-static {p2, v2, v4, v0}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    sget-object p2, Lk1/j;->a:Lk1/c;

    .line 105
    .line 106
    invoke-virtual {v7, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    check-cast p2, Lj91/c;

    .line 111
    .line 112
    iget p2, p2, Lj91/c;->c:F

    .line 113
    .line 114
    invoke-static {p2}, Lk1/j;->g(F)Lk1/h;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    invoke-virtual {v7, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    check-cast v1, Lj91/c;

    .line 123
    .line 124
    iget v1, v1, Lj91/c;->d:F

    .line 125
    .line 126
    invoke-static {v1}, Lk1/j;->g(F)Lk1/h;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    new-instance v1, Lc41/i;

    .line 131
    .line 132
    invoke-direct {v1, p0, p1, v3}, Lc41/i;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 133
    .line 134
    .line 135
    const v3, -0x74053a9d

    .line 136
    .line 137
    .line 138
    invoke-static {v3, v7, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    const/high16 v8, 0x180000

    .line 143
    .line 144
    const/16 v9, 0x38

    .line 145
    .line 146
    const/4 v3, 0x0

    .line 147
    const/4 v4, 0x0

    .line 148
    const/4 v5, 0x0

    .line 149
    move-object v1, p2

    .line 150
    invoke-static/range {v0 .. v9}, Lk1/d;->b(Lx2/s;Lk1/g;Lk1/i;Lx2/i;IILt2/b;Ll2/o;II)V

    .line 151
    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_6
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 155
    .line 156
    .line 157
    :goto_5
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 158
    .line 159
    .line 160
    move-result-object p2

    .line 161
    if-eqz p2, :cond_7

    .line 162
    .line 163
    new-instance v0, Lc41/h;

    .line 164
    .line 165
    invoke-direct {v0, p3, v10, p1, p0}, Lc41/h;-><init>(IILay0/k;Ljava/util/List;)V

    .line 166
    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_7
    return-void
.end method

.method public static final b(ILay0/k;Ljava/util/List;Ll2/o;Lx2/s;)V
    .locals 8

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x686bc75c

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/16 v0, 0x20

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/16 v0, 0x10

    .line 19
    .line 20
    :goto_0
    or-int/2addr v0, p0

    .line 21
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x1

    .line 39
    if-eq v1, v2, :cond_2

    .line 40
    .line 41
    move v1, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v1, v3

    .line 44
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 45
    .line 46
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_6

    .line 51
    .line 52
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 53
    .line 54
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 55
    .line 56
    invoke-static {v1, v2, p3, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iget-wide v2, p3, Ll2/t;->T:J

    .line 61
    .line 62
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    invoke-virtual {p3}, Ll2/t;->m()Ll2/p1;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-static {p3, p4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 75
    .line 76
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 80
    .line 81
    invoke-virtual {p3}, Ll2/t;->c0()V

    .line 82
    .line 83
    .line 84
    iget-boolean v7, p3, Ll2/t;->S:Z

    .line 85
    .line 86
    if-eqz v7, :cond_3

    .line 87
    .line 88
    invoke-virtual {p3, v6}, Ll2/t;->l(Lay0/a;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    invoke-virtual {p3}, Ll2/t;->m0()V

    .line 93
    .line 94
    .line 95
    :goto_3
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 96
    .line 97
    invoke-static {v6, v1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 98
    .line 99
    .line 100
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 101
    .line 102
    invoke-static {v1, v3, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 103
    .line 104
    .line 105
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 106
    .line 107
    iget-boolean v3, p3, Ll2/t;->S:Z

    .line 108
    .line 109
    if-nez v3, :cond_4

    .line 110
    .line 111
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-nez v3, :cond_5

    .line 124
    .line 125
    :cond_4
    invoke-static {v2, p3, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 126
    .line 127
    .line 128
    :cond_5
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 129
    .line 130
    invoke-static {v1, v5, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 131
    .line 132
    .line 133
    shr-int/lit8 v0, v0, 0x3

    .line 134
    .line 135
    and-int/lit8 v0, v0, 0x7e

    .line 136
    .line 137
    invoke-static {p2, p1, p3, v0}, Ljp/yc;->a(Ljava/util/List;Lay0/k;Ll2/o;I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p3, v4}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    goto :goto_4

    .line 144
    :cond_6
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 145
    .line 146
    .line 147
    :goto_4
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 148
    .line 149
    .line 150
    move-result-object p3

    .line 151
    if-eqz p3, :cond_7

    .line 152
    .line 153
    new-instance v0, Lc41/e;

    .line 154
    .line 155
    const/4 v5, 0x1

    .line 156
    move v4, p0

    .line 157
    move-object v3, p1

    .line 158
    move-object v2, p2

    .line 159
    move-object v1, p4

    .line 160
    invoke-direct/range {v0 .. v5}, Lc41/e;-><init>(Lx2/s;Ljava/util/List;Lay0/k;II)V

    .line 161
    .line 162
    .line 163
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 164
    .line 165
    :cond_7
    return-void
.end method

.method public static c(I)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    and-int/lit8 v1, p0, 0x4

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    const-string v1, "IMAGE_CAPTURE"

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    :cond_0
    and-int/lit8 v1, p0, 0x1

    .line 16
    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    const-string v1, "PREVIEW"

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    :cond_1
    and-int/lit8 p0, p0, 0x2

    .line 25
    .line 26
    if-eqz p0, :cond_2

    .line 27
    .line 28
    const-string p0, "VIDEO_CAPTURE"

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    :cond_2
    const-string p0, "|"

    .line 34
    .line 35
    invoke-static {p0, v0}, Ljava/lang/String;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
