.class public abstract Lh2/m8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:Lc1/a2;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/16 v0, 0x16

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lh2/m8;->a:F

    .line 5
    .line 6
    sget-object v0, Lc1/z;->a:Lc1/s;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    const/16 v2, 0x12c

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-static {v2, v3, v0, v1}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lh2/m8;->b:Lc1/a2;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Lt2/b;Ll2/o;I)V
    .locals 9

    .line 1
    move-object v6, p1

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    const p1, 0x3d9bae7c

    .line 5
    .line 6
    .line 7
    invoke-virtual {v6, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x13

    .line 11
    .line 12
    const/16 v0, 0x12

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v8, 0x1

    .line 16
    if-eq p1, v0, :cond_0

    .line 17
    .line 18
    move p1, v8

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move p1, v1

    .line 21
    :goto_0
    and-int/lit8 v0, p2, 0x1

    .line 22
    .line 23
    invoke-virtual {v6, v0, p1}, Ll2/t;->O(IZ)Z

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-eqz p1, :cond_4

    .line 28
    .line 29
    const p1, 0x7f120590

    .line 30
    .line 31
    .line 32
    invoke-static {v6, p1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    sget-object v0, Lx2/c;->q:Lx2/h;

    .line 37
    .line 38
    new-instance v2, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    .line 39
    .line 40
    invoke-direct {v2, v0}, Landroidx/compose/foundation/layout/HorizontalAlignElement;-><init>(Lx2/h;)V

    .line 41
    .line 42
    .line 43
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 44
    .line 45
    invoke-static {v0, v1}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iget-wide v3, v6, Ll2/t;->T:J

    .line 50
    .line 51
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-static {v6, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 64
    .line 65
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 69
    .line 70
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 71
    .line 72
    .line 73
    iget-boolean v5, v6, Ll2/t;->S:Z

    .line 74
    .line 75
    if-eqz v5, :cond_1

    .line 76
    .line 77
    invoke-virtual {v6, v4}, Ll2/t;->l(Lay0/a;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 82
    .line 83
    .line 84
    :goto_1
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 85
    .line 86
    invoke-static {v4, v0, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 87
    .line 88
    .line 89
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 90
    .line 91
    invoke-static {v0, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 95
    .line 96
    iget-boolean v3, v6, Ll2/t;->S:Z

    .line 97
    .line 98
    if-nez v3, :cond_2

    .line 99
    .line 100
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    if-nez v3, :cond_3

    .line 113
    .line 114
    :cond_2
    invoke-static {v1, v6, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 115
    .line 116
    .line 117
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 118
    .line 119
    invoke-static {v0, v2, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    invoke-static {v6}, Lh2/sb;->a(Ll2/o;)Lh2/wb;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    new-instance v1, Lh2/f3;

    .line 127
    .line 128
    const/4 v2, 0x1

    .line 129
    invoke-direct {v1, p1, v2}, Lh2/f3;-><init>(Ljava/lang/String;I)V

    .line 130
    .line 131
    .line 132
    const p1, 0x7ac6d537

    .line 133
    .line 134
    .line 135
    invoke-static {p1, v6, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    invoke-static {v6}, Lh2/vb;->c(Ll2/o;)Lh2/yb;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    const/4 v4, 0x0

    .line 144
    const v7, 0x6000030

    .line 145
    .line 146
    .line 147
    const/4 v3, 0x0

    .line 148
    move-object v5, p0

    .line 149
    invoke-static/range {v0 .. v7}, Lh2/vb;->b(Lx4/v;Lt2/b;Lh2/yb;Lx2/s;ZLt2/b;Ll2/o;I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_4
    move-object v5, p0

    .line 157
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 158
    .line 159
    .line 160
    :goto_2
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-eqz p0, :cond_5

    .line 165
    .line 166
    new-instance p1, Ld71/d;

    .line 167
    .line 168
    const/4 v0, 0x6

    .line 169
    invoke-direct {p1, v5, p2, v0}, Ld71/d;-><init>(Lt2/b;II)V

    .line 170
    .line 171
    .line 172
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 173
    .line 174
    :cond_5
    return-void
.end method

.method public static final b(ZLay0/k;Lh2/s8;Ll2/o;II)Lh2/r8;
    .locals 10

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move v3, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v3, p0

    .line 9
    :goto_0
    and-int/lit8 p0, p5, 0x8

    .line 10
    .line 11
    const/4 p5, 0x1

    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    move v7, v1

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    move v7, p5

    .line 17
    :goto_1
    sget p0, Lh2/v;->e:F

    .line 18
    .line 19
    sget v0, Lh2/v;->f:F

    .line 20
    .line 21
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 22
    .line 23
    check-cast p3, Ll2/t;

    .line 24
    .line 25
    invoke-virtual {p3, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lt4/c;

    .line 30
    .line 31
    invoke-virtual {p3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    invoke-virtual {p3, p0}, Ll2/t;->d(F)Z

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    or-int/2addr v4, v5

    .line 40
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 45
    .line 46
    if-nez v4, :cond_2

    .line 47
    .line 48
    if-ne v5, v8, :cond_3

    .line 49
    .line 50
    :cond_2
    new-instance v5, Lh2/j8;

    .line 51
    .line 52
    const/4 v4, 0x0

    .line 53
    invoke-direct {v5, v2, p0, v4}, Lh2/j8;-><init>(Lt4/c;FI)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_3
    move-object v4, v5

    .line 60
    check-cast v4, Lay0/a;

    .line 61
    .line 62
    invoke-virtual {p3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    invoke-virtual {p3, v0}, Ll2/t;->d(F)Z

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    or-int/2addr p0, v5

    .line 71
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    if-nez p0, :cond_4

    .line 76
    .line 77
    if-ne v5, v8, :cond_5

    .line 78
    .line 79
    :cond_4
    new-instance v5, Lh2/j8;

    .line 80
    .line 81
    const/4 p0, 0x1

    .line 82
    invoke-direct {v5, v2, v0, p0}, Lh2/j8;-><init>(Lt4/c;FI)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_5
    check-cast v5, Lay0/a;

    .line 89
    .line 90
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    filled-new-array {p0, p1, v0}, [Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    new-instance v0, Lgv0/a;

    .line 103
    .line 104
    const/16 v2, 0xc

    .line 105
    .line 106
    const/4 v6, 0x0

    .line 107
    invoke-direct {v0, v6, v2}, Lgv0/a;-><init>(BI)V

    .line 108
    .line 109
    .line 110
    new-instance v2, Lh2/o8;

    .line 111
    .line 112
    move-object v6, p1

    .line 113
    invoke-direct/range {v2 .. v7}, Lh2/o8;-><init>(ZLay0/a;Lay0/a;Lay0/k;Z)V

    .line 114
    .line 115
    .line 116
    new-instance p1, Lu2/l;

    .line 117
    .line 118
    invoke-direct {p1, v0, v2}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 119
    .line 120
    .line 121
    and-int/lit8 v0, p4, 0xe

    .line 122
    .line 123
    xor-int/lit8 v0, v0, 0x6

    .line 124
    .line 125
    const/4 v2, 0x4

    .line 126
    if-le v0, v2, :cond_6

    .line 127
    .line 128
    invoke-virtual {p3, v3}, Ll2/t;->h(Z)Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-nez v0, :cond_7

    .line 133
    .line 134
    :cond_6
    and-int/lit8 v0, p4, 0x6

    .line 135
    .line 136
    if-ne v0, v2, :cond_8

    .line 137
    .line 138
    :cond_7
    move v0, p5

    .line 139
    goto :goto_2

    .line 140
    :cond_8
    move v0, v1

    .line 141
    :goto_2
    invoke-virtual {p3, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    or-int/2addr v0, v2

    .line 146
    invoke-virtual {p3, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v2

    .line 150
    or-int/2addr v0, v2

    .line 151
    and-int/lit16 v2, p4, 0x380

    .line 152
    .line 153
    xor-int/lit16 v2, v2, 0x180

    .line 154
    .line 155
    const/16 v9, 0x100

    .line 156
    .line 157
    if-le v2, v9, :cond_9

    .line 158
    .line 159
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    invoke-virtual {p3, v2}, Ll2/t;->e(I)Z

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    if-nez v2, :cond_b

    .line 168
    .line 169
    :cond_9
    and-int/lit16 p4, p4, 0x180

    .line 170
    .line 171
    if-ne p4, v9, :cond_a

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_a
    move p5, v1

    .line 175
    :cond_b
    :goto_3
    or-int p4, v0, p5

    .line 176
    .line 177
    invoke-virtual {p3, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result p5

    .line 181
    or-int/2addr p4, p5

    .line 182
    invoke-virtual {p3, v7}, Ll2/t;->h(Z)Z

    .line 183
    .line 184
    .line 185
    move-result p5

    .line 186
    or-int/2addr p4, p5

    .line 187
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p5

    .line 191
    if-nez p4, :cond_c

    .line 192
    .line 193
    if-ne p5, v8, :cond_d

    .line 194
    .line 195
    :cond_c
    new-instance v2, Lh2/k8;

    .line 196
    .line 197
    move v8, v7

    .line 198
    move-object v7, v6

    .line 199
    move-object v6, p2

    .line 200
    invoke-direct/range {v2 .. v8}, Lh2/k8;-><init>(ZLay0/a;Lay0/a;Lh2/s8;Lay0/k;Z)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p3, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    move-object p5, v2

    .line 207
    :cond_d
    check-cast p5, Lay0/a;

    .line 208
    .line 209
    invoke-static {p0, p1, p5, p3, v1}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    check-cast p0, Lh2/r8;

    .line 214
    .line 215
    return-object p0
.end method
