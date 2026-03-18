.class public abstract Llp/me;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x2b886faf

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p2, 0x6

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v0, v1

    .line 23
    :goto_0
    or-int/2addr v0, p2

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, p2

    .line 26
    :goto_1
    and-int/lit8 v2, v0, 0x3

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x1

    .line 30
    if-eq v2, v1, :cond_2

    .line 31
    .line 32
    move v1, v4

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    move v1, v3

    .line 35
    :goto_2
    and-int/2addr v0, v4

    .line 36
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_3

    .line 41
    .line 42
    new-instance v0, Ll30/a;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    invoke-direct {v0, p0, v1}, Ll30/a;-><init>(Lx2/s;I)V

    .line 46
    .line 47
    .line 48
    const v1, -0x2bad280

    .line 49
    .line 50
    .line 51
    invoke-static {v1, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const/16 v1, 0x30

    .line 56
    .line 57
    invoke-static {v3, v0, p1, v1, v4}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 58
    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    :goto_3
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-eqz p1, :cond_4

    .line 69
    .line 70
    new-instance v0, Ld00/b;

    .line 71
    .line 72
    const/16 v1, 0x15

    .line 73
    .line 74
    invoke-direct {v0, p0, p2, v1}, Ld00/b;-><init>(Lx2/s;II)V

    .line 75
    .line 76
    .line 77
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 78
    .line 79
    :cond_4
    return-void
.end method

.method public static final b(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v4, p1

    .line 7
    check-cast v4, Ll2/t;

    .line 8
    .line 9
    const p1, -0x32afd223

    .line 10
    .line 11
    .line 12
    invoke-virtual {v4, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p1, p2, 0x6

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-nez p1, :cond_1

    .line 19
    .line 20
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-eqz p1, :cond_0

    .line 25
    .line 26
    const/4 p1, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move p1, v0

    .line 29
    :goto_0
    or-int/2addr p1, p2

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move p1, p2

    .line 32
    :goto_1
    and-int/lit8 v1, p1, 0x3

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    const/4 v3, 0x0

    .line 36
    if-eq v1, v0, :cond_2

    .line 37
    .line 38
    move v0, v2

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    move v0, v3

    .line 41
    :goto_2
    and-int/lit8 v1, p1, 0x1

    .line 42
    .line 43
    invoke-virtual {v4, v1, v0}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_7

    .line 48
    .line 49
    invoke-static {v4}, Lxf0/y1;->F(Ll2/o;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    const v0, -0x7a75c73f

    .line 56
    .line 57
    .line 58
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 59
    .line 60
    .line 61
    and-int/lit8 p1, p1, 0xe

    .line 62
    .line 63
    invoke-static {p0, v4, p1}, Llp/me;->a(Lx2/s;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    if-eqz p1, :cond_8

    .line 74
    .line 75
    new-instance v0, Ld00/b;

    .line 76
    .line 77
    const/16 v1, 0x13

    .line 78
    .line 79
    invoke-direct {v0, p0, p2, v1}, Ld00/b;-><init>(Lx2/s;II)V

    .line 80
    .line 81
    .line 82
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 83
    .line 84
    return-void

    .line 85
    :cond_3
    const v0, -0x7a8b36bb

    .line 86
    .line 87
    .line 88
    const v1, -0x6040e0aa

    .line 89
    .line 90
    .line 91
    invoke-static {v0, v1, v4, v4, v3}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    if-eqz v0, :cond_6

    .line 96
    .line 97
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 102
    .line 103
    .line 104
    move-result-object v10

    .line 105
    const-class v1, Lk30/b;

    .line 106
    .line 107
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 108
    .line 109
    invoke-virtual {v5, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 114
    .line 115
    .line 116
    move-result-object v6

    .line 117
    const/4 v7, 0x0

    .line 118
    const/4 v9, 0x0

    .line 119
    const/4 v11, 0x0

    .line 120
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    .line 125
    .line 126
    .line 127
    check-cast v0, Lql0/j;

    .line 128
    .line 129
    const/16 v1, 0x30

    .line 130
    .line 131
    invoke-static {v0, v4, v1, v3}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 132
    .line 133
    .line 134
    move-object v7, v0

    .line 135
    check-cast v7, Lk30/b;

    .line 136
    .line 137
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 138
    .line 139
    const/4 v1, 0x0

    .line 140
    invoke-static {v0, v1, v4, v2}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    move-object v1, v0

    .line 149
    check-cast v1, Lk30/a;

    .line 150
    .line 151
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    if-nez v0, :cond_4

    .line 160
    .line 161
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 162
    .line 163
    if-ne v2, v0, :cond_5

    .line 164
    .line 165
    :cond_4
    new-instance v5, Ll20/c;

    .line 166
    .line 167
    const/4 v11, 0x0

    .line 168
    const/16 v12, 0x11

    .line 169
    .line 170
    const/4 v6, 0x0

    .line 171
    const-class v8, Lk30/b;

    .line 172
    .line 173
    const-string v9, "onOpenHealthScan"

    .line 174
    .line 175
    const-string v10, "onOpenHealthScan()V"

    .line 176
    .line 177
    invoke-direct/range {v5 .. v12}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    move-object v2, v5

    .line 184
    :cond_5
    check-cast v2, Lhy0/g;

    .line 185
    .line 186
    move-object v3, v2

    .line 187
    check-cast v3, Lay0/a;

    .line 188
    .line 189
    shl-int/lit8 p1, p1, 0x3

    .line 190
    .line 191
    and-int/lit8 v5, p1, 0x70

    .line 192
    .line 193
    const/4 v6, 0x0

    .line 194
    move-object v2, p0

    .line 195
    invoke-static/range {v1 .. v6}, Llp/me;->c(Lk30/a;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 196
    .line 197
    .line 198
    goto :goto_3

    .line 199
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 200
    .line 201
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 202
    .line 203
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    throw p0

    .line 207
    :cond_7
    move-object v2, p0

    .line 208
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 209
    .line 210
    .line 211
    :goto_3
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    if-eqz p0, :cond_8

    .line 216
    .line 217
    new-instance p1, Ld00/b;

    .line 218
    .line 219
    const/16 v0, 0x14

    .line 220
    .line 221
    invoke-direct {p1, v2, p2, v0}, Ld00/b;-><init>(Lx2/s;II)V

    .line 222
    .line 223
    .line 224
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 225
    .line 226
    :cond_8
    return-void
.end method

.method public static final c(Lk30/a;Lx2/s;Lay0/a;Ll2/o;II)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v4, p4

    .line 6
    .line 7
    move-object/from16 v14, p3

    .line 8
    .line 9
    check-cast v14, Ll2/t;

    .line 10
    .line 11
    const v0, 0x67ac86d6

    .line 12
    .line 13
    .line 14
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v4, 0x6

    .line 18
    .line 19
    const/4 v3, 0x2

    .line 20
    const/4 v5, 0x4

    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    move v0, v5

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v0, v3

    .line 32
    :goto_0
    or-int/2addr v0, v4

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move v0, v4

    .line 35
    :goto_1
    and-int/lit8 v6, v4, 0x30

    .line 36
    .line 37
    if-nez v6, :cond_3

    .line 38
    .line 39
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-eqz v6, :cond_2

    .line 44
    .line 45
    const/16 v6, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v6, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v6

    .line 51
    :cond_3
    and-int/lit8 v6, p5, 0x4

    .line 52
    .line 53
    if-eqz v6, :cond_5

    .line 54
    .line 55
    or-int/lit16 v0, v0, 0x180

    .line 56
    .line 57
    :cond_4
    move-object/from16 v7, p2

    .line 58
    .line 59
    goto :goto_4

    .line 60
    :cond_5
    and-int/lit16 v7, v4, 0x180

    .line 61
    .line 62
    if-nez v7, :cond_4

    .line 63
    .line 64
    move-object/from16 v7, p2

    .line 65
    .line 66
    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-eqz v8, :cond_6

    .line 71
    .line 72
    const/16 v8, 0x100

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_6
    const/16 v8, 0x80

    .line 76
    .line 77
    :goto_3
    or-int/2addr v0, v8

    .line 78
    :goto_4
    and-int/lit16 v8, v0, 0x93

    .line 79
    .line 80
    const/16 v9, 0x92

    .line 81
    .line 82
    const/4 v10, 0x1

    .line 83
    const/4 v11, 0x0

    .line 84
    if-eq v8, v9, :cond_7

    .line 85
    .line 86
    move v8, v10

    .line 87
    goto :goto_5

    .line 88
    :cond_7
    move v8, v11

    .line 89
    :goto_5
    and-int/lit8 v9, v0, 0x1

    .line 90
    .line 91
    invoke-virtual {v14, v9, v8}, Ll2/t;->O(IZ)Z

    .line 92
    .line 93
    .line 94
    move-result v8

    .line 95
    if-eqz v8, :cond_11

    .line 96
    .line 97
    if-eqz v6, :cond_9

    .line 98
    .line 99
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 104
    .line 105
    if-ne v6, v7, :cond_8

    .line 106
    .line 107
    new-instance v6, Lz81/g;

    .line 108
    .line 109
    const/4 v7, 0x2

    .line 110
    invoke-direct {v6, v7}, Lz81/g;-><init>(I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v14, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_8
    check-cast v6, Lay0/a;

    .line 117
    .line 118
    move-object v12, v6

    .line 119
    goto :goto_6

    .line 120
    :cond_9
    move-object v12, v7

    .line 121
    :goto_6
    iget-object v6, v1, Lk30/a;->b:Llf0/i;

    .line 122
    .line 123
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 124
    .line 125
    .line 126
    move-result v6

    .line 127
    const v7, 0x7f12155e

    .line 128
    .line 129
    .line 130
    if-eqz v6, :cond_10

    .line 131
    .line 132
    const/4 v8, 0x3

    .line 133
    if-eq v6, v10, :cond_f

    .line 134
    .line 135
    if-eq v6, v3, :cond_e

    .line 136
    .line 137
    if-eq v6, v8, :cond_d

    .line 138
    .line 139
    if-eq v6, v5, :cond_c

    .line 140
    .line 141
    const/4 v3, 0x5

    .line 142
    if-ne v6, v3, :cond_b

    .line 143
    .line 144
    const v3, -0x59ccfdc4

    .line 145
    .line 146
    .line 147
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 148
    .line 149
    .line 150
    invoke-static {v14, v7}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    iget-object v6, v1, Lk30/a;->d:Ljava/lang/String;

    .line 155
    .line 156
    iget-boolean v3, v1, Lk30/a;->a:Z

    .line 157
    .line 158
    xor-int/lit8 v9, v3, 0x1

    .line 159
    .line 160
    invoke-static {v2, v7}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 161
    .line 162
    .line 163
    move-result-object v8

    .line 164
    iget-boolean v3, v1, Lk30/a;->c:Z

    .line 165
    .line 166
    if-eqz v3, :cond_a

    .line 167
    .line 168
    const v3, 0x2ea7005d

    .line 169
    .line 170
    .line 171
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 175
    .line 176
    invoke-virtual {v14, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v3

    .line 180
    check-cast v3, Lj91/e;

    .line 181
    .line 182
    invoke-virtual {v3}, Lj91/e;->u()J

    .line 183
    .line 184
    .line 185
    move-result-wide v15

    .line 186
    :goto_7
    invoke-virtual {v14, v11}, Ll2/t;->q(Z)V

    .line 187
    .line 188
    .line 189
    goto :goto_8

    .line 190
    :cond_a
    const v3, 0x2ea70423

    .line 191
    .line 192
    .line 193
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 194
    .line 195
    .line 196
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 197
    .line 198
    invoke-virtual {v14, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v3

    .line 202
    check-cast v3, Lj91/e;

    .line 203
    .line 204
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 205
    .line 206
    .line 207
    move-result-wide v15

    .line 208
    goto :goto_7

    .line 209
    :goto_8
    iget-boolean v13, v1, Lk30/a;->a:Z

    .line 210
    .line 211
    shl-int/lit8 v0, v0, 0xc

    .line 212
    .line 213
    const/high16 v3, 0x380000

    .line 214
    .line 215
    and-int/2addr v0, v3

    .line 216
    move v3, v11

    .line 217
    move-wide v10, v15

    .line 218
    const/16 v16, 0x0

    .line 219
    .line 220
    const v7, 0x7f080482

    .line 221
    .line 222
    .line 223
    move v15, v0

    .line 224
    invoke-static/range {v5 .. v16}, Lxf0/r0;->b(Ljava/lang/String;Ljava/lang/String;ILx2/s;ZJLay0/a;ZLl2/o;II)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 228
    .line 229
    .line 230
    goto/16 :goto_9

    .line 231
    .line 232
    :cond_b
    move v3, v11

    .line 233
    const v0, 0x2ea6418a

    .line 234
    .line 235
    .line 236
    invoke-static {v0, v14, v3}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    throw v0

    .line 241
    :cond_c
    move v3, v11

    .line 242
    const v0, 0x2ea713fa

    .line 243
    .line 244
    .line 245
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 249
    .line 250
    .line 251
    goto :goto_9

    .line 252
    :cond_d
    move v3, v11

    .line 253
    const v5, -0x59da3b6c

    .line 254
    .line 255
    .line 256
    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 257
    .line 258
    .line 259
    invoke-static {v14, v7}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v5

    .line 263
    invoke-static {v2, v7}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 264
    .line 265
    .line 266
    move-result-object v6

    .line 267
    shl-int/2addr v0, v8

    .line 268
    and-int/lit16 v0, v0, 0x1c00

    .line 269
    .line 270
    invoke-static {v5, v6, v12, v14, v0}, Lxf0/r0;->d(Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 274
    .line 275
    .line 276
    goto :goto_9

    .line 277
    :cond_e
    move v3, v11

    .line 278
    const v5, -0x59d1a535

    .line 279
    .line 280
    .line 281
    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 282
    .line 283
    .line 284
    invoke-static {v14, v7}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    invoke-static {v2, v7}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 289
    .line 290
    .line 291
    move-result-object v6

    .line 292
    shl-int/2addr v0, v8

    .line 293
    and-int/lit16 v0, v0, 0x1c00

    .line 294
    .line 295
    invoke-static {v5, v6, v12, v14, v0}, Lxf0/r0;->a(Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 299
    .line 300
    .line 301
    goto :goto_9

    .line 302
    :cond_f
    move v3, v11

    .line 303
    const v5, -0x59d609af

    .line 304
    .line 305
    .line 306
    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 307
    .line 308
    .line 309
    invoke-static {v14, v7}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object v5

    .line 313
    invoke-static {v2, v7}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 314
    .line 315
    .line 316
    move-result-object v6

    .line 317
    shl-int/2addr v0, v8

    .line 318
    and-int/lit16 v0, v0, 0x1c00

    .line 319
    .line 320
    invoke-static {v5, v6, v12, v14, v0}, Lxf0/r0;->e(Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 324
    .line 325
    .line 326
    goto :goto_9

    .line 327
    :cond_10
    move v3, v11

    .line 328
    const v0, 0x2ea6422f

    .line 329
    .line 330
    .line 331
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 332
    .line 333
    .line 334
    invoke-static {v14, v7}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    invoke-static {v2, v7}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 339
    .line 340
    .line 341
    move-result-object v5

    .line 342
    invoke-static {v3, v0, v14, v5}, Lxf0/r0;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v14, v3}, Ll2/t;->q(Z)V

    .line 346
    .line 347
    .line 348
    :goto_9
    move-object v3, v12

    .line 349
    goto :goto_a

    .line 350
    :cond_11
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 351
    .line 352
    .line 353
    move-object v3, v7

    .line 354
    :goto_a
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 355
    .line 356
    .line 357
    move-result-object v7

    .line 358
    if-eqz v7, :cond_12

    .line 359
    .line 360
    new-instance v0, Lc71/c;

    .line 361
    .line 362
    const/16 v6, 0xd

    .line 363
    .line 364
    move/from16 v5, p5

    .line 365
    .line 366
    invoke-direct/range {v0 .. v6}, Lc71/c;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;III)V

    .line 367
    .line 368
    .line 369
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 370
    .line 371
    :cond_12
    return-void
.end method

.method public static final d(Lyj/b;Lyj/b;Ljava/lang/String;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    const-string v0, "chargingCardId"

    .line 8
    .line 9
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v11, p3

    .line 13
    .line 14
    check-cast v11, Ll2/t;

    .line 15
    .line 16
    const v0, 0x57bbfa5d

    .line 17
    .line 18
    .line 19
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v1, 0x4

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    move v0, v1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x2

    .line 32
    :goto_0
    or-int v0, p4, v0

    .line 33
    .line 34
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    const/16 v6, 0x20

    .line 39
    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    move v2, v6

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    const/16 v2, 0x10

    .line 45
    .line 46
    :goto_1
    or-int/2addr v0, v2

    .line 47
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    const/16 v7, 0x100

    .line 52
    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    move v2, v7

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v2, 0x80

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v2

    .line 60
    and-int/lit16 v2, v0, 0x93

    .line 61
    .line 62
    const/16 v8, 0x92

    .line 63
    .line 64
    const/4 v9, 0x1

    .line 65
    const/4 v10, 0x0

    .line 66
    if-eq v2, v8, :cond_3

    .line 67
    .line 68
    move v2, v9

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    move v2, v10

    .line 71
    :goto_3
    and-int/lit8 v8, v0, 0x1

    .line 72
    .line 73
    invoke-virtual {v11, v8, v2}, Ll2/t;->O(IZ)Z

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    if-eqz v2, :cond_e

    .line 78
    .line 79
    and-int/lit8 v2, v0, 0xe

    .line 80
    .line 81
    if-ne v2, v1, :cond_4

    .line 82
    .line 83
    move v1, v9

    .line 84
    goto :goto_4

    .line 85
    :cond_4
    move v1, v10

    .line 86
    :goto_4
    and-int/lit8 v2, v0, 0x70

    .line 87
    .line 88
    if-ne v2, v6, :cond_5

    .line 89
    .line 90
    move v2, v9

    .line 91
    goto :goto_5

    .line 92
    :cond_5
    move v2, v10

    .line 93
    :goto_5
    or-int/2addr v1, v2

    .line 94
    and-int/lit16 v0, v0, 0x380

    .line 95
    .line 96
    if-ne v0, v7, :cond_6

    .line 97
    .line 98
    goto :goto_6

    .line 99
    :cond_6
    move v9, v10

    .line 100
    :goto_6
    or-int v0, v1, v9

    .line 101
    .line 102
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 107
    .line 108
    if-nez v0, :cond_7

    .line 109
    .line 110
    if-ne v1, v2, :cond_8

    .line 111
    .line 112
    :cond_7
    new-instance v1, Lxc/b;

    .line 113
    .line 114
    const/4 v0, 0x0

    .line 115
    invoke-direct {v1, v3, v4, v5, v0}, Lxc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_8
    check-cast v1, Lay0/k;

    .line 122
    .line 123
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 124
    .line 125
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    check-cast v0, Ljava/lang/Boolean;

    .line 130
    .line 131
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-eqz v0, :cond_9

    .line 136
    .line 137
    const v0, -0x105bcaaa

    .line 138
    .line 139
    .line 140
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v11, v10}, Ll2/t;->q(Z)V

    .line 144
    .line 145
    .line 146
    const/4 v0, 0x0

    .line 147
    goto :goto_7

    .line 148
    :cond_9
    const v0, 0x31054eee

    .line 149
    .line 150
    .line 151
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 152
    .line 153
    .line 154
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 155
    .line 156
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    check-cast v0, Lhi/a;

    .line 161
    .line 162
    invoke-virtual {v11, v10}, Ll2/t;->q(Z)V

    .line 163
    .line 164
    .line 165
    :goto_7
    new-instance v9, Lvh/i;

    .line 166
    .line 167
    const/4 v6, 0x4

    .line 168
    invoke-direct {v9, v6, v0, v1}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 172
    .line 173
    .line 174
    move-result-object v7

    .line 175
    if-eqz v7, :cond_d

    .line 176
    .line 177
    instance-of v0, v7, Landroidx/lifecycle/k;

    .line 178
    .line 179
    if-eqz v0, :cond_a

    .line 180
    .line 181
    move-object v0, v7

    .line 182
    check-cast v0, Landroidx/lifecycle/k;

    .line 183
    .line 184
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    :goto_8
    move-object v10, v0

    .line 189
    goto :goto_9

    .line 190
    :cond_a
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 191
    .line 192
    goto :goto_8

    .line 193
    :goto_9
    const-class v0, Lxc/h;

    .line 194
    .line 195
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 196
    .line 197
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 198
    .line 199
    .line 200
    move-result-object v6

    .line 201
    const/4 v8, 0x0

    .line 202
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    move-object v14, v0

    .line 207
    check-cast v14, Lxc/h;

    .line 208
    .line 209
    invoke-static {v11}, Llp/kb;->c(Ll2/o;)Lvc/b;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    iget-object v1, v14, Lxc/h;->m:Lyy0/l1;

    .line 214
    .line 215
    invoke-static {v1, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    check-cast v1, Llc/q;

    .line 224
    .line 225
    invoke-virtual {v11, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v6

    .line 229
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v7

    .line 233
    if-nez v6, :cond_b

    .line 234
    .line 235
    if-ne v7, v2, :cond_c

    .line 236
    .line 237
    :cond_b
    new-instance v12, Lwc/a;

    .line 238
    .line 239
    const/16 v18, 0x0

    .line 240
    .line 241
    const/16 v19, 0xe

    .line 242
    .line 243
    const/4 v13, 0x1

    .line 244
    const-class v15, Lxc/h;

    .line 245
    .line 246
    const-string v16, "onUiEvent"

    .line 247
    .line 248
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/chargingcard/presentation/order/OrderChargingCardUiEvent;)V"

    .line 249
    .line 250
    invoke-direct/range {v12 .. v19}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v11, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    move-object v7, v12

    .line 257
    :cond_c
    check-cast v7, Lhy0/g;

    .line 258
    .line 259
    check-cast v7, Lay0/k;

    .line 260
    .line 261
    const/16 v2, 0x8

    .line 262
    .line 263
    invoke-interface {v0, v1, v7, v11, v2}, Lvc/b;->k(Llc/q;Lay0/k;Ll2/o;I)V

    .line 264
    .line 265
    .line 266
    goto :goto_a

    .line 267
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 270
    .line 271
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v0

    .line 275
    :cond_e
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 276
    .line 277
    .line 278
    :goto_a
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 279
    .line 280
    .line 281
    move-result-object v6

    .line 282
    if-eqz v6, :cond_f

    .line 283
    .line 284
    new-instance v0, Luj/j0;

    .line 285
    .line 286
    const/16 v2, 0xf

    .line 287
    .line 288
    move/from16 v1, p4

    .line 289
    .line 290
    invoke-direct/range {v0 .. v5}, Luj/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 294
    .line 295
    :cond_f
    return-void
.end method
