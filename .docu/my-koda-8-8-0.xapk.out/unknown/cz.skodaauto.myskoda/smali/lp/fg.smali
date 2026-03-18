.class public abstract Llp/fg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    move-object v4, p1

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p1, -0x65ba993d

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x3

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x1

    .line 15
    if-eq p1, v0, :cond_0

    .line 16
    .line 17
    move p1, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move p1, v1

    .line 20
    :goto_0
    and-int/lit8 v0, p2, 0x1

    .line 21
    .line 22
    invoke-virtual {v4, v0, p1}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_6

    .line 27
    .line 28
    const p1, -0x6040e0aa

    .line 29
    .line 30
    .line 31
    invoke-virtual {v4, p1}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    if-eqz p1, :cond_5

    .line 39
    .line 40
    invoke-static {p1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 45
    .line 46
    .line 47
    move-result-object v10

    .line 48
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 49
    .line 50
    const-class v3, Lx60/j;

    .line 51
    .line 52
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-interface {p1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    const/4 v7, 0x0

    .line 61
    const/4 v9, 0x0

    .line 62
    const/4 v11, 0x0

    .line 63
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {v4, v1}, Ll2/t;->q(Z)V

    .line 68
    .line 69
    .line 70
    check-cast p1, Lql0/j;

    .line 71
    .line 72
    const/16 v3, 0x30

    .line 73
    .line 74
    invoke-static {p1, v4, v3, v1}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 75
    .line 76
    .line 77
    move-object v7, p1

    .line 78
    check-cast v7, Lx60/j;

    .line 79
    .line 80
    iget-object p1, v7, Lql0/j;->g:Lyy0/l1;

    .line 81
    .line 82
    const/4 v3, 0x0

    .line 83
    invoke-static {p1, v3, v4, v2}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    const-string v2, "bff-api-auth-no-ssl-pinning"

    .line 88
    .line 89
    invoke-static {v2}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    const v5, -0x45a63586

    .line 94
    .line 95
    .line 96
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 97
    .line 98
    .line 99
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    const v6, -0x615d173a

    .line 104
    .line 105
    .line 106
    invoke-virtual {v4, v6}, Ll2/t;->Y(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v6

    .line 113
    invoke-virtual {v4, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v8

    .line 117
    or-int/2addr v6, v8

    .line 118
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v8

    .line 122
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 123
    .line 124
    if-nez v6, :cond_1

    .line 125
    .line 126
    if-ne v8, v9, :cond_2

    .line 127
    .line 128
    :cond_1
    const-class v6, Ld01/h0;

    .line 129
    .line 130
    invoke-virtual {v0, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    invoke-virtual {v5, v0, v2, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v8

    .line 138
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_2
    invoke-virtual {v4, v1}, Ll2/t;->q(Z)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v4, v1}, Ll2/t;->q(Z)V

    .line 145
    .line 146
    .line 147
    move-object v1, v8

    .line 148
    check-cast v1, Ld01/h0;

    .line 149
    .line 150
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    move-object v0, p1

    .line 155
    check-cast v0, Lx60/i;

    .line 156
    .line 157
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result p1

    .line 161
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    if-nez p1, :cond_3

    .line 166
    .line 167
    if-ne v2, v9, :cond_4

    .line 168
    .line 169
    :cond_3
    new-instance v5, Ly60/d;

    .line 170
    .line 171
    const/4 v11, 0x0

    .line 172
    const/16 v12, 0xc

    .line 173
    .line 174
    const/4 v6, 0x0

    .line 175
    const-class v8, Lx60/j;

    .line 176
    .line 177
    const-string v9, "onUserProfile"

    .line 178
    .line 179
    const-string v10, "onUserProfile()V"

    .line 180
    .line 181
    invoke-direct/range {v5 .. v12}, Ly60/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    move-object v2, v5

    .line 188
    :cond_4
    check-cast v2, Lhy0/g;

    .line 189
    .line 190
    move-object v3, v2

    .line 191
    check-cast v3, Lay0/a;

    .line 192
    .line 193
    const/16 v5, 0x180

    .line 194
    .line 195
    move-object v2, p0

    .line 196
    invoke-static/range {v0 .. v5}, Llp/fg;->b(Lx60/i;Ld01/h0;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 197
    .line 198
    .line 199
    goto :goto_1

    .line 200
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 201
    .line 202
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 203
    .line 204
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw p0

    .line 208
    :cond_6
    move-object v2, p0

    .line 209
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 210
    .line 211
    .line 212
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    if-eqz p0, :cond_7

    .line 217
    .line 218
    new-instance p1, Luz/e;

    .line 219
    .line 220
    const/16 v0, 0xa

    .line 221
    .line 222
    invoke-direct {p1, v2, p2, v0}, Luz/e;-><init>(Lx2/s;II)V

    .line 223
    .line 224
    .line 225
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 226
    .line 227
    :cond_7
    return-void
.end method

.method public static final b(Lx60/i;Ld01/h0;Lx2/s;Lay0/a;Ll2/o;I)V
    .locals 29

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v5, p5

    .line 4
    .line 5
    move-object/from16 v11, p4

    .line 6
    .line 7
    check-cast v11, Ll2/t;

    .line 8
    .line 9
    const v0, 0x7df3c62f

    .line 10
    .line 11
    .line 12
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v5, 0x6

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v0, v2

    .line 29
    :goto_0
    or-int/2addr v0, v5

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move v0, v5

    .line 32
    :goto_1
    and-int/lit8 v3, v5, 0x30

    .line 33
    .line 34
    move-object/from16 v7, p1

    .line 35
    .line 36
    if-nez v3, :cond_3

    .line 37
    .line 38
    invoke-virtual {v11, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_2

    .line 43
    .line 44
    const/16 v3, 0x20

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v3, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v0, v3

    .line 50
    :cond_3
    and-int/lit16 v3, v5, 0x180

    .line 51
    .line 52
    move-object/from16 v12, p2

    .line 53
    .line 54
    if-nez v3, :cond_5

    .line 55
    .line 56
    invoke-virtual {v11, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_4

    .line 61
    .line 62
    const/16 v3, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v3, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v3

    .line 68
    :cond_5
    and-int/lit16 v3, v5, 0xc00

    .line 69
    .line 70
    move-object/from16 v4, p3

    .line 71
    .line 72
    if-nez v3, :cond_7

    .line 73
    .line 74
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-eqz v3, :cond_6

    .line 79
    .line 80
    const/16 v3, 0x800

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_6
    const/16 v3, 0x400

    .line 84
    .line 85
    :goto_4
    or-int/2addr v0, v3

    .line 86
    :cond_7
    and-int/lit16 v3, v0, 0x493

    .line 87
    .line 88
    const/16 v6, 0x492

    .line 89
    .line 90
    const/4 v8, 0x0

    .line 91
    const/4 v9, 0x1

    .line 92
    if-eq v3, v6, :cond_8

    .line 93
    .line 94
    move v3, v9

    .line 95
    goto :goto_5

    .line 96
    :cond_8
    move v3, v8

    .line 97
    :goto_5
    and-int/lit8 v6, v0, 0x1

    .line 98
    .line 99
    invoke-virtual {v11, v6, v3}, Ll2/t;->O(IZ)Z

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-eqz v3, :cond_d

    .line 104
    .line 105
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 106
    .line 107
    const/4 v15, 0x0

    .line 108
    const/16 v17, 0xf

    .line 109
    .line 110
    const/4 v13, 0x0

    .line 111
    const/4 v14, 0x0

    .line 112
    move-object/from16 v16, v4

    .line 113
    .line 114
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    const-string v6, "profile_row"

    .line 119
    .line 120
    invoke-static {v4, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    iget-boolean v6, v1, Lx60/i;->c:Z

    .line 125
    .line 126
    invoke-static {v4, v6}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    sget-object v14, Lj91/a;->a:Ll2/u2;

    .line 131
    .line 132
    invoke-virtual {v11, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    check-cast v6, Lj91/c;

    .line 137
    .line 138
    iget v6, v6, Lj91/c;->c:F

    .line 139
    .line 140
    invoke-virtual {v11, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v10

    .line 144
    check-cast v10, Lj91/c;

    .line 145
    .line 146
    iget v10, v10, Lj91/c;->j:F

    .line 147
    .line 148
    invoke-static {v4, v10, v6}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 153
    .line 154
    const/16 v10, 0x30

    .line 155
    .line 156
    invoke-static {v6, v3, v11, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 157
    .line 158
    .line 159
    move-result-object v3

    .line 160
    iget-wide v12, v11, Ll2/t;->T:J

    .line 161
    .line 162
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 167
    .line 168
    .line 169
    move-result-object v10

    .line 170
    invoke-static {v11, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 171
    .line 172
    .line 173
    move-result-object v4

    .line 174
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 175
    .line 176
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 180
    .line 181
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 182
    .line 183
    .line 184
    iget-boolean v13, v11, Ll2/t;->S:Z

    .line 185
    .line 186
    if-eqz v13, :cond_9

    .line 187
    .line 188
    invoke-virtual {v11, v12}, Ll2/t;->l(Lay0/a;)V

    .line 189
    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_9
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 193
    .line 194
    .line 195
    :goto_6
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 196
    .line 197
    invoke-static {v12, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 201
    .line 202
    invoke-static {v3, v10, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 203
    .line 204
    .line 205
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 206
    .line 207
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 208
    .line 209
    if-nez v10, :cond_a

    .line 210
    .line 211
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v10

    .line 215
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 216
    .line 217
    .line 218
    move-result-object v12

    .line 219
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v10

    .line 223
    if-nez v10, :cond_b

    .line 224
    .line 225
    :cond_a
    invoke-static {v6, v11, v6, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 226
    .line 227
    .line 228
    :cond_b
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 229
    .line 230
    invoke-static {v3, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 231
    .line 232
    .line 233
    const-string v3, "profile_row_avatar"

    .line 234
    .line 235
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 236
    .line 237
    invoke-static {v4, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    iget-object v6, v1, Lx60/i;->b:Ljava/lang/String;

    .line 242
    .line 243
    move v10, v8

    .line 244
    sget-object v8, Lxf0/g;->b:Lxf0/g;

    .line 245
    .line 246
    and-int/lit8 v0, v0, 0x70

    .line 247
    .line 248
    or-int/lit16 v12, v0, 0xc00

    .line 249
    .line 250
    const/16 v13, 0x10

    .line 251
    .line 252
    move v0, v10

    .line 253
    const/4 v10, 0x0

    .line 254
    move/from16 v28, v9

    .line 255
    .line 256
    move-object v9, v3

    .line 257
    move/from16 v3, v28

    .line 258
    .line 259
    invoke-static/range {v6 .. v13}, Lxf0/i0;->d(Ljava/lang/String;Ld01/h0;Lxf0/h;Lx2/s;ZLl2/o;II)V

    .line 260
    .line 261
    .line 262
    iget-object v6, v1, Lx60/i;->a:Ljava/lang/String;

    .line 263
    .line 264
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 265
    .line 266
    invoke-virtual {v11, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v7

    .line 270
    check-cast v7, Lj91/f;

    .line 271
    .line 272
    invoke-virtual {v7}, Lj91/f;->l()Lg4/p0;

    .line 273
    .line 274
    .line 275
    move-result-object v7

    .line 276
    const/high16 v8, 0x3f800000    # 1.0f

    .line 277
    .line 278
    float-to-double v9, v8

    .line 279
    const-wide/16 v12, 0x0

    .line 280
    .line 281
    cmpl-double v9, v9, v12

    .line 282
    .line 283
    if-lez v9, :cond_c

    .line 284
    .line 285
    goto :goto_7

    .line 286
    :cond_c
    const-string v9, "invalid weight; must be greater than zero"

    .line 287
    .line 288
    invoke-static {v9}, Ll1/a;->a(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    :goto_7
    new-instance v9, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 292
    .line 293
    invoke-direct {v9, v8, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v11, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v8

    .line 300
    check-cast v8, Lj91/c;

    .line 301
    .line 302
    iget v8, v8, Lj91/c;->c:F

    .line 303
    .line 304
    const/4 v10, 0x0

    .line 305
    invoke-static {v9, v8, v10, v2}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 306
    .line 307
    .line 308
    move-result-object v2

    .line 309
    const-string v8, "profile_row_user_name"

    .line 310
    .line 311
    invoke-static {v2, v8}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 312
    .line 313
    .line 314
    move-result-object v8

    .line 315
    const/16 v26, 0x6180

    .line 316
    .line 317
    const v27, 0xaff8

    .line 318
    .line 319
    .line 320
    const-wide/16 v9, 0x0

    .line 321
    .line 322
    move-object/from16 v24, v11

    .line 323
    .line 324
    const-wide/16 v11, 0x0

    .line 325
    .line 326
    const/4 v13, 0x0

    .line 327
    const-wide/16 v14, 0x0

    .line 328
    .line 329
    const/16 v16, 0x0

    .line 330
    .line 331
    const/16 v17, 0x0

    .line 332
    .line 333
    const-wide/16 v18, 0x0

    .line 334
    .line 335
    const/16 v20, 0x2

    .line 336
    .line 337
    const/16 v21, 0x0

    .line 338
    .line 339
    const/16 v22, 0x1

    .line 340
    .line 341
    const/16 v23, 0x0

    .line 342
    .line 343
    const/16 v25, 0x0

    .line 344
    .line 345
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 346
    .line 347
    .line 348
    move-object/from16 v11, v24

    .line 349
    .line 350
    const-string v2, "profile_row_chevron_right"

    .line 351
    .line 352
    invoke-static {v4, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 353
    .line 354
    .line 355
    move-result-object v8

    .line 356
    const v2, 0x7f08033b

    .line 357
    .line 358
    .line 359
    invoke-static {v2, v0, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 360
    .line 361
    .line 362
    move-result-object v6

    .line 363
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 364
    .line 365
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    check-cast v0, Lj91/e;

    .line 370
    .line 371
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 372
    .line 373
    .line 374
    move-result-wide v9

    .line 375
    const/16 v12, 0x1b0

    .line 376
    .line 377
    const/4 v13, 0x0

    .line 378
    const/4 v7, 0x0

    .line 379
    invoke-static/range {v6 .. v13}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 383
    .line 384
    .line 385
    goto :goto_8

    .line 386
    :cond_d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 387
    .line 388
    .line 389
    :goto_8
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 390
    .line 391
    .line 392
    move-result-object v6

    .line 393
    if-eqz v6, :cond_e

    .line 394
    .line 395
    new-instance v0, Lr40/f;

    .line 396
    .line 397
    move-object/from16 v2, p1

    .line 398
    .line 399
    move-object/from16 v3, p2

    .line 400
    .line 401
    move-object/from16 v4, p3

    .line 402
    .line 403
    invoke-direct/range {v0 .. v5}, Lr40/f;-><init>(Lx60/i;Ld01/h0;Lx2/s;Lay0/a;I)V

    .line 404
    .line 405
    .line 406
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 407
    .line 408
    :cond_e
    return-void
.end method

.method public static c(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p0, p1, :cond_1

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return v0

    .line 14
    :cond_0
    return v1

    .line 15
    :cond_1
    return v0
.end method
