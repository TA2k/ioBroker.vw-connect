.class public abstract Ljp/ka;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    check-cast v1, Ll2/t;

    .line 4
    .line 5
    const v2, -0x15fe526b

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    move v4, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v4, v2

    .line 18
    :goto_0
    and-int/lit8 v5, p1, 0x1

    .line 19
    .line 20
    invoke-virtual {v1, v5, v4}, Ll2/t;->O(IZ)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_4

    .line 25
    .line 26
    sget-object v4, Lx2/c;->h:Lx2/j;

    .line 27
    .line 28
    sget-object v5, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 29
    .line 30
    sget-wide v6, Le3/s;->b:J

    .line 31
    .line 32
    const v8, 0x3f19999a    # 0.6f

    .line 33
    .line 34
    .line 35
    invoke-static {v6, v7, v8}, Le3/s;->b(JF)J

    .line 36
    .line 37
    .line 38
    move-result-wide v6

    .line 39
    sget-object v8, Le3/j0;->a:Le3/i0;

    .line 40
    .line 41
    invoke-static {v5, v6, v7, v8}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    invoke-static {v4, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    iget-wide v6, v1, Ll2/t;->T:J

    .line 50
    .line 51
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 56
    .line 57
    .line 58
    move-result-object v6

    .line 59
    invoke-static {v1, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 64
    .line 65
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 69
    .line 70
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 71
    .line 72
    .line 73
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 74
    .line 75
    if-eqz v8, :cond_1

    .line 76
    .line 77
    invoke-virtual {v1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 82
    .line 83
    .line 84
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 85
    .line 86
    invoke-static {v7, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 87
    .line 88
    .line 89
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 90
    .line 91
    invoke-static {v2, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 95
    .line 96
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 97
    .line 98
    if-nez v6, :cond_2

    .line 99
    .line 100
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v6

    .line 112
    if-nez v6, :cond_3

    .line 113
    .line 114
    :cond_2
    invoke-static {v4, v1, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 115
    .line 116
    .line 117
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 118
    .line 119
    invoke-static {v2, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 123
    .line 124
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    check-cast v2, Lj91/f;

    .line 129
    .line 130
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    sget-wide v4, Le3/s;->e:J

    .line 135
    .line 136
    const/high16 v6, 0x3f000000    # 0.5f

    .line 137
    .line 138
    invoke-static {v4, v5, v6}, Le3/s;->b(JF)J

    .line 139
    .line 140
    .line 141
    move-result-wide v4

    .line 142
    new-instance v12, Lr4/k;

    .line 143
    .line 144
    const/4 v6, 0x3

    .line 145
    invoke-direct {v12, v6}, Lr4/k;-><init>(I)V

    .line 146
    .line 147
    .line 148
    const/16 v21, 0x0

    .line 149
    .line 150
    const v22, 0xfbf4

    .line 151
    .line 152
    .line 153
    move-object/from16 v19, v1

    .line 154
    .line 155
    const-string v1, "QR scanner\npreview"

    .line 156
    .line 157
    move v6, v3

    .line 158
    const/4 v3, 0x0

    .line 159
    move v8, v6

    .line 160
    const-wide/16 v6, 0x0

    .line 161
    .line 162
    move v9, v8

    .line 163
    const/4 v8, 0x0

    .line 164
    move v11, v9

    .line 165
    const-wide/16 v9, 0x0

    .line 166
    .line 167
    move v13, v11

    .line 168
    const/4 v11, 0x0

    .line 169
    move v15, v13

    .line 170
    const-wide/16 v13, 0x0

    .line 171
    .line 172
    move/from16 v16, v15

    .line 173
    .line 174
    const/4 v15, 0x0

    .line 175
    move/from16 v17, v16

    .line 176
    .line 177
    const/16 v16, 0x0

    .line 178
    .line 179
    move/from16 v18, v17

    .line 180
    .line 181
    const/16 v17, 0x0

    .line 182
    .line 183
    move/from16 v20, v18

    .line 184
    .line 185
    const/16 v18, 0x0

    .line 186
    .line 187
    move/from16 v23, v20

    .line 188
    .line 189
    const/16 v20, 0xc06

    .line 190
    .line 191
    move/from16 v0, v23

    .line 192
    .line 193
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 194
    .line 195
    .line 196
    move-object/from16 v1, v19

    .line 197
    .line 198
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 199
    .line 200
    .line 201
    goto :goto_2

    .line 202
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 203
    .line 204
    .line 205
    :goto_2
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    if-eqz v0, :cond_5

    .line 210
    .line 211
    new-instance v1, Lnc0/l;

    .line 212
    .line 213
    const/4 v2, 0x1

    .line 214
    move/from16 v3, p1

    .line 215
    .line 216
    invoke-direct {v1, v3, v2}, Lnc0/l;-><init>(II)V

    .line 217
    .line 218
    .line 219
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 220
    .line 221
    :cond_5
    return-void
.end method

.method public static final b(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V
    .locals 22

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v10, p4

    .line 6
    .line 7
    check-cast v10, Ll2/t;

    .line 8
    .line 9
    const v0, -0x65241493

    .line 10
    .line 11
    .line 12
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    or-int/lit8 v0, v1, 0x6

    .line 16
    .line 17
    and-int/lit8 v3, v2, 0x2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    or-int/lit8 v0, v1, 0x36

    .line 22
    .line 23
    move-object/from16 v4, p2

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    move-object/from16 v4, p2

    .line 27
    .line 28
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    const/16 v5, 0x20

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/16 v5, 0x10

    .line 38
    .line 39
    :goto_0
    or-int/2addr v0, v5

    .line 40
    :goto_1
    and-int/lit8 v5, v2, 0x4

    .line 41
    .line 42
    if-eqz v5, :cond_2

    .line 43
    .line 44
    or-int/lit16 v0, v0, 0x180

    .line 45
    .line 46
    move-object/from16 v6, p3

    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_2
    move-object/from16 v6, p3

    .line 50
    .line 51
    invoke-virtual {v10, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    if-eqz v7, :cond_3

    .line 56
    .line 57
    const/16 v7, 0x100

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    const/16 v7, 0x80

    .line 61
    .line 62
    :goto_2
    or-int/2addr v0, v7

    .line 63
    :goto_3
    and-int/lit16 v7, v0, 0x93

    .line 64
    .line 65
    const/16 v8, 0x92

    .line 66
    .line 67
    const/4 v9, 0x0

    .line 68
    const/4 v11, 0x1

    .line 69
    if-eq v7, v8, :cond_4

    .line 70
    .line 71
    move v7, v11

    .line 72
    goto :goto_4

    .line 73
    :cond_4
    move v7, v9

    .line 74
    :goto_4
    and-int/lit8 v8, v0, 0x1

    .line 75
    .line 76
    invoke-virtual {v10, v8, v7}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-eqz v7, :cond_f

    .line 81
    .line 82
    const/4 v7, 0x0

    .line 83
    if-eqz v3, :cond_5

    .line 84
    .line 85
    move-object v4, v7

    .line 86
    :cond_5
    if-eqz v5, :cond_6

    .line 87
    .line 88
    move-object v5, v7

    .line 89
    goto :goto_5

    .line 90
    :cond_6
    move-object v5, v6

    .line 91
    :goto_5
    invoke-static {v10}, Lxf0/y1;->F(Ll2/o;)Z

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    if-eqz v3, :cond_7

    .line 96
    .line 97
    const v0, 0x1e4c9c61

    .line 98
    .line 99
    .line 100
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    invoke-static {v10, v9}, Ljp/ka;->a(Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v10, v9}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    if-eqz v0, :cond_10

    .line 114
    .line 115
    new-instance v3, Lnd0/a;

    .line 116
    .line 117
    invoke-direct {v3, v4, v5, v1, v2}, Lnd0/a;-><init>(Lay0/k;Lay0/k;II)V

    .line 118
    .line 119
    .line 120
    iput-object v3, v0, Ll2/u1;->d:Lay0/n;

    .line 121
    .line 122
    return-void

    .line 123
    :cond_7
    const v3, 0x1e347555

    .line 124
    .line 125
    .line 126
    const v6, -0x6040e0aa

    .line 127
    .line 128
    .line 129
    invoke-static {v3, v6, v10, v10, v9}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    if-eqz v3, :cond_e

    .line 134
    .line 135
    invoke-static {v3}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 136
    .line 137
    .line 138
    move-result-object v15

    .line 139
    invoke-static {v10}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 140
    .line 141
    .line 142
    move-result-object v17

    .line 143
    const-class v6, Lmd0/b;

    .line 144
    .line 145
    sget-object v8, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 146
    .line 147
    invoke-virtual {v8, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 148
    .line 149
    .line 150
    move-result-object v12

    .line 151
    invoke-interface {v3}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 152
    .line 153
    .line 154
    move-result-object v13

    .line 155
    const/4 v14, 0x0

    .line 156
    const/16 v16, 0x0

    .line 157
    .line 158
    const/16 v18, 0x0

    .line 159
    .line 160
    invoke-static/range {v12 .. v18}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    invoke-virtual {v10, v9}, Ll2/t;->q(Z)V

    .line 165
    .line 166
    .line 167
    move-object v14, v3

    .line 168
    check-cast v14, Lmd0/b;

    .line 169
    .line 170
    iget-object v3, v14, Lql0/j;->g:Lyy0/l1;

    .line 171
    .line 172
    invoke-static {v3, v7, v10, v11}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v3

    .line 180
    check-cast v3, Lmd0/a;

    .line 181
    .line 182
    invoke-virtual {v10, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v6

    .line 186
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 191
    .line 192
    if-nez v6, :cond_8

    .line 193
    .line 194
    if-ne v7, v11, :cond_9

    .line 195
    .line 196
    :cond_8
    new-instance v12, Ln80/d;

    .line 197
    .line 198
    const/16 v18, 0x0

    .line 199
    .line 200
    const/16 v19, 0x11

    .line 201
    .line 202
    const/4 v13, 0x0

    .line 203
    const-class v15, Lmd0/b;

    .line 204
    .line 205
    const-string v16, "onPositive"

    .line 206
    .line 207
    const-string v17, "onPositive()V"

    .line 208
    .line 209
    invoke-direct/range {v12 .. v19}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v10, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    move-object v7, v12

    .line 216
    :cond_9
    check-cast v7, Lhy0/g;

    .line 217
    .line 218
    move-object v6, v7

    .line 219
    check-cast v6, Lay0/a;

    .line 220
    .line 221
    invoke-virtual {v10, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v7

    .line 225
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v8

    .line 229
    if-nez v7, :cond_a

    .line 230
    .line 231
    if-ne v8, v11, :cond_b

    .line 232
    .line 233
    :cond_a
    new-instance v12, Ln80/d;

    .line 234
    .line 235
    const/16 v18, 0x0

    .line 236
    .line 237
    const/16 v19, 0x12

    .line 238
    .line 239
    const/4 v13, 0x0

    .line 240
    const-class v15, Lmd0/b;

    .line 241
    .line 242
    const-string v16, "onNegative"

    .line 243
    .line 244
    const-string v17, "onNegative()V"

    .line 245
    .line 246
    invoke-direct/range {v12 .. v19}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v10, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    move-object v8, v12

    .line 253
    :cond_b
    check-cast v8, Lhy0/g;

    .line 254
    .line 255
    move-object v7, v8

    .line 256
    check-cast v7, Lay0/a;

    .line 257
    .line 258
    and-int/lit16 v0, v0, 0x3f0

    .line 259
    .line 260
    const/high16 v8, 0x30000

    .line 261
    .line 262
    or-int/2addr v0, v8

    .line 263
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 264
    .line 265
    move-object v9, v10

    .line 266
    move v10, v0

    .line 267
    invoke-static/range {v3 .. v10}, Ljp/ka;->c(Lmd0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 268
    .line 269
    .line 270
    move-object v0, v4

    .line 271
    move-object/from16 v20, v5

    .line 272
    .line 273
    move-object/from16 v21, v8

    .line 274
    .line 275
    move-object v10, v9

    .line 276
    invoke-virtual {v10, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v3

    .line 280
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v4

    .line 284
    if-nez v3, :cond_c

    .line 285
    .line 286
    if-ne v4, v11, :cond_d

    .line 287
    .line 288
    :cond_c
    new-instance v12, Ln80/d;

    .line 289
    .line 290
    const/16 v18, 0x0

    .line 291
    .line 292
    const/16 v19, 0x13

    .line 293
    .line 294
    const/4 v13, 0x0

    .line 295
    const-class v15, Lmd0/b;

    .line 296
    .line 297
    const-string v16, "onStart"

    .line 298
    .line 299
    const-string v17, "onStart()V"

    .line 300
    .line 301
    invoke-direct/range {v12 .. v19}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v10, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    move-object v4, v12

    .line 308
    :cond_d
    check-cast v4, Lhy0/g;

    .line 309
    .line 310
    move-object v5, v4

    .line 311
    check-cast v5, Lay0/a;

    .line 312
    .line 313
    const/4 v11, 0x0

    .line 314
    const/16 v12, 0xfb

    .line 315
    .line 316
    const/4 v3, 0x0

    .line 317
    const/4 v4, 0x0

    .line 318
    const/4 v6, 0x0

    .line 319
    const/4 v7, 0x0

    .line 320
    const/4 v8, 0x0

    .line 321
    const/4 v9, 0x0

    .line 322
    invoke-static/range {v3 .. v12}, Lxf0/i0;->z(Landroidx/lifecycle/x;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 323
    .line 324
    .line 325
    move-object v3, v0

    .line 326
    move-object/from16 v4, v20

    .line 327
    .line 328
    move-object/from16 v5, v21

    .line 329
    .line 330
    goto :goto_6

    .line 331
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 332
    .line 333
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 334
    .line 335
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    throw v0

    .line 339
    :cond_f
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 340
    .line 341
    .line 342
    move-object/from16 v5, p5

    .line 343
    .line 344
    move-object v3, v4

    .line 345
    move-object v4, v6

    .line 346
    :goto_6
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 347
    .line 348
    .line 349
    move-result-object v6

    .line 350
    if-eqz v6, :cond_10

    .line 351
    .line 352
    new-instance v0, Li50/j0;

    .line 353
    .line 354
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILay0/k;Lay0/k;Lx2/s;)V

    .line 355
    .line 356
    .line 357
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 358
    .line 359
    :cond_10
    return-void
.end method

.method public static final c(Lmd0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lx2/s;Ll2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v6, p5

    .line 8
    .line 9
    move/from16 v7, p7

    .line 10
    .line 11
    move-object/from16 v12, p6

    .line 12
    .line 13
    check-cast v12, Ll2/t;

    .line 14
    .line 15
    const v0, -0x3861d0c2

    .line 16
    .line 17
    .line 18
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, v7, 0x6

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const/4 v0, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v0, 0x2

    .line 34
    :goto_0
    or-int/2addr v0, v7

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v0, v7

    .line 37
    :goto_1
    and-int/lit8 v5, v7, 0x30

    .line 38
    .line 39
    if-nez v5, :cond_3

    .line 40
    .line 41
    invoke-virtual {v12, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    const/16 v5, 0x20

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v5, 0x10

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v5

    .line 53
    :cond_3
    and-int/lit16 v5, v7, 0x180

    .line 54
    .line 55
    if-nez v5, :cond_5

    .line 56
    .line 57
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    if-eqz v5, :cond_4

    .line 62
    .line 63
    const/16 v5, 0x100

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    const/16 v5, 0x80

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v5

    .line 69
    :cond_5
    and-int/lit16 v5, v7, 0xc00

    .line 70
    .line 71
    move-object/from16 v13, p3

    .line 72
    .line 73
    if-nez v5, :cond_7

    .line 74
    .line 75
    invoke-virtual {v12, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    if-eqz v5, :cond_6

    .line 80
    .line 81
    const/16 v5, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v5, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v0, v5

    .line 87
    :cond_7
    and-int/lit16 v5, v7, 0x6000

    .line 88
    .line 89
    move-object/from16 v15, p4

    .line 90
    .line 91
    if-nez v5, :cond_9

    .line 92
    .line 93
    invoke-virtual {v12, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v5

    .line 97
    if-eqz v5, :cond_8

    .line 98
    .line 99
    const/16 v5, 0x4000

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_8
    const/16 v5, 0x2000

    .line 103
    .line 104
    :goto_5
    or-int/2addr v0, v5

    .line 105
    :cond_9
    const/high16 v5, 0x30000

    .line 106
    .line 107
    and-int/2addr v5, v7

    .line 108
    if-nez v5, :cond_b

    .line 109
    .line 110
    invoke-virtual {v12, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v5

    .line 114
    if-eqz v5, :cond_a

    .line 115
    .line 116
    const/high16 v5, 0x20000

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_a
    const/high16 v5, 0x10000

    .line 120
    .line 121
    :goto_6
    or-int/2addr v0, v5

    .line 122
    :cond_b
    const v5, 0x12493

    .line 123
    .line 124
    .line 125
    and-int/2addr v5, v0

    .line 126
    const v8, 0x12492

    .line 127
    .line 128
    .line 129
    if-eq v5, v8, :cond_c

    .line 130
    .line 131
    const/4 v5, 0x1

    .line 132
    goto :goto_7

    .line 133
    :cond_c
    const/4 v5, 0x0

    .line 134
    :goto_7
    and-int/lit8 v8, v0, 0x1

    .line 135
    .line 136
    invoke-virtual {v12, v8, v5}, Ll2/t;->O(IZ)Z

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    if-eqz v5, :cond_12

    .line 141
    .line 142
    sget-object v5, Ln7/c;->a:Ll2/s1;

    .line 143
    .line 144
    invoke-virtual {v12, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v5

    .line 148
    check-cast v5, Landroidx/lifecycle/x;

    .line 149
    .line 150
    sget-object v8, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 151
    .line 152
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    check-cast v8, Landroid/content/Context;

    .line 157
    .line 158
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v10

    .line 162
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 163
    .line 164
    if-ne v10, v11, :cond_d

    .line 165
    .line 166
    sget-object v10, Lv0/f;->b:Lv0/f;

    .line 167
    .line 168
    invoke-static {v8}, Llp/ua;->a(Landroid/content/Context;)Lk0/b;

    .line 169
    .line 170
    .line 171
    move-result-object v10

    .line 172
    invoke-virtual {v12, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    :cond_d
    check-cast v10, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 176
    .line 177
    new-instance v8, Lbb/g0;

    .line 178
    .line 179
    invoke-direct {v8, v2, v3}, Lbb/g0;-><init>(Lay0/k;Lay0/k;)V

    .line 180
    .line 181
    .line 182
    iget-boolean v14, v1, Lmd0/a;->a:Z

    .line 183
    .line 184
    if-eqz v14, :cond_f

    .line 185
    .line 186
    const v14, -0x3edb0d78

    .line 187
    .line 188
    .line 189
    invoke-virtual {v12, v14}, Ll2/t;->Y(I)V

    .line 190
    .line 191
    .line 192
    const v14, 0x7f120eee

    .line 193
    .line 194
    .line 195
    invoke-static {v12, v14}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v14

    .line 199
    const v9, 0x7f120eec

    .line 200
    .line 201
    .line 202
    invoke-static {v12, v9}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v9

    .line 206
    const v4, 0x7f120eed

    .line 207
    .line 208
    .line 209
    invoke-static {v12, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v4

    .line 213
    move/from16 v17, v0

    .line 214
    .line 215
    const v0, 0x7f120373

    .line 216
    .line 217
    .line 218
    invoke-static {v12, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    move-object/from16 v18, v0

    .line 223
    .line 224
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    if-ne v0, v11, :cond_e

    .line 229
    .line 230
    new-instance v0, Lz81/g;

    .line 231
    .line 232
    const/4 v1, 0x2

    .line 233
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v12, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    :cond_e
    check-cast v0, Lay0/a;

    .line 240
    .line 241
    shl-int/lit8 v1, v17, 0x6

    .line 242
    .line 243
    const/high16 v16, 0x70000

    .line 244
    .line 245
    and-int v1, v1, v16

    .line 246
    .line 247
    or-int/lit16 v1, v1, 0x180

    .line 248
    .line 249
    shl-int/lit8 v16, v17, 0x9

    .line 250
    .line 251
    const/high16 v17, 0x1c00000

    .line 252
    .line 253
    and-int v16, v16, v17

    .line 254
    .line 255
    or-int v23, v1, v16

    .line 256
    .line 257
    const/16 v24, 0x0

    .line 258
    .line 259
    const/16 v25, 0x3f10

    .line 260
    .line 261
    move-object/from16 v22, v12

    .line 262
    .line 263
    const/4 v12, 0x0

    .line 264
    const/16 v16, 0x0

    .line 265
    .line 266
    const/16 v17, 0x0

    .line 267
    .line 268
    move-object v1, v8

    .line 269
    move-object v8, v14

    .line 270
    move-object/from16 v14, v18

    .line 271
    .line 272
    const/16 v18, 0x0

    .line 273
    .line 274
    const/16 v19, 0x0

    .line 275
    .line 276
    const/16 v20, 0x0

    .line 277
    .line 278
    const/16 v21, 0x0

    .line 279
    .line 280
    move-object v2, v10

    .line 281
    move-object v10, v0

    .line 282
    move-object v0, v2

    .line 283
    move-object v2, v11

    .line 284
    move-object v11, v4

    .line 285
    const/4 v4, 0x0

    .line 286
    invoke-static/range {v8 .. v25}, Li91/j0;->d(Ljava/lang/String;Ljava/lang/String;Lay0/a;Ljava/lang/String;Lx2/s;Lay0/a;Ljava/lang/String;Lay0/a;Lx4/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;III)V

    .line 287
    .line 288
    .line 289
    move-object/from16 v12, v22

    .line 290
    .line 291
    :goto_8
    invoke-virtual {v12, v4}, Ll2/t;->q(Z)V

    .line 292
    .line 293
    .line 294
    goto :goto_9

    .line 295
    :cond_f
    move-object v1, v8

    .line 296
    move-object v0, v10

    .line 297
    move-object v2, v11

    .line 298
    const/4 v4, 0x0

    .line 299
    const v8, -0x3f04b4fc

    .line 300
    .line 301
    .line 302
    invoke-virtual {v12, v8}, Ll2/t;->Y(I)V

    .line 303
    .line 304
    .line 305
    goto :goto_8

    .line 306
    :goto_9
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    move-result v4

    .line 310
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result v8

    .line 314
    or-int/2addr v4, v8

    .line 315
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    move-result v8

    .line 319
    or-int/2addr v4, v8

    .line 320
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v8

    .line 324
    if-nez v4, :cond_10

    .line 325
    .line 326
    if-ne v8, v2, :cond_11

    .line 327
    .line 328
    :cond_10
    new-instance v8, Lkv0/e;

    .line 329
    .line 330
    const/4 v2, 0x6

    .line 331
    invoke-direct {v8, v0, v5, v1, v2}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 335
    .line 336
    .line 337
    :cond_11
    move-object v10, v8

    .line 338
    check-cast v10, Lay0/k;

    .line 339
    .line 340
    sget-object v0, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 341
    .line 342
    invoke-interface {v6, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 343
    .line 344
    .line 345
    move-result-object v13

    .line 346
    const/4 v8, 0x0

    .line 347
    const/4 v9, 0x4

    .line 348
    const/4 v11, 0x0

    .line 349
    invoke-static/range {v8 .. v13}, Landroidx/compose/ui/viewinterop/a;->a(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 350
    .line 351
    .line 352
    goto :goto_a

    .line 353
    :cond_12
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 354
    .line 355
    .line 356
    :goto_a
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 357
    .line 358
    .line 359
    move-result-object v8

    .line 360
    if-eqz v8, :cond_13

    .line 361
    .line 362
    new-instance v0, Ld80/d;

    .line 363
    .line 364
    move-object/from16 v1, p0

    .line 365
    .line 366
    move-object/from16 v2, p1

    .line 367
    .line 368
    move-object/from16 v4, p3

    .line 369
    .line 370
    move-object/from16 v5, p4

    .line 371
    .line 372
    invoke-direct/range {v0 .. v7}, Ld80/d;-><init>(Lmd0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lx2/s;I)V

    .line 373
    .line 374
    .line 375
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 376
    .line 377
    :cond_13
    return-void
.end method

.method public static final d(Lb90/f;)Ljava/util/List;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb90/f;->b:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Lb90/p;

    .line 30
    .line 31
    iget-object v1, v1, Lb90/p;->b:Lb90/q;

    .line 32
    .line 33
    sget-object v2, Lb90/q;->r:Lb90/q;

    .line 34
    .line 35
    if-ne v1, v2, :cond_1

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    :goto_0
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_3
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_5

    .line 54
    .line 55
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, Lb90/p;

    .line 60
    .line 61
    iget-object v0, v0, Lb90/p;->b:Lb90/q;

    .line 62
    .line 63
    sget-object v1, Lb90/q;->s:Lb90/q;

    .line 64
    .line 65
    if-ne v0, v1, :cond_4

    .line 66
    .line 67
    :goto_1
    sget-object p0, Lb90/d;->j:Lsx0/b;

    .line 68
    .line 69
    return-object p0

    .line 70
    :cond_5
    :goto_2
    sget-object p0, Lb90/d;->j:Lsx0/b;

    .line 71
    .line 72
    invoke-static {p0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    sget-object v0, Lb90/d;->f:Lb90/d;

    .line 77
    .line 78
    invoke-static {p0, v0}, Lmx0/q;->W(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method
