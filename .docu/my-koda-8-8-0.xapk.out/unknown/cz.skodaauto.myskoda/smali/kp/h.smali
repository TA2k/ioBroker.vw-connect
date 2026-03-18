.class public abstract Lkp/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(JF)Le1/t;
    .locals 2

    .line 1
    new-instance v0, Le1/t;

    .line 2
    .line 3
    new-instance v1, Le3/p0;

    .line 4
    .line 5
    invoke-direct {v1, p0, p1}, Le3/p0;-><init>(J)V

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, p2, v1}, Le1/t;-><init>(FLe3/p0;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static final b(Ll2/o;I)V
    .locals 11

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x73eb0755

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

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
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Lq20/b;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, Lq20/b;

    .line 73
    .line 74
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    if-nez v0, :cond_1

    .line 83
    .line 84
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-ne v2, v0, :cond_2

    .line 87
    .line 88
    :cond_1
    new-instance v3, Loz/c;

    .line 89
    .line 90
    const/4 v9, 0x0

    .line 91
    const/16 v10, 0x14

    .line 92
    .line 93
    const/4 v4, 0x0

    .line 94
    const-class v6, Lq20/b;

    .line 95
    .line 96
    const-string v7, "onClose"

    .line 97
    .line 98
    const-string v8, "onClose()V"

    .line 99
    .line 100
    invoke-direct/range {v3 .. v10}, Loz/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    move-object v2, v3

    .line 107
    :cond_2
    check-cast v2, Lhy0/g;

    .line 108
    .line 109
    check-cast v2, Lay0/a;

    .line 110
    .line 111
    invoke-static {v2, p0, v1}, Lkp/h;->c(Lay0/a;Ll2/o;I)V

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 116
    .line 117
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 124
    .line 125
    .line 126
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-eqz p0, :cond_5

    .line 131
    .line 132
    new-instance v0, Lqz/a;

    .line 133
    .line 134
    const/4 v1, 0x6

    .line 135
    invoke-direct {v0, p1, v1}, Lqz/a;-><init>(II)V

    .line 136
    .line 137
    .line 138
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_5
    return-void
.end method

.method public static final c(Lay0/a;Ll2/o;I)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v2, -0x1db4cad9

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v12, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v12

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v3, v2, 0x3

    .line 26
    .line 27
    const/4 v13, 0x0

    .line 28
    const/4 v14, 0x1

    .line 29
    if-eq v3, v12, :cond_1

    .line 30
    .line 31
    move v3, v14

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v3, v13

    .line 34
    :goto_1
    and-int/2addr v2, v14

    .line 35
    invoke-virtual {v9, v2, v3}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_8

    .line 40
    .line 41
    sget-object v15, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 42
    .line 43
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 44
    .line 45
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 46
    .line 47
    invoke-static {v2, v3, v9, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    iget-wide v5, v9, Ll2/t;->T:J

    .line 52
    .line 53
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    invoke-static {v9, v15}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 66
    .line 67
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 71
    .line 72
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 73
    .line 74
    .line 75
    iget-boolean v10, v9, Ll2/t;->S:Z

    .line 76
    .line 77
    if-eqz v10, :cond_2

    .line 78
    .line 79
    invoke-virtual {v9, v8}, Ll2/t;->l(Lay0/a;)V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_2
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 84
    .line 85
    .line 86
    :goto_2
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 87
    .line 88
    invoke-static {v10, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 89
    .line 90
    .line 91
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 92
    .line 93
    invoke-static {v4, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 94
    .line 95
    .line 96
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 97
    .line 98
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 99
    .line 100
    if-nez v11, :cond_3

    .line 101
    .line 102
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v11

    .line 106
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 107
    .line 108
    .line 109
    move-result-object v14

    .line 110
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v11

    .line 114
    if-nez v11, :cond_4

    .line 115
    .line 116
    :cond_3
    invoke-static {v5, v9, v5, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 117
    .line 118
    .line 119
    :cond_4
    sget-object v14, Lv3/j;->d:Lv3/h;

    .line 120
    .line 121
    invoke-static {v14, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 122
    .line 123
    .line 124
    new-instance v5, Li91/x2;

    .line 125
    .line 126
    const/4 v7, 0x3

    .line 127
    invoke-direct {v5, v0, v7}, Li91/x2;-><init>(Lay0/a;I)V

    .line 128
    .line 129
    .line 130
    move-object v7, v10

    .line 131
    const/4 v10, 0x0

    .line 132
    const/16 v11, 0x3bf

    .line 133
    .line 134
    move-object/from16 v16, v2

    .line 135
    .line 136
    const/4 v2, 0x0

    .line 137
    move-object/from16 v17, v3

    .line 138
    .line 139
    const/4 v3, 0x0

    .line 140
    move-object/from16 v18, v4

    .line 141
    .line 142
    const/4 v4, 0x0

    .line 143
    move-object/from16 v19, v6

    .line 144
    .line 145
    const/4 v6, 0x0

    .line 146
    move-object/from16 v20, v7

    .line 147
    .line 148
    const/4 v7, 0x0

    .line 149
    move-object/from16 v21, v8

    .line 150
    .line 151
    const/4 v8, 0x0

    .line 152
    move-object/from16 v24, v16

    .line 153
    .line 154
    move-object/from16 v25, v17

    .line 155
    .line 156
    move-object/from16 v28, v18

    .line 157
    .line 158
    move-object/from16 v29, v19

    .line 159
    .line 160
    move-object/from16 v27, v20

    .line 161
    .line 162
    move-object/from16 v26, v21

    .line 163
    .line 164
    invoke-static/range {v2 .. v11}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 165
    .line 166
    .line 167
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 168
    .line 169
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v3

    .line 173
    check-cast v3, Lj91/c;

    .line 174
    .line 175
    iget v3, v3, Lj91/c;->j:F

    .line 176
    .line 177
    const/4 v4, 0x0

    .line 178
    invoke-static {v15, v3, v4, v12}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    move-object/from16 v4, v24

    .line 183
    .line 184
    move-object/from16 v5, v25

    .line 185
    .line 186
    invoke-static {v4, v5, v9, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    iget-wide v5, v9, Ll2/t;->T:J

    .line 191
    .line 192
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 193
    .line 194
    .line 195
    move-result v5

    .line 196
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 197
    .line 198
    .line 199
    move-result-object v6

    .line 200
    invoke-static {v9, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 205
    .line 206
    .line 207
    iget-boolean v7, v9, Ll2/t;->S:Z

    .line 208
    .line 209
    if-eqz v7, :cond_5

    .line 210
    .line 211
    move-object/from16 v7, v26

    .line 212
    .line 213
    invoke-virtual {v9, v7}, Ll2/t;->l(Lay0/a;)V

    .line 214
    .line 215
    .line 216
    :goto_3
    move-object/from16 v7, v27

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_5
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 220
    .line 221
    .line 222
    goto :goto_3

    .line 223
    :goto_4
    invoke-static {v7, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 224
    .line 225
    .line 226
    move-object/from16 v4, v28

    .line 227
    .line 228
    invoke-static {v4, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 229
    .line 230
    .line 231
    iget-boolean v4, v9, Ll2/t;->S:Z

    .line 232
    .line 233
    if-nez v4, :cond_6

    .line 234
    .line 235
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v4

    .line 247
    if-nez v4, :cond_7

    .line 248
    .line 249
    :cond_6
    move-object/from16 v4, v29

    .line 250
    .line 251
    invoke-static {v5, v9, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 252
    .line 253
    .line 254
    :cond_7
    invoke-static {v14, v3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 255
    .line 256
    .line 257
    const v3, 0x7f12033d

    .line 258
    .line 259
    .line 260
    move-object v4, v2

    .line 261
    invoke-static {v9, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 266
    .line 267
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v6

    .line 271
    check-cast v6, Lj91/f;

    .line 272
    .line 273
    invoke-virtual {v6}, Lj91/f;->i()Lg4/p0;

    .line 274
    .line 275
    .line 276
    move-result-object v6

    .line 277
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 278
    .line 279
    invoke-static {v7, v3}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    const/16 v22, 0x0

    .line 284
    .line 285
    const v23, 0xfff8

    .line 286
    .line 287
    .line 288
    move-object v10, v4

    .line 289
    move-object v8, v5

    .line 290
    move-object v4, v3

    .line 291
    move-object v3, v6

    .line 292
    const-wide/16 v5, 0x0

    .line 293
    .line 294
    move-object v12, v7

    .line 295
    move-object v11, v8

    .line 296
    const-wide/16 v7, 0x0

    .line 297
    .line 298
    move-object/from16 v20, v9

    .line 299
    .line 300
    const/4 v9, 0x0

    .line 301
    move-object v13, v10

    .line 302
    move-object v14, v11

    .line 303
    const-wide/16 v10, 0x0

    .line 304
    .line 305
    move-object v15, v12

    .line 306
    const/4 v12, 0x0

    .line 307
    move-object/from16 v16, v13

    .line 308
    .line 309
    const/4 v13, 0x0

    .line 310
    move-object/from16 v17, v14

    .line 311
    .line 312
    move-object/from16 v18, v15

    .line 313
    .line 314
    const-wide/16 v14, 0x0

    .line 315
    .line 316
    move-object/from16 v19, v16

    .line 317
    .line 318
    const/16 v16, 0x0

    .line 319
    .line 320
    move-object/from16 v21, v17

    .line 321
    .line 322
    const/16 v17, 0x0

    .line 323
    .line 324
    move-object/from16 v24, v18

    .line 325
    .line 326
    const/16 v18, 0x0

    .line 327
    .line 328
    move-object/from16 v25, v19

    .line 329
    .line 330
    const/16 v19, 0x0

    .line 331
    .line 332
    move-object/from16 v26, v21

    .line 333
    .line 334
    const/16 v21, 0x0

    .line 335
    .line 336
    move-object/from16 v1, v24

    .line 337
    .line 338
    move-object/from16 v0, v25

    .line 339
    .line 340
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 341
    .line 342
    .line 343
    move-object/from16 v9, v20

    .line 344
    .line 345
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v0

    .line 349
    check-cast v0, Lj91/c;

    .line 350
    .line 351
    iget v0, v0, Lj91/c;->e:F

    .line 352
    .line 353
    const v2, 0x7f12033c

    .line 354
    .line 355
    .line 356
    invoke-static {v1, v0, v9, v2, v9}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object v2

    .line 360
    move-object/from16 v14, v26

    .line 361
    .line 362
    invoke-virtual {v9, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v0

    .line 366
    check-cast v0, Lj91/f;

    .line 367
    .line 368
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 369
    .line 370
    .line 371
    move-result-object v3

    .line 372
    const v0, 0x7f121497

    .line 373
    .line 374
    .line 375
    invoke-static {v1, v0}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 376
    .line 377
    .line 378
    move-result-object v4

    .line 379
    const/4 v9, 0x0

    .line 380
    const-wide/16 v14, 0x0

    .line 381
    .line 382
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 383
    .line 384
    .line 385
    move-object/from16 v9, v20

    .line 386
    .line 387
    const/4 v0, 0x1

    .line 388
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 392
    .line 393
    .line 394
    goto :goto_5

    .line 395
    :cond_8
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 396
    .line 397
    .line 398
    :goto_5
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 399
    .line 400
    .line 401
    move-result-object v0

    .line 402
    if-eqz v0, :cond_9

    .line 403
    .line 404
    new-instance v1, Ln70/v;

    .line 405
    .line 406
    const/16 v2, 0xf

    .line 407
    .line 408
    move-object/from16 v3, p0

    .line 409
    .line 410
    move/from16 v4, p2

    .line 411
    .line 412
    invoke-direct {v1, v3, v4, v2}, Ln70/v;-><init>(Lay0/a;II)V

    .line 413
    .line 414
    .line 415
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 416
    .line 417
    :cond_9
    return-void
.end method
