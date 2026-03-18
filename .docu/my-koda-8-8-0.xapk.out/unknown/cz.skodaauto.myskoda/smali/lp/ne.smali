.class public abstract Llp/ne;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Li91/c2;ILjava/util/List;FLl2/o;I)V
    .locals 23

    .line 1
    move/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v8, p4

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v0, 0x4a3c2d9f    # 3083111.8f

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    move-object/from16 v1, p0

    .line 18
    .line 19
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/4 v11, 0x2

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v0, v11

    .line 29
    :goto_0
    or-int v0, p5, v0

    .line 30
    .line 31
    invoke-virtual {v8, v2}, Ll2/t;->e(I)Z

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    const/16 v5, 0x20

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v5, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v5

    .line 43
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    const/16 v5, 0x100

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v5, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v5

    .line 55
    invoke-virtual {v8, v4}, Ll2/t;->d(F)Z

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    if-eqz v5, :cond_3

    .line 60
    .line 61
    const/16 v5, 0x800

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/16 v5, 0x400

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v5

    .line 67
    and-int/lit16 v5, v0, 0x493

    .line 68
    .line 69
    const/16 v6, 0x492

    .line 70
    .line 71
    const/4 v12, 0x1

    .line 72
    const/4 v13, 0x0

    .line 73
    if-eq v5, v6, :cond_4

    .line 74
    .line 75
    move v5, v12

    .line 76
    goto :goto_4

    .line 77
    :cond_4
    move v5, v13

    .line 78
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 79
    .line 80
    invoke-virtual {v8, v6, v5}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_b

    .line 85
    .line 86
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 87
    .line 88
    invoke-static {v14, v4}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 93
    .line 94
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 95
    .line 96
    invoke-static {v6, v7, v8, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 97
    .line 98
    .line 99
    move-result-object v6

    .line 100
    iget-wide v9, v8, Ll2/t;->T:J

    .line 101
    .line 102
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 103
    .line 104
    .line 105
    move-result v7

    .line 106
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 107
    .line 108
    .line 109
    move-result-object v9

    .line 110
    invoke-static {v8, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 115
    .line 116
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 120
    .line 121
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 122
    .line 123
    .line 124
    iget-boolean v15, v8, Ll2/t;->S:Z

    .line 125
    .line 126
    if-eqz v15, :cond_5

    .line 127
    .line 128
    invoke-virtual {v8, v10}, Ll2/t;->l(Lay0/a;)V

    .line 129
    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_5
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 133
    .line 134
    .line 135
    :goto_5
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 136
    .line 137
    invoke-static {v10, v6, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 141
    .line 142
    invoke-static {v6, v9, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 146
    .line 147
    iget-boolean v9, v8, Ll2/t;->S:Z

    .line 148
    .line 149
    if-nez v9, :cond_6

    .line 150
    .line 151
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v9

    .line 155
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v10

    .line 159
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    if-nez v9, :cond_7

    .line 164
    .line 165
    :cond_6
    invoke-static {v7, v8, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 166
    .line 167
    .line 168
    :cond_7
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 169
    .line 170
    invoke-static {v6, v5, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    sget-object v15, Lj91/h;->a:Ll2/u2;

    .line 174
    .line 175
    invoke-virtual {v8, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    check-cast v5, Lj91/e;

    .line 180
    .line 181
    invoke-virtual {v5}, Lj91/e;->c()J

    .line 182
    .line 183
    .line 184
    move-result-wide v5

    .line 185
    sget-object v7, Le3/j0;->a:Le3/i0;

    .line 186
    .line 187
    invoke-static {v14, v5, v6, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 188
    .line 189
    .line 190
    move-result-object v16

    .line 191
    if-nez v2, :cond_8

    .line 192
    .line 193
    int-to-float v5, v13

    .line 194
    :goto_6
    move/from16 v18, v5

    .line 195
    .line 196
    goto :goto_7

    .line 197
    :cond_8
    const/16 v5, 0xc

    .line 198
    .line 199
    int-to-float v5, v5

    .line 200
    goto :goto_6

    .line 201
    :goto_7
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 202
    .line 203
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v6

    .line 207
    check-cast v6, Lj91/c;

    .line 208
    .line 209
    iget v6, v6, Lj91/c;->k:F

    .line 210
    .line 211
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v9

    .line 215
    check-cast v9, Lj91/c;

    .line 216
    .line 217
    iget v9, v9, Lj91/c;->k:F

    .line 218
    .line 219
    const/16 v20, 0x0

    .line 220
    .line 221
    const/16 v21, 0x8

    .line 222
    .line 223
    move/from16 v17, v6

    .line 224
    .line 225
    move/from16 v19, v9

    .line 226
    .line 227
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 228
    .line 229
    .line 230
    move-result-object v6

    .line 231
    and-int/lit8 v9, v0, 0xe

    .line 232
    .line 233
    const/4 v10, 0x4

    .line 234
    move-object v0, v7

    .line 235
    const/4 v7, 0x0

    .line 236
    move-object/from16 v22, v1

    .line 237
    .line 238
    move-object v1, v0

    .line 239
    move-object v0, v5

    .line 240
    move-object/from16 v5, v22

    .line 241
    .line 242
    invoke-static/range {v5 .. v10}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v8, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v5

    .line 249
    check-cast v5, Lj91/e;

    .line 250
    .line 251
    invoke-virtual {v5}, Lj91/e;->c()J

    .line 252
    .line 253
    .line 254
    move-result-wide v5

    .line 255
    invoke-static {v14, v5, v6, v1}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    check-cast v0, Lj91/c;

    .line 264
    .line 265
    iget v0, v0, Lj91/c;->k:F

    .line 266
    .line 267
    const/4 v5, 0x0

    .line 268
    invoke-static {v1, v0, v5, v11}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    invoke-static {v13, v13, v8, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 273
    .line 274
    .line 275
    const v0, -0xbfdae66

    .line 276
    .line 277
    .line 278
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 279
    .line 280
    .line 281
    move-object v0, v3

    .line 282
    check-cast v0, Ljava/lang/Iterable;

    .line 283
    .line 284
    new-instance v1, Ljava/util/ArrayList;

    .line 285
    .line 286
    const/16 v5, 0xa

    .line 287
    .line 288
    invoke-static {v0, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 289
    .line 290
    .line 291
    move-result v5

    .line 292
    invoke-direct {v1, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 293
    .line 294
    .line 295
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    move v5, v13

    .line 300
    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 301
    .line 302
    .line 303
    move-result v6

    .line 304
    if-eqz v6, :cond_a

    .line 305
    .line 306
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v6

    .line 310
    add-int/lit8 v7, v5, 0x1

    .line 311
    .line 312
    if-ltz v5, :cond_9

    .line 313
    .line 314
    check-cast v6, Li91/c2;

    .line 315
    .line 316
    invoke-static {v5, v6, v8, v13}, Llp/ne;->j(ILi91/c2;Ll2/o;I)V

    .line 317
    .line 318
    .line 319
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 320
    .line 321
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 322
    .line 323
    .line 324
    move v5, v7

    .line 325
    goto :goto_8

    .line 326
    :cond_9
    invoke-static {}, Ljp/k1;->r()V

    .line 327
    .line 328
    .line 329
    const/4 v0, 0x0

    .line 330
    throw v0

    .line 331
    :cond_a
    invoke-virtual {v8, v13}, Ll2/t;->q(Z)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 335
    .line 336
    .line 337
    goto :goto_9

    .line 338
    :cond_b
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 339
    .line 340
    .line 341
    :goto_9
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 342
    .line 343
    .line 344
    move-result-object v6

    .line 345
    if-eqz v6, :cond_c

    .line 346
    .line 347
    new-instance v0, Ll30/b;

    .line 348
    .line 349
    move-object/from16 v1, p0

    .line 350
    .line 351
    move/from16 v5, p5

    .line 352
    .line 353
    invoke-direct/range {v0 .. v5}, Ll30/b;-><init>(Li91/c2;ILjava/util/List;FI)V

    .line 354
    .line 355
    .line 356
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 357
    .line 358
    :cond_c
    return-void
.end method

.method public static final b(Lay0/o;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    move/from16 v7, p2

    .line 4
    .line 5
    const-string v0, "viewPlans"

    .line 6
    .line 7
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v8, p1

    .line 11
    .line 12
    check-cast v8, Ll2/t;

    .line 13
    .line 14
    const v0, 0x2b000d0c

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    and-int/lit8 v0, v7, 0x3

    .line 21
    .line 22
    const/4 v1, 0x2

    .line 23
    if-eq v0, v1, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    and-int/lit8 v1, v7, 0x1

    .line 29
    .line 30
    invoke-virtual {v8, v1, v0}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_7

    .line 35
    .line 36
    const-string v0, "CouponsFlowScreen"

    .line 37
    .line 38
    invoke-static {v0, v8}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 47
    .line 48
    if-ne v1, v2, :cond_1

    .line 49
    .line 50
    new-instance v1, Lw81/d;

    .line 51
    .line 52
    const/16 v3, 0x11

    .line 53
    .line 54
    invoke-direct {v1, v3}, Lw81/d;-><init>(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v8, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_1
    check-cast v1, Lay0/k;

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-ne v1, v2, :cond_2

    .line 71
    .line 72
    new-instance v1, Lw81/d;

    .line 73
    .line 74
    const/16 v4, 0x12

    .line 75
    .line 76
    invoke-direct {v1, v4}, Lw81/d;-><init>(I)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v8, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_2
    check-cast v1, Lay0/k;

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    if-ne v1, v2, :cond_3

    .line 93
    .line 94
    new-instance v1, Lw81/d;

    .line 95
    .line 96
    const/16 v6, 0x13

    .line 97
    .line 98
    invoke-direct {v1, v6}, Lw81/d;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v8, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    :cond_3
    check-cast v1, Lay0/k;

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    if-ne v1, v2, :cond_4

    .line 115
    .line 116
    new-instance v1, Lx40/e;

    .line 117
    .line 118
    const/16 v9, 0xc

    .line 119
    .line 120
    invoke-direct {v1, v9}, Lx40/e;-><init>(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v8, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_4
    check-cast v1, Lay0/n;

    .line 127
    .line 128
    new-instance v9, Ly1/i;

    .line 129
    .line 130
    const/16 v10, 0x11

    .line 131
    .line 132
    invoke-direct {v9, v0, v10}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0}, Lzb/v0;->b()Lz9/y;

    .line 136
    .line 137
    .line 138
    move-result-object v10

    .line 139
    invoke-virtual {v8, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    invoke-virtual {v8, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v11

    .line 147
    or-int/2addr v0, v11

    .line 148
    invoke-virtual {v8, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v11

    .line 152
    or-int/2addr v0, v11

    .line 153
    invoke-virtual {v8, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v11

    .line 157
    or-int/2addr v0, v11

    .line 158
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v11

    .line 162
    if-nez v0, :cond_5

    .line 163
    .line 164
    if-ne v11, v2, :cond_6

    .line 165
    .line 166
    :cond_5
    new-instance v0, Lbi/a;

    .line 167
    .line 168
    move-object v2, v9

    .line 169
    invoke-direct/range {v0 .. v6}, Lbi/a;-><init>(Lay0/n;Ly1/i;Lyj/b;Lyj/b;Lay0/o;Lyj/b;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    move-object v11, v0

    .line 176
    :cond_6
    move-object/from16 v16, v11

    .line 177
    .line 178
    check-cast v16, Lay0/k;

    .line 179
    .line 180
    const/16 v19, 0x0

    .line 181
    .line 182
    const/16 v20, 0x3fc

    .line 183
    .line 184
    const-string v9, "/overview"

    .line 185
    .line 186
    move-object/from16 v17, v8

    .line 187
    .line 188
    move-object v8, v10

    .line 189
    const/4 v10, 0x0

    .line 190
    const/4 v11, 0x0

    .line 191
    const/4 v12, 0x0

    .line 192
    const/4 v13, 0x0

    .line 193
    const/4 v14, 0x0

    .line 194
    const/4 v15, 0x0

    .line 195
    const/16 v18, 0x30

    .line 196
    .line 197
    invoke-static/range {v8 .. v20}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 198
    .line 199
    .line 200
    goto :goto_1

    .line 201
    :cond_7
    move-object/from16 v17, v8

    .line 202
    .line 203
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 204
    .line 205
    .line 206
    :goto_1
    invoke-virtual/range {v17 .. v17}, Ll2/t;->s()Ll2/u1;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    if-eqz v0, :cond_8

    .line 211
    .line 212
    new-instance v1, Ltj/g;

    .line 213
    .line 214
    const/16 v2, 0x12

    .line 215
    .line 216
    invoke-direct {v1, v5, v7, v2}, Ltj/g;-><init>(Ljava/lang/Object;II)V

    .line 217
    .line 218
    .line 219
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 220
    .line 221
    :cond_8
    return-void
.end method

.method public static final c(Lk30/e;Lx2/s;Ll2/o;I)V
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v6, p2

    .line 8
    .line 9
    check-cast v6, Ll2/t;

    .line 10
    .line 11
    const v3, -0x1d4f7c15

    .line 12
    .line 13
    .line 14
    invoke-virtual {v6, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v6, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v10, 0x2

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    const/4 v3, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v3, v10

    .line 27
    :goto_0
    or-int/2addr v3, v2

    .line 28
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    const/16 v11, 0x10

    .line 33
    .line 34
    if-eqz v4, :cond_1

    .line 35
    .line 36
    const/16 v4, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v4, v11

    .line 40
    :goto_1
    or-int/2addr v3, v4

    .line 41
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    const/4 v12, 0x1

    .line 46
    const/4 v13, 0x0

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v12

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    move v4, v13

    .line 52
    :goto_2
    and-int/2addr v3, v12

    .line 53
    invoke-virtual {v6, v3, v4}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_e

    .line 58
    .line 59
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 60
    .line 61
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 62
    .line 63
    invoke-static {v3, v4, v6, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    iget-wide v4, v6, Ll2/t;->T:J

    .line 68
    .line 69
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    invoke-static {v6, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 82
    .line 83
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 87
    .line 88
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 89
    .line 90
    .line 91
    iget-boolean v14, v6, Ll2/t;->S:Z

    .line 92
    .line 93
    if-eqz v14, :cond_3

    .line 94
    .line 95
    invoke-virtual {v6, v8}, Ll2/t;->l(Lay0/a;)V

    .line 96
    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_3
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 100
    .line 101
    .line 102
    :goto_3
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 103
    .line 104
    invoke-static {v8, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 105
    .line 106
    .line 107
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 108
    .line 109
    invoke-static {v3, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 110
    .line 111
    .line 112
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 113
    .line 114
    iget-boolean v5, v6, Ll2/t;->S:Z

    .line 115
    .line 116
    if-nez v5, :cond_4

    .line 117
    .line 118
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 123
    .line 124
    .line 125
    move-result-object v8

    .line 126
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v5

    .line 130
    if-nez v5, :cond_5

    .line 131
    .line 132
    :cond_4
    invoke-static {v4, v6, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 133
    .line 134
    .line 135
    :cond_5
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 136
    .line 137
    invoke-static {v3, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 141
    .line 142
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    check-cast v4, Lj91/c;

    .line 147
    .line 148
    iget v4, v4, Lj91/c;->e:F

    .line 149
    .line 150
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 151
    .line 152
    invoke-static {v14, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-static {v6, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 157
    .line 158
    .line 159
    invoke-static {v6, v13}, Llp/ne;->h(Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v3

    .line 166
    check-cast v3, Lj91/c;

    .line 167
    .line 168
    iget v3, v3, Lj91/c;->f:F

    .line 169
    .line 170
    invoke-static {v14, v3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    invoke-static {v6, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 175
    .line 176
    .line 177
    const v3, -0x84558c3

    .line 178
    .line 179
    .line 180
    invoke-virtual {v6, v3}, Ll2/t;->Y(I)V

    .line 181
    .line 182
    .line 183
    iget-object v3, v0, Lk30/e;->g:Ljava/util/List;

    .line 184
    .line 185
    check-cast v3, Ljava/lang/Iterable;

    .line 186
    .line 187
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 188
    .line 189
    .line 190
    move-result-object v20

    .line 191
    move v3, v13

    .line 192
    :goto_4
    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->hasNext()Z

    .line 193
    .line 194
    .line 195
    move-result v4

    .line 196
    if-eqz v4, :cond_d

    .line 197
    .line 198
    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    add-int/lit8 v21, v3, 0x1

    .line 203
    .line 204
    const/4 v5, 0x0

    .line 205
    if-ltz v3, :cond_c

    .line 206
    .line 207
    check-cast v4, Lk30/d;

    .line 208
    .line 209
    new-instance v22, Li91/c2;

    .line 210
    .line 211
    iget-object v7, v4, Lk30/d;->a:Ljava/lang/String;

    .line 212
    .line 213
    new-instance v8, Li91/q1;

    .line 214
    .line 215
    iget v4, v4, Lk30/d;->b:I

    .line 216
    .line 217
    const/4 v15, 0x6

    .line 218
    invoke-direct {v8, v4, v5, v15}, Li91/q1;-><init>(ILe3/s;I)V

    .line 219
    .line 220
    .line 221
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 222
    .line 223
    .line 224
    move-result-object v4

    .line 225
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 226
    .line 227
    .line 228
    move-result-wide v4

    .line 229
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 230
    .line 231
    .line 232
    move-result-object v15

    .line 233
    invoke-virtual {v15}, Lj91/e;->r()J

    .line 234
    .line 235
    .line 236
    move-result-wide v26

    .line 237
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 238
    .line 239
    .line 240
    move-result-object v15

    .line 241
    invoke-virtual {v15}, Lj91/e;->s()J

    .line 242
    .line 243
    .line 244
    move-result-wide v15

    .line 245
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 246
    .line 247
    .line 248
    move-result-object v17

    .line 249
    invoke-virtual/range {v17 .. v17}, Lj91/e;->r()J

    .line 250
    .line 251
    .line 252
    move-result-wide v30

    .line 253
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 254
    .line 255
    .line 256
    move-result-object v17

    .line 257
    invoke-virtual/range {v17 .. v17}, Lj91/e;->q()J

    .line 258
    .line 259
    .line 260
    move-result-wide v17

    .line 261
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 262
    .line 263
    .line 264
    move-result-object v19

    .line 265
    invoke-virtual/range {v19 .. v19}, Lj91/e;->r()J

    .line 266
    .line 267
    .line 268
    move-result-wide v34

    .line 269
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 270
    .line 271
    .line 272
    move-result-object v19

    .line 273
    invoke-virtual/range {v19 .. v19}, Lj91/e;->q()J

    .line 274
    .line 275
    .line 276
    move-result-wide v23

    .line 277
    invoke-static {v6}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 278
    .line 279
    .line 280
    move-result-object v19

    .line 281
    invoke-virtual/range {v19 .. v19}, Lj91/e;->r()J

    .line 282
    .line 283
    .line 284
    move-result-wide v38

    .line 285
    const/16 p2, 0x4

    .line 286
    .line 287
    sget-object v9, Lj91/h;->a:Ll2/u2;

    .line 288
    .line 289
    invoke-virtual {v6, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v19

    .line 293
    check-cast v19, Lj91/e;

    .line 294
    .line 295
    invoke-virtual/range {v19 .. v19}, Lj91/e;->r()J

    .line 296
    .line 297
    .line 298
    move-result-wide v28

    .line 299
    invoke-virtual {v6, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v9

    .line 303
    check-cast v9, Lj91/e;

    .line 304
    .line 305
    invoke-virtual {v9}, Lj91/e;->r()J

    .line 306
    .line 307
    .line 308
    move-result-wide v32

    .line 309
    const/16 v9, 0xbe

    .line 310
    .line 311
    and-int/2addr v9, v12

    .line 312
    if-eqz v9, :cond_6

    .line 313
    .line 314
    goto :goto_5

    .line 315
    :cond_6
    move-wide/from16 v4, v32

    .line 316
    .line 317
    :goto_5
    const/16 v9, 0xbe

    .line 318
    .line 319
    and-int/lit8 v19, v9, 0x4

    .line 320
    .line 321
    const-wide/16 v32, 0x0

    .line 322
    .line 323
    if-eqz v19, :cond_7

    .line 324
    .line 325
    goto :goto_6

    .line 326
    :cond_7
    move-wide/from16 v15, v32

    .line 327
    .line 328
    :goto_6
    and-int/lit8 v19, v9, 0x10

    .line 329
    .line 330
    if-eqz v19, :cond_8

    .line 331
    .line 332
    move-wide/from16 v32, v17

    .line 333
    .line 334
    :cond_8
    and-int/lit8 v9, v9, 0x40

    .line 335
    .line 336
    if-eqz v9, :cond_9

    .line 337
    .line 338
    move-wide/from16 v36, v23

    .line 339
    .line 340
    goto :goto_7

    .line 341
    :cond_9
    move-wide/from16 v36, v28

    .line 342
    .line 343
    :goto_7
    new-instance v28, Li91/t1;

    .line 344
    .line 345
    move-wide/from16 v24, v4

    .line 346
    .line 347
    move-object/from16 v23, v28

    .line 348
    .line 349
    move-wide/from16 v28, v15

    .line 350
    .line 351
    invoke-direct/range {v23 .. v39}, Li91/t1;-><init>(JJJJJJJJ)V

    .line 352
    .line 353
    .line 354
    move-object/from16 v28, v23

    .line 355
    .line 356
    const/16 v31, 0x0

    .line 357
    .line 358
    const/16 v32, 0xfda

    .line 359
    .line 360
    const/16 v24, 0x0

    .line 361
    .line 362
    const/16 v26, 0x0

    .line 363
    .line 364
    const/16 v27, 0x0

    .line 365
    .line 366
    const/16 v29, 0x0

    .line 367
    .line 368
    const/16 v30, 0x0

    .line 369
    .line 370
    move-object/from16 v23, v7

    .line 371
    .line 372
    move-object/from16 v25, v8

    .line 373
    .line 374
    invoke-direct/range {v22 .. v32}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 375
    .line 376
    .line 377
    if-nez v3, :cond_a

    .line 378
    .line 379
    const v4, -0x5f762032

    .line 380
    .line 381
    .line 382
    invoke-virtual {v6, v4}, Ll2/t;->Y(I)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v6, v13}, Ll2/t;->q(Z)V

    .line 386
    .line 387
    .line 388
    int-to-float v4, v13

    .line 389
    :goto_8
    move/from16 v16, v4

    .line 390
    .line 391
    goto :goto_9

    .line 392
    :cond_a
    const v4, -0x5f761c8d

    .line 393
    .line 394
    .line 395
    invoke-virtual {v6, v4}, Ll2/t;->Y(I)V

    .line 396
    .line 397
    .line 398
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 399
    .line 400
    invoke-virtual {v6, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    check-cast v4, Lj91/c;

    .line 405
    .line 406
    iget v4, v4, Lj91/c;->c:F

    .line 407
    .line 408
    invoke-virtual {v6, v13}, Ll2/t;->q(Z)V

    .line 409
    .line 410
    .line 411
    goto :goto_8

    .line 412
    :goto_9
    sget-object v9, Lj91/a;->a:Ll2/u2;

    .line 413
    .line 414
    invoke-virtual {v6, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v4

    .line 418
    check-cast v4, Lj91/c;

    .line 419
    .line 420
    iget v15, v4, Lj91/c;->k:F

    .line 421
    .line 422
    invoke-virtual {v6, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v4

    .line 426
    check-cast v4, Lj91/c;

    .line 427
    .line 428
    iget v4, v4, Lj91/c;->k:F

    .line 429
    .line 430
    const/16 v18, 0x0

    .line 431
    .line 432
    const/16 v19, 0x8

    .line 433
    .line 434
    move/from16 v17, v4

    .line 435
    .line 436
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 437
    .line 438
    .line 439
    move-result-object v4

    .line 440
    const/4 v7, 0x0

    .line 441
    const/4 v8, 0x4

    .line 442
    const/4 v5, 0x0

    .line 443
    move v15, v3

    .line 444
    move-object/from16 v3, v22

    .line 445
    .line 446
    invoke-static/range {v3 .. v8}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 447
    .line 448
    .line 449
    iget-object v3, v0, Lk30/e;->g:Ljava/util/List;

    .line 450
    .line 451
    invoke-static {v3}, Ljp/k1;->h(Ljava/util/List;)I

    .line 452
    .line 453
    .line 454
    move-result v3

    .line 455
    if-eq v15, v3, :cond_b

    .line 456
    .line 457
    const v3, 0x70b61ea5

    .line 458
    .line 459
    .line 460
    invoke-virtual {v6, v3}, Ll2/t;->Y(I)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v6, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v3

    .line 467
    check-cast v3, Lj91/c;

    .line 468
    .line 469
    iget v3, v3, Lj91/c;->k:F

    .line 470
    .line 471
    const/4 v4, 0x0

    .line 472
    invoke-static {v14, v3, v4, v10}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 473
    .line 474
    .line 475
    move-result-object v3

    .line 476
    invoke-static {v13, v13, v6, v3}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 477
    .line 478
    .line 479
    :goto_a
    invoke-virtual {v6, v13}, Ll2/t;->q(Z)V

    .line 480
    .line 481
    .line 482
    goto :goto_b

    .line 483
    :cond_b
    const v3, 0x6fc4aa76

    .line 484
    .line 485
    .line 486
    invoke-virtual {v6, v3}, Ll2/t;->Y(I)V

    .line 487
    .line 488
    .line 489
    goto :goto_a

    .line 490
    :goto_b
    move/from16 v3, v21

    .line 491
    .line 492
    goto/16 :goto_4

    .line 493
    .line 494
    :cond_c
    invoke-static {}, Ljp/k1;->r()V

    .line 495
    .line 496
    .line 497
    throw v5

    .line 498
    :cond_d
    invoke-virtual {v6, v13}, Ll2/t;->q(Z)V

    .line 499
    .line 500
    .line 501
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 502
    .line 503
    .line 504
    goto :goto_c

    .line 505
    :cond_e
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 506
    .line 507
    .line 508
    :goto_c
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 509
    .line 510
    .line 511
    move-result-object v3

    .line 512
    if-eqz v3, :cond_f

    .line 513
    .line 514
    new-instance v4, Ll2/u;

    .line 515
    .line 516
    const/4 v5, 0x2

    .line 517
    invoke-direct {v4, v2, v5, v0, v1}, Ll2/u;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 518
    .line 519
    .line 520
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 521
    .line 522
    :cond_f
    return-void
.end method

.method public static final d(Li91/c2;FZZLl2/o;I)V
    .locals 20

    .line 1
    move/from16 v2, p1

    .line 2
    .line 3
    move/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v8, p4

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v0, -0x2df82081

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    move-object/from16 v1, p0

    .line 18
    .line 19
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    const/4 v11, 0x2

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v0, v11

    .line 29
    :goto_0
    or-int v0, p5, v0

    .line 30
    .line 31
    invoke-virtual {v8, v2}, Ll2/t;->d(F)Z

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    const/16 v5, 0x20

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v5, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v5

    .line 43
    invoke-virtual {v8, v3}, Ll2/t;->h(Z)Z

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    const/16 v5, 0x100

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v5, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v5

    .line 55
    invoke-virtual {v8, v4}, Ll2/t;->h(Z)Z

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    if-eqz v5, :cond_3

    .line 60
    .line 61
    const/16 v5, 0x800

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/16 v5, 0x400

    .line 65
    .line 66
    :goto_3
    or-int/2addr v0, v5

    .line 67
    and-int/lit16 v5, v0, 0x493

    .line 68
    .line 69
    const/16 v6, 0x492

    .line 70
    .line 71
    const/4 v12, 0x1

    .line 72
    const/4 v13, 0x0

    .line 73
    if-eq v5, v6, :cond_4

    .line 74
    .line 75
    move v5, v12

    .line 76
    goto :goto_4

    .line 77
    :cond_4
    move v5, v13

    .line 78
    :goto_4
    and-int/lit8 v6, v0, 0x1

    .line 79
    .line 80
    invoke-virtual {v8, v6, v5}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eqz v5, :cond_a

    .line 85
    .line 86
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 87
    .line 88
    invoke-static {v14, v2}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 93
    .line 94
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 95
    .line 96
    invoke-static {v6, v7, v8, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 97
    .line 98
    .line 99
    move-result-object v6

    .line 100
    iget-wide v9, v8, Ll2/t;->T:J

    .line 101
    .line 102
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 103
    .line 104
    .line 105
    move-result v7

    .line 106
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 107
    .line 108
    .line 109
    move-result-object v9

    .line 110
    invoke-static {v8, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 115
    .line 116
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 120
    .line 121
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 122
    .line 123
    .line 124
    iget-boolean v15, v8, Ll2/t;->S:Z

    .line 125
    .line 126
    if-eqz v15, :cond_5

    .line 127
    .line 128
    invoke-virtual {v8, v10}, Ll2/t;->l(Lay0/a;)V

    .line 129
    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_5
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 133
    .line 134
    .line 135
    :goto_5
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 136
    .line 137
    invoke-static {v10, v6, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 141
    .line 142
    invoke-static {v6, v9, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 146
    .line 147
    iget-boolean v9, v8, Ll2/t;->S:Z

    .line 148
    .line 149
    if-nez v9, :cond_6

    .line 150
    .line 151
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v9

    .line 155
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v10

    .line 159
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    if-nez v9, :cond_7

    .line 164
    .line 165
    :cond_6
    invoke-static {v7, v8, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 166
    .line 167
    .line 168
    :cond_7
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 169
    .line 170
    invoke-static {v6, v5, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    if-eqz v3, :cond_8

    .line 174
    .line 175
    const v5, 0x2acb2e8b

    .line 176
    .line 177
    .line 178
    invoke-virtual {v8, v5}, Ll2/t;->Y(I)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v8, v13}, Ll2/t;->q(Z)V

    .line 182
    .line 183
    .line 184
    int-to-float v5, v13

    .line 185
    :goto_6
    move/from16 v16, v5

    .line 186
    .line 187
    goto :goto_7

    .line 188
    :cond_8
    const v5, 0x2acb3230

    .line 189
    .line 190
    .line 191
    invoke-virtual {v8, v5}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 195
    .line 196
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    check-cast v5, Lj91/c;

    .line 201
    .line 202
    iget v5, v5, Lj91/c;->c:F

    .line 203
    .line 204
    invoke-virtual {v8, v13}, Ll2/t;->q(Z)V

    .line 205
    .line 206
    .line 207
    goto :goto_6

    .line 208
    :goto_7
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 209
    .line 210
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v6

    .line 214
    check-cast v6, Lj91/c;

    .line 215
    .line 216
    iget v15, v6, Lj91/c;->k:F

    .line 217
    .line 218
    invoke-virtual {v8, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v6

    .line 222
    check-cast v6, Lj91/c;

    .line 223
    .line 224
    iget v6, v6, Lj91/c;->k:F

    .line 225
    .line 226
    const/16 v18, 0x0

    .line 227
    .line 228
    const/16 v19, 0x8

    .line 229
    .line 230
    move/from16 v17, v6

    .line 231
    .line 232
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 233
    .line 234
    .line 235
    move-result-object v6

    .line 236
    and-int/lit8 v9, v0, 0xe

    .line 237
    .line 238
    const/4 v10, 0x4

    .line 239
    const/4 v7, 0x0

    .line 240
    move-object v0, v5

    .line 241
    move-object v5, v1

    .line 242
    invoke-static/range {v5 .. v10}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 243
    .line 244
    .line 245
    if-nez v4, :cond_9

    .line 246
    .line 247
    const v1, 0x2e9e40d8

    .line 248
    .line 249
    .line 250
    invoke-virtual {v8, v1}, Ll2/t;->Y(I)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    check-cast v0, Lj91/c;

    .line 258
    .line 259
    iget v0, v0, Lj91/c;->k:F

    .line 260
    .line 261
    const/4 v1, 0x0

    .line 262
    invoke-static {v14, v0, v1, v11}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    invoke-static {v13, v13, v8, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 267
    .line 268
    .line 269
    :goto_8
    invoke-virtual {v8, v13}, Ll2/t;->q(Z)V

    .line 270
    .line 271
    .line 272
    goto :goto_9

    .line 273
    :cond_9
    const v0, 0x2e0096b9

    .line 274
    .line 275
    .line 276
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 277
    .line 278
    .line 279
    goto :goto_8

    .line 280
    :goto_9
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 281
    .line 282
    .line 283
    goto :goto_a

    .line 284
    :cond_a
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_a
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    if-eqz v6, :cond_b

    .line 292
    .line 293
    new-instance v0, Ll30/c;

    .line 294
    .line 295
    move-object/from16 v1, p0

    .line 296
    .line 297
    move/from16 v5, p5

    .line 298
    .line 299
    invoke-direct/range {v0 .. v5}, Ll30/c;-><init>(Li91/c2;FZZI)V

    .line 300
    .line 301
    .line 302
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 303
    .line 304
    :cond_b
    return-void
.end method

.method public static final e(Ll2/o;I)V
    .locals 13

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, -0x37b07a38

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_8

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_7

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v8

    .line 41
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v10

    .line 45
    const-class v2, Lk30/h;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v4, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v7, v1

    .line 73
    check-cast v7, Lk30/h;

    .line 74
    .line 75
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v4, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v0, p0

    .line 87
    check-cast v0, Lk30/e;

    .line 88
    .line 89
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez p0, :cond_1

    .line 100
    .line 101
    if-ne v1, v2, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v5, Ll20/c;

    .line 104
    .line 105
    const/4 v11, 0x0

    .line 106
    const/16 v12, 0x12

    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    const-class v8, Lk30/h;

    .line 110
    .line 111
    const-string v9, "onGoBack"

    .line 112
    .line 113
    const-string v10, "onGoBack()V"

    .line 114
    .line 115
    invoke-direct/range {v5 .. v12}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v5

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    if-nez p0, :cond_3

    .line 135
    .line 136
    if-ne v3, v2, :cond_4

    .line 137
    .line 138
    :cond_3
    new-instance v5, Ll20/c;

    .line 139
    .line 140
    const/4 v11, 0x0

    .line 141
    const/16 v12, 0x13

    .line 142
    .line 143
    const/4 v6, 0x0

    .line 144
    const-class v8, Lk30/h;

    .line 145
    .line 146
    const-string v9, "onRefresh"

    .line 147
    .line 148
    const-string v10, "onRefresh()V"

    .line 149
    .line 150
    invoke-direct/range {v5 .. v12}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object v3, v5

    .line 157
    :cond_4
    check-cast v3, Lhy0/g;

    .line 158
    .line 159
    check-cast v3, Lay0/a;

    .line 160
    .line 161
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    if-nez p0, :cond_5

    .line 170
    .line 171
    if-ne v5, v2, :cond_6

    .line 172
    .line 173
    :cond_5
    new-instance v5, Ll20/c;

    .line 174
    .line 175
    const/4 v11, 0x0

    .line 176
    const/16 v12, 0x14

    .line 177
    .line 178
    const/4 v6, 0x0

    .line 179
    const-class v8, Lk30/h;

    .line 180
    .line 181
    const-string v9, "onAnimationsFinished"

    .line 182
    .line 183
    const-string v10, "onAnimationsFinished()V"

    .line 184
    .line 185
    invoke-direct/range {v5 .. v12}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    :cond_6
    check-cast v5, Lhy0/g;

    .line 192
    .line 193
    check-cast v5, Lay0/a;

    .line 194
    .line 195
    move-object v2, v3

    .line 196
    move-object v3, v5

    .line 197
    const/4 v5, 0x0

    .line 198
    invoke-static/range {v0 .. v5}, Llp/ne;->f(Lk30/e;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 199
    .line 200
    .line 201
    goto :goto_1

    .line 202
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 203
    .line 204
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 205
    .line 206
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :cond_8
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 211
    .line 212
    .line 213
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    if-eqz p0, :cond_9

    .line 218
    .line 219
    new-instance v0, Ll20/f;

    .line 220
    .line 221
    const/4 v1, 0x5

    .line 222
    invoke-direct {v0, p1, v1}, Ll20/f;-><init>(II)V

    .line 223
    .line 224
    .line 225
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 226
    .line 227
    :cond_9
    return-void
.end method

.method public static final f(Lk30/e;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v4, p1

    .line 2
    .line 3
    move-object/from16 v0, p4

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, -0x6398e0e1

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    move-object/from16 v3, p0

    .line 14
    .line 15
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v1, 0x2

    .line 24
    :goto_0
    or-int v1, p5, v1

    .line 25
    .line 26
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v2, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v1, v2

    .line 38
    move-object/from16 v5, p2

    .line 39
    .line 40
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const/16 v2, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v2, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v1, v2

    .line 52
    move-object/from16 v6, p3

    .line 53
    .line 54
    invoke-virtual {v0, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_3

    .line 59
    .line 60
    const/16 v2, 0x800

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v2, 0x400

    .line 64
    .line 65
    :goto_3
    or-int/2addr v1, v2

    .line 66
    and-int/lit16 v2, v1, 0x493

    .line 67
    .line 68
    const/16 v7, 0x492

    .line 69
    .line 70
    const/4 v8, 0x1

    .line 71
    if-eq v2, v7, :cond_4

    .line 72
    .line 73
    move v2, v8

    .line 74
    goto :goto_4

    .line 75
    :cond_4
    const/4 v2, 0x0

    .line 76
    :goto_4
    and-int/2addr v1, v8

    .line 77
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eqz v1, :cond_5

    .line 82
    .line 83
    new-instance v1, Li40/r0;

    .line 84
    .line 85
    const/16 v2, 0x19

    .line 86
    .line 87
    invoke-direct {v1, v4, v2}, Li40/r0;-><init>(Lay0/a;I)V

    .line 88
    .line 89
    .line 90
    const v2, -0x66003b1d

    .line 91
    .line 92
    .line 93
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    new-instance v5, Li40/n2;

    .line 98
    .line 99
    const/4 v10, 0x4

    .line 100
    const/4 v8, 0x0

    .line 101
    move-object/from16 v7, p2

    .line 102
    .line 103
    move-object v9, v6

    .line 104
    move-object v6, v3

    .line 105
    invoke-direct/range {v5 .. v10}, Li40/n2;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    const v2, 0x348ee6e

    .line 109
    .line 110
    .line 111
    invoke-static {v2, v0, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 112
    .line 113
    .line 114
    move-result-object v16

    .line 115
    const v18, 0x30000030

    .line 116
    .line 117
    .line 118
    const/16 v19, 0x1fd

    .line 119
    .line 120
    const/4 v5, 0x0

    .line 121
    const/4 v7, 0x0

    .line 122
    const/4 v8, 0x0

    .line 123
    const/4 v9, 0x0

    .line 124
    const/4 v10, 0x0

    .line 125
    const-wide/16 v11, 0x0

    .line 126
    .line 127
    const-wide/16 v13, 0x0

    .line 128
    .line 129
    const/4 v15, 0x0

    .line 130
    move-object/from16 v17, v0

    .line 131
    .line 132
    move-object v6, v1

    .line 133
    invoke-static/range {v5 .. v19}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 134
    .line 135
    .line 136
    goto :goto_5

    .line 137
    :cond_5
    move-object/from16 v17, v0

    .line 138
    .line 139
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 140
    .line 141
    .line 142
    :goto_5
    invoke-virtual/range {v17 .. v17}, Ll2/t;->s()Ll2/u1;

    .line 143
    .line 144
    .line 145
    move-result-object v8

    .line 146
    if-eqz v8, :cond_6

    .line 147
    .line 148
    new-instance v0, Laj0/b;

    .line 149
    .line 150
    const/16 v2, 0x16

    .line 151
    .line 152
    const/4 v7, 0x0

    .line 153
    move-object/from16 v3, p0

    .line 154
    .line 155
    move-object/from16 v5, p2

    .line 156
    .line 157
    move-object/from16 v6, p3

    .line 158
    .line 159
    move/from16 v1, p5

    .line 160
    .line 161
    invoke-direct/range {v0 .. v7}, Laj0/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 162
    .line 163
    .line 164
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 165
    .line 166
    :cond_6
    return-void
.end method

.method public static final g(Lk30/e;Ll2/o;I)V
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    check-cast v2, Ll2/t;

    .line 6
    .line 7
    const v3, 0x36c53e68

    .line 8
    .line 9
    .line 10
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v3, p2, 0x6

    .line 14
    .line 15
    const/4 v4, 0x2

    .line 16
    if-nez v3, :cond_1

    .line 17
    .line 18
    invoke-virtual {v2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    const/4 v3, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v3, v4

    .line 27
    :goto_0
    or-int v3, p2, v3

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move/from16 v3, p2

    .line 31
    .line 32
    :goto_1
    and-int/lit8 v5, v3, 0x3

    .line 33
    .line 34
    const/4 v6, 0x1

    .line 35
    const/4 v7, 0x0

    .line 36
    if-eq v5, v4, :cond_2

    .line 37
    .line 38
    move v5, v6

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    move v5, v7

    .line 41
    :goto_2
    and-int/2addr v3, v6

    .line 42
    invoke-virtual {v2, v3, v5}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_b

    .line 47
    .line 48
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 49
    .line 50
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    check-cast v5, Lj91/c;

    .line 55
    .line 56
    iget v5, v5, Lj91/c;->d:F

    .line 57
    .line 58
    const/4 v8, 0x0

    .line 59
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 60
    .line 61
    invoke-static {v9, v5, v8, v4}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 66
    .line 67
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 68
    .line 69
    invoke-static {v5, v8, v2, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    iget-wide v10, v2, Ll2/t;->T:J

    .line 74
    .line 75
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 76
    .line 77
    .line 78
    move-result v8

    .line 79
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 80
    .line 81
    .line 82
    move-result-object v10

    .line 83
    invoke-static {v2, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 88
    .line 89
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 93
    .line 94
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 95
    .line 96
    .line 97
    iget-boolean v12, v2, Ll2/t;->S:Z

    .line 98
    .line 99
    if-eqz v12, :cond_3

    .line 100
    .line 101
    invoke-virtual {v2, v11}, Ll2/t;->l(Lay0/a;)V

    .line 102
    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_3
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 106
    .line 107
    .line 108
    :goto_3
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 109
    .line 110
    invoke-static {v12, v5, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 111
    .line 112
    .line 113
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 114
    .line 115
    invoke-static {v5, v10, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    .line 117
    .line 118
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 119
    .line 120
    iget-boolean v13, v2, Ll2/t;->S:Z

    .line 121
    .line 122
    if-nez v13, :cond_4

    .line 123
    .line 124
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v13

    .line 128
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v14

    .line 132
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v13

    .line 136
    if-nez v13, :cond_5

    .line 137
    .line 138
    :cond_4
    invoke-static {v8, v2, v8, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 139
    .line 140
    .line 141
    :cond_5
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 142
    .line 143
    invoke-static {v8, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v4, Lk1/j;->a:Lk1/c;

    .line 147
    .line 148
    sget-object v13, Lx2/c;->m:Lx2/i;

    .line 149
    .line 150
    invoke-static {v4, v13, v2, v7}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 151
    .line 152
    .line 153
    move-result-object v4

    .line 154
    iget-wide v13, v2, Ll2/t;->T:J

    .line 155
    .line 156
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 157
    .line 158
    .line 159
    move-result v13

    .line 160
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 161
    .line 162
    .line 163
    move-result-object v14

    .line 164
    invoke-static {v2, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object v15

    .line 168
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 169
    .line 170
    .line 171
    iget-boolean v6, v2, Ll2/t;->S:Z

    .line 172
    .line 173
    if-eqz v6, :cond_6

    .line 174
    .line 175
    invoke-virtual {v2, v11}, Ll2/t;->l(Lay0/a;)V

    .line 176
    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_6
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 180
    .line 181
    .line 182
    :goto_4
    invoke-static {v12, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 183
    .line 184
    .line 185
    invoke-static {v5, v14, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 186
    .line 187
    .line 188
    iget-boolean v4, v2, Ll2/t;->S:Z

    .line 189
    .line 190
    if-nez v4, :cond_7

    .line 191
    .line 192
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v4

    .line 204
    if-nez v4, :cond_8

    .line 205
    .line 206
    :cond_7
    invoke-static {v13, v2, v13, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 207
    .line 208
    .line 209
    :cond_8
    invoke-static {v8, v15, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 210
    .line 211
    .line 212
    iget-boolean v4, v0, Lk30/e;->c:Z

    .line 213
    .line 214
    if-nez v4, :cond_9

    .line 215
    .line 216
    iget-boolean v4, v0, Lk30/e;->b:Z

    .line 217
    .line 218
    if-eqz v4, :cond_a

    .line 219
    .line 220
    :cond_9
    move-object v1, v3

    .line 221
    move v0, v7

    .line 222
    move-object/from16 v27, v9

    .line 223
    .line 224
    goto/16 :goto_5

    .line 225
    .line 226
    :cond_a
    const v4, 0x75e50e85

    .line 227
    .line 228
    .line 229
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 230
    .line 231
    .line 232
    iget-object v4, v0, Lk30/e;->e:Ljava/lang/String;

    .line 233
    .line 234
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 235
    .line 236
    invoke-virtual {v2, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v5

    .line 240
    check-cast v5, Lj91/f;

    .line 241
    .line 242
    invoke-virtual {v5}, Lj91/f;->k()Lg4/p0;

    .line 243
    .line 244
    .line 245
    move-result-object v5

    .line 246
    const-string v6, "vhr_found_warnings"

    .line 247
    .line 248
    invoke-static {v9, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 249
    .line 250
    .line 251
    move-result-object v6

    .line 252
    const/16 v22, 0x0

    .line 253
    .line 254
    const v23, 0xfff8

    .line 255
    .line 256
    .line 257
    move-object/from16 v20, v2

    .line 258
    .line 259
    move-object v8, v3

    .line 260
    move-object v2, v4

    .line 261
    move-object v3, v5

    .line 262
    move-object v4, v6

    .line 263
    const-wide/16 v5, 0x0

    .line 264
    .line 265
    move v11, v7

    .line 266
    move-object v10, v8

    .line 267
    const-wide/16 v7, 0x0

    .line 268
    .line 269
    move-object v12, v9

    .line 270
    const/4 v9, 0x0

    .line 271
    move-object v13, v10

    .line 272
    move v14, v11

    .line 273
    const-wide/16 v10, 0x0

    .line 274
    .line 275
    move-object v15, v12

    .line 276
    const/4 v12, 0x0

    .line 277
    move-object/from16 v16, v13

    .line 278
    .line 279
    const/4 v13, 0x0

    .line 280
    move/from16 v17, v14

    .line 281
    .line 282
    move-object/from16 v18, v15

    .line 283
    .line 284
    const-wide/16 v14, 0x0

    .line 285
    .line 286
    move-object/from16 v19, v16

    .line 287
    .line 288
    const/16 v16, 0x0

    .line 289
    .line 290
    move/from16 v21, v17

    .line 291
    .line 292
    const/16 v17, 0x0

    .line 293
    .line 294
    move-object/from16 v24, v18

    .line 295
    .line 296
    const/16 v18, 0x0

    .line 297
    .line 298
    move-object/from16 v25, v19

    .line 299
    .line 300
    const/16 v19, 0x0

    .line 301
    .line 302
    move/from16 v26, v21

    .line 303
    .line 304
    const/16 v21, 0x180

    .line 305
    .line 306
    move-object/from16 v27, v24

    .line 307
    .line 308
    move-object/from16 v1, v25

    .line 309
    .line 310
    move/from16 v0, v26

    .line 311
    .line 312
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 313
    .line 314
    .line 315
    move-object/from16 v2, v20

    .line 316
    .line 317
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 318
    .line 319
    .line 320
    move-object/from16 v15, v27

    .line 321
    .line 322
    const/4 v4, 0x1

    .line 323
    goto :goto_6

    .line 324
    :goto_5
    const v3, 0x75e2aaff

    .line 325
    .line 326
    .line 327
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 328
    .line 329
    .line 330
    const/4 v3, 0x0

    .line 331
    const/4 v4, 0x1

    .line 332
    invoke-static {v0, v4, v2, v3}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v3

    .line 339
    check-cast v3, Lj91/c;

    .line 340
    .line 341
    iget v3, v3, Lj91/c;->c:F

    .line 342
    .line 343
    move-object/from16 v15, v27

    .line 344
    .line 345
    invoke-static {v15, v3, v2, v0}, Lvj/b;->C(Lx2/p;FLl2/t;Z)V

    .line 346
    .line 347
    .line 348
    :goto_6
    invoke-virtual {v2, v4}, Ll2/t;->q(Z)V

    .line 349
    .line 350
    .line 351
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    check-cast v0, Lj91/c;

    .line 356
    .line 357
    iget v0, v0, Lj91/c;->c:F

    .line 358
    .line 359
    invoke-static {v15, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    invoke-static {v2, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 364
    .line 365
    .line 366
    move-object/from16 v0, p0

    .line 367
    .line 368
    iget-object v1, v0, Lk30/e;->d:Ljava/lang/String;

    .line 369
    .line 370
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 371
    .line 372
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v3

    .line 376
    check-cast v3, Lj91/f;

    .line 377
    .line 378
    invoke-virtual {v3}, Lj91/f;->e()Lg4/p0;

    .line 379
    .line 380
    .line 381
    move-result-object v3

    .line 382
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 383
    .line 384
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v4

    .line 388
    check-cast v4, Lj91/e;

    .line 389
    .line 390
    invoke-virtual {v4}, Lj91/e;->t()J

    .line 391
    .line 392
    .line 393
    move-result-wide v5

    .line 394
    const-string v4, "vhr_last_scanned_at"

    .line 395
    .line 396
    invoke-static {v15, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 397
    .line 398
    .line 399
    move-result-object v4

    .line 400
    const/16 v22, 0x0

    .line 401
    .line 402
    const v23, 0xfff0

    .line 403
    .line 404
    .line 405
    const-wide/16 v7, 0x0

    .line 406
    .line 407
    const/4 v9, 0x0

    .line 408
    const-wide/16 v10, 0x0

    .line 409
    .line 410
    const/4 v12, 0x0

    .line 411
    const/4 v13, 0x0

    .line 412
    const-wide/16 v14, 0x0

    .line 413
    .line 414
    const/16 v16, 0x0

    .line 415
    .line 416
    const/16 v17, 0x0

    .line 417
    .line 418
    const/16 v18, 0x0

    .line 419
    .line 420
    const/16 v19, 0x0

    .line 421
    .line 422
    const/16 v21, 0x180

    .line 423
    .line 424
    move-object/from16 v20, v2

    .line 425
    .line 426
    move-object v2, v1

    .line 427
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 428
    .line 429
    .line 430
    move-object/from16 v2, v20

    .line 431
    .line 432
    const/4 v4, 0x1

    .line 433
    invoke-virtual {v2, v4}, Ll2/t;->q(Z)V

    .line 434
    .line 435
    .line 436
    goto :goto_7

    .line 437
    :cond_b
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 438
    .line 439
    .line 440
    :goto_7
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    if-eqz v1, :cond_c

    .line 445
    .line 446
    new-instance v2, Ld90/h;

    .line 447
    .line 448
    const/16 v3, 0x8

    .line 449
    .line 450
    move/from16 v4, p2

    .line 451
    .line 452
    invoke-direct {v2, v0, v4, v3}, Ld90/h;-><init>(Ljava/lang/Object;II)V

    .line 453
    .line 454
    .line 455
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 456
    .line 457
    :cond_c
    return-void
.end method

.method public static final h(Ll2/o;I)V
    .locals 30

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    check-cast v1, Ll2/t;

    .line 4
    .line 5
    const v2, -0x64c37c5f

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
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 27
    .line 28
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 29
    .line 30
    invoke-static {v4, v5, v1, v2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    iget-wide v4, v1, Ll2/t;->T:J

    .line 35
    .line 36
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 45
    .line 46
    invoke-static {v1, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 51
    .line 52
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 56
    .line 57
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 58
    .line 59
    .line 60
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 61
    .line 62
    if-eqz v9, :cond_1

    .line 63
    .line 64
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 69
    .line 70
    .line 71
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 72
    .line 73
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 74
    .line 75
    .line 76
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 77
    .line 78
    invoke-static {v2, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 79
    .line 80
    .line 81
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 82
    .line 83
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 84
    .line 85
    if-nez v5, :cond_2

    .line 86
    .line 87
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-nez v5, :cond_3

    .line 100
    .line 101
    :cond_2
    invoke-static {v4, v1, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 102
    .line 103
    .line 104
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 105
    .line 106
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 107
    .line 108
    .line 109
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 110
    .line 111
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    check-cast v4, Lj91/f;

    .line 116
    .line 117
    invoke-virtual {v4}, Lj91/f;->k()Lg4/p0;

    .line 118
    .line 119
    .line 120
    move-result-object v4

    .line 121
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 122
    .line 123
    invoke-virtual {v1, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    check-cast v7, Lj91/c;

    .line 128
    .line 129
    iget v7, v7, Lj91/c;->d:F

    .line 130
    .line 131
    const/4 v8, 0x0

    .line 132
    const/4 v9, 0x2

    .line 133
    invoke-static {v6, v7, v8, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v7

    .line 137
    const/16 v21, 0x0

    .line 138
    .line 139
    const v22, 0xfff8

    .line 140
    .line 141
    .line 142
    move-object/from16 v19, v1

    .line 143
    .line 144
    const-string v1, "No records to show"

    .line 145
    .line 146
    move-object v10, v2

    .line 147
    move-object v2, v4

    .line 148
    move-object v11, v5

    .line 149
    const-wide/16 v4, 0x0

    .line 150
    .line 151
    move v12, v3

    .line 152
    move-object v13, v6

    .line 153
    move-object v3, v7

    .line 154
    const-wide/16 v6, 0x0

    .line 155
    .line 156
    move v14, v8

    .line 157
    const/4 v8, 0x0

    .line 158
    move/from16 v16, v9

    .line 159
    .line 160
    move-object v15, v10

    .line 161
    const-wide/16 v9, 0x0

    .line 162
    .line 163
    move-object/from16 v17, v11

    .line 164
    .line 165
    const/4 v11, 0x0

    .line 166
    move/from16 v18, v12

    .line 167
    .line 168
    const/4 v12, 0x0

    .line 169
    move-object/from16 v23, v13

    .line 170
    .line 171
    move/from16 v20, v14

    .line 172
    .line 173
    const-wide/16 v13, 0x0

    .line 174
    .line 175
    move-object/from16 v24, v15

    .line 176
    .line 177
    const/4 v15, 0x0

    .line 178
    move/from16 v25, v16

    .line 179
    .line 180
    const/16 v16, 0x0

    .line 181
    .line 182
    move-object/from16 v26, v17

    .line 183
    .line 184
    const/16 v17, 0x0

    .line 185
    .line 186
    move/from16 v27, v18

    .line 187
    .line 188
    const/16 v18, 0x0

    .line 189
    .line 190
    move/from16 v28, v20

    .line 191
    .line 192
    const/16 v20, 0x6

    .line 193
    .line 194
    move-object/from16 v29, v23

    .line 195
    .line 196
    move-object/from16 v0, v26

    .line 197
    .line 198
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 199
    .line 200
    .line 201
    move-object/from16 v1, v19

    .line 202
    .line 203
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    check-cast v2, Lj91/c;

    .line 208
    .line 209
    iget v2, v2, Lj91/c;->c:F

    .line 210
    .line 211
    move-object/from16 v15, v24

    .line 212
    .line 213
    move-object/from16 v13, v29

    .line 214
    .line 215
    invoke-static {v13, v2, v1, v15}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    check-cast v2, Lj91/f;

    .line 220
    .line 221
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 226
    .line 227
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    check-cast v3, Lj91/e;

    .line 232
    .line 233
    invoke-virtual {v3}, Lj91/e;->t()J

    .line 234
    .line 235
    .line 236
    move-result-wide v4

    .line 237
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    check-cast v0, Lj91/c;

    .line 242
    .line 243
    iget v0, v0, Lj91/c;->d:F

    .line 244
    .line 245
    const/4 v3, 0x2

    .line 246
    const/4 v14, 0x0

    .line 247
    invoke-static {v13, v0, v14, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    const v22, 0xfff0

    .line 252
    .line 253
    .line 254
    const-string v1, "An issue occurred and this information could not be displayed. We are working on fixing it right now."

    .line 255
    .line 256
    const-wide/16 v13, 0x0

    .line 257
    .line 258
    const/4 v15, 0x0

    .line 259
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 260
    .line 261
    .line 262
    move-object/from16 v1, v19

    .line 263
    .line 264
    const/4 v12, 0x1

    .line 265
    invoke-virtual {v1, v12}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    goto :goto_2

    .line 269
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 270
    .line 271
    .line 272
    :goto_2
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    if-eqz v0, :cond_5

    .line 277
    .line 278
    new-instance v1, Ll20/f;

    .line 279
    .line 280
    const/4 v2, 0x6

    .line 281
    move/from16 v3, p1

    .line 282
    .line 283
    invoke-direct {v1, v3, v2}, Ll20/f;-><init>(II)V

    .line 284
    .line 285
    .line 286
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 287
    .line 288
    :cond_5
    return-void
.end method

.method public static final i(Lk30/e;Lx2/s;Lay0/a;Ll2/o;I)V
    .locals 50

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v9, p3

    .line 6
    .line 7
    check-cast v9, Ll2/t;

    .line 8
    .line 9
    const v0, -0x752acb05

    .line 10
    .line 11
    .line 12
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int v0, p4, v0

    .line 25
    .line 26
    invoke-virtual {v9, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v2, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v2

    .line 38
    move-object/from16 v2, p2

    .line 39
    .line 40
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    if-eqz v6, :cond_2

    .line 45
    .line 46
    const/16 v6, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v6, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v6

    .line 52
    and-int/lit16 v6, v0, 0x93

    .line 53
    .line 54
    const/16 v7, 0x92

    .line 55
    .line 56
    if-eq v6, v7, :cond_3

    .line 57
    .line 58
    const/4 v6, 0x1

    .line 59
    goto :goto_3

    .line 60
    :cond_3
    const/4 v6, 0x0

    .line 61
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 62
    .line 63
    invoke-virtual {v9, v7, v6}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    if-eqz v6, :cond_27

    .line 68
    .line 69
    iget-boolean v6, v3, Lk30/e;->b:Z

    .line 70
    .line 71
    iget-object v13, v3, Lk30/e;->g:Ljava/util/List;

    .line 72
    .line 73
    if-eqz v6, :cond_4

    .line 74
    .line 75
    const/4 v6, 0x0

    .line 76
    move v15, v6

    .line 77
    goto :goto_4

    .line 78
    :cond_4
    const/high16 v15, 0x3f800000    # 1.0f

    .line 79
    .line 80
    :goto_4
    move-object v6, v13

    .line 81
    check-cast v6, Ljava/lang/Iterable;

    .line 82
    .line 83
    new-instance v7, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 86
    .line 87
    .line 88
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 89
    .line 90
    .line 91
    move-result-object v8

    .line 92
    :cond_5
    :goto_5
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 93
    .line 94
    .line 95
    move-result v10

    .line 96
    if-eqz v10, :cond_6

    .line 97
    .line 98
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v10

    .line 102
    const/16 p3, 0x4

    .line 103
    .line 104
    move-object v1, v10

    .line 105
    check-cast v1, Lk30/d;

    .line 106
    .line 107
    iget-object v1, v1, Lk30/d;->c:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v1, Ljava/util/Collection;

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-nez v1, :cond_5

    .line 116
    .line 117
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_5

    .line 121
    :cond_6
    const/16 p3, 0x4

    .line 122
    .line 123
    new-instance v1, Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 126
    .line 127
    .line 128
    const v8, -0x7f97d7fa

    .line 129
    .line 130
    .line 131
    invoke-virtual {v9, v8}, Ll2/t;->Y(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 135
    .line 136
    .line 137
    move-result-object v7

    .line 138
    :goto_6
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 139
    .line 140
    .line 141
    move-result v8

    .line 142
    const/4 v10, 0x6

    .line 143
    const-wide/16 v16, 0x0

    .line 144
    .line 145
    const/high16 v18, 0x3f800000    # 1.0f

    .line 146
    .line 147
    const/16 v19, 0x1

    .line 148
    .line 149
    const/4 v11, 0x0

    .line 150
    if-eqz v8, :cond_c

    .line 151
    .line 152
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    check-cast v8, Lk30/d;

    .line 157
    .line 158
    const/16 v20, 0x10

    .line 159
    .line 160
    new-instance v5, Llx0/l;

    .line 161
    .line 162
    new-instance v21, Li91/c2;

    .line 163
    .line 164
    iget-object v12, v8, Lk30/d;->a:Ljava/lang/String;

    .line 165
    .line 166
    iget-object v14, v8, Lk30/d;->c:Ljava/lang/Object;

    .line 167
    .line 168
    move/from16 v32, v0

    .line 169
    .line 170
    new-instance v0, Li91/q1;

    .line 171
    .line 172
    iget v8, v8, Lk30/d;->b:I

    .line 173
    .line 174
    invoke-direct {v0, v8, v11, v10}, Li91/q1;-><init>(ILe3/s;I)V

    .line 175
    .line 176
    .line 177
    new-instance v8, Li91/n1;

    .line 178
    .line 179
    move-object v10, v14

    .line 180
    check-cast v10, Ljava/util/Collection;

    .line 181
    .line 182
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 183
    .line 184
    .line 185
    move-result v10

    .line 186
    invoke-static {v10}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v10

    .line 190
    sget-object v11, Li91/e1;->d:Li91/e1;

    .line 191
    .line 192
    invoke-direct {v8, v10}, Li91/n1;-><init>(Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 196
    .line 197
    .line 198
    move-result-object v10

    .line 199
    invoke-virtual {v10}, Lj91/e;->q()J

    .line 200
    .line 201
    .line 202
    move-result-wide v10

    .line 203
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 204
    .line 205
    .line 206
    move-result-object v22

    .line 207
    invoke-virtual/range {v22 .. v22}, Lj91/e;->r()J

    .line 208
    .line 209
    .line 210
    move-result-wide v36

    .line 211
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 212
    .line 213
    .line 214
    move-result-object v22

    .line 215
    invoke-virtual/range {v22 .. v22}, Lj91/e;->s()J

    .line 216
    .line 217
    .line 218
    move-result-wide v22

    .line 219
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 220
    .line 221
    .line 222
    move-result-object v24

    .line 223
    invoke-virtual/range {v24 .. v24}, Lj91/e;->r()J

    .line 224
    .line 225
    .line 226
    move-result-wide v40

    .line 227
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 228
    .line 229
    .line 230
    move-result-object v24

    .line 231
    invoke-virtual/range {v24 .. v24}, Lj91/e;->q()J

    .line 232
    .line 233
    .line 234
    move-result-wide v24

    .line 235
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 236
    .line 237
    .line 238
    move-result-object v26

    .line 239
    invoke-virtual/range {v26 .. v26}, Lj91/e;->r()J

    .line 240
    .line 241
    .line 242
    move-result-wide v44

    .line 243
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 244
    .line 245
    .line 246
    move-result-object v26

    .line 247
    invoke-virtual/range {v26 .. v26}, Lj91/e;->q()J

    .line 248
    .line 249
    .line 250
    move-result-wide v26

    .line 251
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 252
    .line 253
    .line 254
    move-result-object v28

    .line 255
    invoke-virtual/range {v28 .. v28}, Lj91/e;->r()J

    .line 256
    .line 257
    .line 258
    move-result-wide v48

    .line 259
    move-object/from16 v28, v0

    .line 260
    .line 261
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 262
    .line 263
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    check-cast v0, Lj91/e;

    .line 268
    .line 269
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 270
    .line 271
    .line 272
    move-result-wide v29

    .line 273
    const/16 v0, 0xbf

    .line 274
    .line 275
    and-int/lit8 v0, v0, 0x1

    .line 276
    .line 277
    if-eqz v0, :cond_7

    .line 278
    .line 279
    move-wide/from16 v34, v10

    .line 280
    .line 281
    goto :goto_7

    .line 282
    :cond_7
    move-wide/from16 v34, v16

    .line 283
    .line 284
    :goto_7
    const/16 v0, 0xbf

    .line 285
    .line 286
    and-int/lit8 v0, v0, 0x4

    .line 287
    .line 288
    if-eqz v0, :cond_8

    .line 289
    .line 290
    move-wide/from16 v38, v22

    .line 291
    .line 292
    goto :goto_8

    .line 293
    :cond_8
    move-wide/from16 v38, v16

    .line 294
    .line 295
    :goto_8
    const/16 v0, 0xbf

    .line 296
    .line 297
    and-int/lit8 v0, v0, 0x10

    .line 298
    .line 299
    if-eqz v0, :cond_9

    .line 300
    .line 301
    move-wide/from16 v42, v24

    .line 302
    .line 303
    goto :goto_9

    .line 304
    :cond_9
    move-wide/from16 v42, v16

    .line 305
    .line 306
    :goto_9
    const/16 v0, 0xbf

    .line 307
    .line 308
    and-int/lit8 v0, v0, 0x40

    .line 309
    .line 310
    if-eqz v0, :cond_a

    .line 311
    .line 312
    move-wide/from16 v46, v26

    .line 313
    .line 314
    goto :goto_a

    .line 315
    :cond_a
    move-wide/from16 v46, v29

    .line 316
    .line 317
    :goto_a
    new-instance v27, Li91/t1;

    .line 318
    .line 319
    move-object/from16 v33, v27

    .line 320
    .line 321
    invoke-direct/range {v33 .. v49}, Li91/t1;-><init>(JJJJJJJJ)V

    .line 322
    .line 323
    .line 324
    const/16 v30, 0x0

    .line 325
    .line 326
    const/16 v31, 0xed2

    .line 327
    .line 328
    const/16 v23, 0x0

    .line 329
    .line 330
    const/16 v26, 0x0

    .line 331
    .line 332
    move-object/from16 v24, v28

    .line 333
    .line 334
    const/16 v28, 0x0

    .line 335
    .line 336
    const-string v29, "vhr_category_with_warnings"

    .line 337
    .line 338
    move-object/from16 v25, v8

    .line 339
    .line 340
    move-object/from16 v22, v12

    .line 341
    .line 342
    invoke-direct/range {v21 .. v31}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 343
    .line 344
    .line 345
    move-object/from16 v0, v21

    .line 346
    .line 347
    check-cast v14, Ljava/lang/Iterable;

    .line 348
    .line 349
    new-instance v8, Ljava/util/ArrayList;

    .line 350
    .line 351
    const/16 v10, 0xa

    .line 352
    .line 353
    invoke-static {v14, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 354
    .line 355
    .line 356
    move-result v10

    .line 357
    invoke-direct {v8, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 358
    .line 359
    .line 360
    invoke-interface {v14}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 361
    .line 362
    .line 363
    move-result-object v10

    .line 364
    :goto_b
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 365
    .line 366
    .line 367
    move-result v11

    .line 368
    if-eqz v11, :cond_b

    .line 369
    .line 370
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v11

    .line 374
    move-object/from16 v22, v11

    .line 375
    .line 376
    check-cast v22, Ljava/lang/String;

    .line 377
    .line 378
    new-instance v21, Li91/c2;

    .line 379
    .line 380
    const/16 v30, 0x0

    .line 381
    .line 382
    const/16 v31, 0xffe

    .line 383
    .line 384
    const/16 v23, 0x0

    .line 385
    .line 386
    const/16 v24, 0x0

    .line 387
    .line 388
    const/16 v25, 0x0

    .line 389
    .line 390
    const/16 v26, 0x0

    .line 391
    .line 392
    const/16 v27, 0x0

    .line 393
    .line 394
    const/16 v28, 0x0

    .line 395
    .line 396
    const/16 v29, 0x0

    .line 397
    .line 398
    invoke-direct/range {v21 .. v31}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 399
    .line 400
    .line 401
    move-object/from16 v11, v21

    .line 402
    .line 403
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 404
    .line 405
    .line 406
    goto :goto_b

    .line 407
    :cond_b
    invoke-direct {v5, v0, v8}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 411
    .line 412
    .line 413
    move/from16 v0, v32

    .line 414
    .line 415
    goto/16 :goto_6

    .line 416
    .line 417
    :cond_c
    move/from16 v32, v0

    .line 418
    .line 419
    const/4 v0, 0x0

    .line 420
    const/16 v20, 0x10

    .line 421
    .line 422
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 423
    .line 424
    .line 425
    invoke-static {v1}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 426
    .line 427
    .line 428
    move-result-object v0

    .line 429
    new-instance v1, Ljava/util/ArrayList;

    .line 430
    .line 431
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 432
    .line 433
    .line 434
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 435
    .line 436
    .line 437
    move-result-object v5

    .line 438
    :cond_d
    :goto_c
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 439
    .line 440
    .line 441
    move-result v6

    .line 442
    if-eqz v6, :cond_e

    .line 443
    .line 444
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v6

    .line 448
    move-object v7, v6

    .line 449
    check-cast v7, Lk30/d;

    .line 450
    .line 451
    iget-object v7, v7, Lk30/d;->c:Ljava/lang/Object;

    .line 452
    .line 453
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 454
    .line 455
    .line 456
    move-result v7

    .line 457
    if-eqz v7, :cond_d

    .line 458
    .line 459
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 460
    .line 461
    .line 462
    goto :goto_c

    .line 463
    :cond_e
    const v5, 0x63247de8

    .line 464
    .line 465
    .line 466
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 467
    .line 468
    .line 469
    new-instance v12, Ljava/util/ArrayList;

    .line 470
    .line 471
    const/16 v5, 0xa

    .line 472
    .line 473
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 474
    .line 475
    .line 476
    move-result v6

    .line 477
    invoke-direct {v12, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 478
    .line 479
    .line 480
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 481
    .line 482
    .line 483
    move-result-object v1

    .line 484
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 485
    .line 486
    .line 487
    move-result v5

    .line 488
    if-eqz v5, :cond_13

    .line 489
    .line 490
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v5

    .line 494
    check-cast v5, Lk30/d;

    .line 495
    .line 496
    new-instance v21, Li91/c2;

    .line 497
    .line 498
    iget-object v6, v5, Lk30/d;->a:Ljava/lang/String;

    .line 499
    .line 500
    new-instance v7, Li91/q1;

    .line 501
    .line 502
    iget v5, v5, Lk30/d;->b:I

    .line 503
    .line 504
    invoke-direct {v7, v5, v11, v10}, Li91/q1;-><init>(ILe3/s;I)V

    .line 505
    .line 506
    .line 507
    new-instance v5, Li91/p1;

    .line 508
    .line 509
    const v8, 0x7f080321

    .line 510
    .line 511
    .line 512
    invoke-direct {v5, v8}, Li91/p1;-><init>(I)V

    .line 513
    .line 514
    .line 515
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 516
    .line 517
    .line 518
    move-result-object v8

    .line 519
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 520
    .line 521
    .line 522
    move-result-wide v22

    .line 523
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 524
    .line 525
    .line 526
    move-result-object v8

    .line 527
    invoke-virtual {v8}, Lj91/e;->r()J

    .line 528
    .line 529
    .line 530
    move-result-wide v36

    .line 531
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 532
    .line 533
    .line 534
    move-result-object v8

    .line 535
    invoke-virtual {v8}, Lj91/e;->s()J

    .line 536
    .line 537
    .line 538
    move-result-wide v24

    .line 539
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 540
    .line 541
    .line 542
    move-result-object v8

    .line 543
    invoke-virtual {v8}, Lj91/e;->r()J

    .line 544
    .line 545
    .line 546
    move-result-wide v40

    .line 547
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 548
    .line 549
    .line 550
    move-result-object v8

    .line 551
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 552
    .line 553
    .line 554
    move-result-wide v26

    .line 555
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 556
    .line 557
    .line 558
    move-result-object v8

    .line 559
    invoke-virtual {v8}, Lj91/e;->r()J

    .line 560
    .line 561
    .line 562
    move-result-wide v44

    .line 563
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 564
    .line 565
    .line 566
    move-result-object v8

    .line 567
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 568
    .line 569
    .line 570
    move-result-wide v28

    .line 571
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 572
    .line 573
    .line 574
    move-result-object v8

    .line 575
    invoke-virtual {v8}, Lj91/e;->r()J

    .line 576
    .line 577
    .line 578
    move-result-wide v48

    .line 579
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 580
    .line 581
    invoke-virtual {v9, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 582
    .line 583
    .line 584
    move-result-object v14

    .line 585
    check-cast v14, Lj91/e;

    .line 586
    .line 587
    invoke-virtual {v14}, Lj91/e;->q()J

    .line 588
    .line 589
    .line 590
    move-result-wide v30

    .line 591
    invoke-virtual {v9, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    move-result-object v8

    .line 595
    check-cast v8, Lj91/e;

    .line 596
    .line 597
    invoke-virtual {v8}, Lj91/e;->e()J

    .line 598
    .line 599
    .line 600
    move-result-wide v33

    .line 601
    const/16 v8, 0xaf

    .line 602
    .line 603
    and-int/lit8 v8, v8, 0x1

    .line 604
    .line 605
    if-eqz v8, :cond_f

    .line 606
    .line 607
    goto :goto_e

    .line 608
    :cond_f
    move-wide/from16 v22, v16

    .line 609
    .line 610
    :goto_e
    const/16 v8, 0xaf

    .line 611
    .line 612
    and-int/lit8 v14, v8, 0x4

    .line 613
    .line 614
    if-eqz v14, :cond_10

    .line 615
    .line 616
    move-wide/from16 v38, v24

    .line 617
    .line 618
    goto :goto_f

    .line 619
    :cond_10
    move-wide/from16 v38, v16

    .line 620
    .line 621
    :goto_f
    and-int/lit8 v14, v8, 0x10

    .line 622
    .line 623
    if-eqz v14, :cond_11

    .line 624
    .line 625
    move-wide/from16 v42, v26

    .line 626
    .line 627
    goto :goto_10

    .line 628
    :cond_11
    move-wide/from16 v42, v33

    .line 629
    .line 630
    :goto_10
    and-int/lit8 v8, v8, 0x40

    .line 631
    .line 632
    if-eqz v8, :cond_12

    .line 633
    .line 634
    move-wide/from16 v46, v28

    .line 635
    .line 636
    goto :goto_11

    .line 637
    :cond_12
    move-wide/from16 v46, v30

    .line 638
    .line 639
    :goto_11
    new-instance v27, Li91/t1;

    .line 640
    .line 641
    move-wide/from16 v34, v22

    .line 642
    .line 643
    move-object/from16 v33, v27

    .line 644
    .line 645
    invoke-direct/range {v33 .. v49}, Li91/t1;-><init>(JJJJJJJJ)V

    .line 646
    .line 647
    .line 648
    const/16 v30, 0x0

    .line 649
    .line 650
    const/16 v31, 0xed2

    .line 651
    .line 652
    const/16 v23, 0x0

    .line 653
    .line 654
    const/16 v26, 0x0

    .line 655
    .line 656
    const/16 v28, 0x0

    .line 657
    .line 658
    const-string v29, "vhr_category_without_warnings"

    .line 659
    .line 660
    move-object/from16 v25, v5

    .line 661
    .line 662
    move-object/from16 v22, v6

    .line 663
    .line 664
    move-object/from16 v24, v7

    .line 665
    .line 666
    invoke-direct/range {v21 .. v31}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 667
    .line 668
    .line 669
    move-object/from16 v5, v21

    .line 670
    .line 671
    invoke-virtual {v12, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 672
    .line 673
    .line 674
    goto/16 :goto_d

    .line 675
    .line 676
    :cond_13
    const/4 v5, 0x0

    .line 677
    invoke-virtual {v9, v5}, Ll2/t;->q(Z)V

    .line 678
    .line 679
    .line 680
    move/from16 v1, v19

    .line 681
    .line 682
    invoke-static {v5, v1, v9}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 683
    .line 684
    .line 685
    move-result-object v6

    .line 686
    const/16 v1, 0xe

    .line 687
    .line 688
    invoke-static {v4, v6, v1}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 689
    .line 690
    .line 691
    move-result-object v6

    .line 692
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 693
    .line 694
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 695
    .line 696
    invoke-static {v7, v8, v9, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 697
    .line 698
    .line 699
    move-result-object v7

    .line 700
    move/from16 p3, v1

    .line 701
    .line 702
    iget-wide v1, v9, Ll2/t;->T:J

    .line 703
    .line 704
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 705
    .line 706
    .line 707
    move-result v1

    .line 708
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 709
    .line 710
    .line 711
    move-result-object v2

    .line 712
    invoke-static {v9, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 713
    .line 714
    .line 715
    move-result-object v5

    .line 716
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 717
    .line 718
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 719
    .line 720
    .line 721
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 722
    .line 723
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 724
    .line 725
    .line 726
    iget-boolean v8, v9, Ll2/t;->S:Z

    .line 727
    .line 728
    if-eqz v8, :cond_14

    .line 729
    .line 730
    invoke-virtual {v9, v6}, Ll2/t;->l(Lay0/a;)V

    .line 731
    .line 732
    .line 733
    goto :goto_12

    .line 734
    :cond_14
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 735
    .line 736
    .line 737
    :goto_12
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 738
    .line 739
    invoke-static {v6, v7, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 740
    .line 741
    .line 742
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 743
    .line 744
    invoke-static {v6, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 745
    .line 746
    .line 747
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 748
    .line 749
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 750
    .line 751
    if-nez v6, :cond_15

    .line 752
    .line 753
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 754
    .line 755
    .line 756
    move-result-object v6

    .line 757
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 758
    .line 759
    .line 760
    move-result-object v7

    .line 761
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 762
    .line 763
    .line 764
    move-result v6

    .line 765
    if-nez v6, :cond_16

    .line 766
    .line 767
    :cond_15
    invoke-static {v1, v9, v1, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 768
    .line 769
    .line 770
    :cond_16
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 771
    .line 772
    invoke-static {v1, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 773
    .line 774
    .line 775
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 776
    .line 777
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 778
    .line 779
    .line 780
    move-result-object v2

    .line 781
    check-cast v2, Lj91/c;

    .line 782
    .line 783
    iget v2, v2, Lj91/c;->e:F

    .line 784
    .line 785
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 786
    .line 787
    invoke-static {v5, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 788
    .line 789
    .line 790
    move-result-object v2

    .line 791
    invoke-static {v9, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 792
    .line 793
    .line 794
    and-int/lit8 v2, v32, 0xe

    .line 795
    .line 796
    invoke-static {v3, v9, v2}, Llp/ne;->g(Lk30/e;Ll2/o;I)V

    .line 797
    .line 798
    .line 799
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 800
    .line 801
    .line 802
    move-result-object v1

    .line 803
    check-cast v1, Lj91/c;

    .line 804
    .line 805
    iget v1, v1, Lj91/c;->f:F

    .line 806
    .line 807
    invoke-static {v5, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 808
    .line 809
    .line 810
    move-result-object v1

    .line 811
    invoke-static {v9, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 812
    .line 813
    .line 814
    const v1, 0x46d4dcd9

    .line 815
    .line 816
    .line 817
    invoke-virtual {v9, v1}, Ll2/t;->Y(I)V

    .line 818
    .line 819
    .line 820
    move-object v1, v0

    .line 821
    check-cast v1, Ljava/lang/Iterable;

    .line 822
    .line 823
    new-instance v2, Ljava/util/ArrayList;

    .line 824
    .line 825
    const/16 v5, 0xa

    .line 826
    .line 827
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 828
    .line 829
    .line 830
    move-result v6

    .line 831
    invoke-direct {v2, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 832
    .line 833
    .line 834
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 835
    .line 836
    .line 837
    move-result-object v1

    .line 838
    const/4 v6, 0x0

    .line 839
    :goto_13
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 840
    .line 841
    .line 842
    move-result v5

    .line 843
    sget-object v14, Llx0/b0;->a:Llx0/b0;

    .line 844
    .line 845
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 846
    .line 847
    if-eqz v5, :cond_1d

    .line 848
    .line 849
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 850
    .line 851
    .line 852
    move-result-object v5

    .line 853
    add-int/lit8 v16, v6, 0x1

    .line 854
    .line 855
    if-ltz v6, :cond_1c

    .line 856
    .line 857
    check-cast v5, Llx0/l;

    .line 858
    .line 859
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 860
    .line 861
    .line 862
    move-result-object v8

    .line 863
    if-ne v8, v7, :cond_17

    .line 864
    .line 865
    invoke-static {v15}, Lc1/d;->a(F)Lc1/c;

    .line 866
    .line 867
    .line 868
    move-result-object v8

    .line 869
    invoke-virtual {v9, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 870
    .line 871
    .line 872
    :cond_17
    check-cast v8, Lc1/c;

    .line 873
    .line 874
    invoke-static {v0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 875
    .line 876
    .line 877
    move-result v10

    .line 878
    if-ne v6, v10, :cond_18

    .line 879
    .line 880
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 881
    .line 882
    .line 883
    move-result v10

    .line 884
    invoke-interface {v13}, Ljava/util/List;->size()I

    .line 885
    .line 886
    .line 887
    move-result v11

    .line 888
    if-ne v10, v11, :cond_18

    .line 889
    .line 890
    const/4 v10, 0x1

    .line 891
    goto :goto_14

    .line 892
    :cond_18
    const/4 v10, 0x0

    .line 893
    :goto_14
    invoke-virtual {v8}, Lc1/c;->d()Ljava/lang/Object;

    .line 894
    .line 895
    .line 896
    move-result-object v11

    .line 897
    check-cast v11, Ljava/lang/Number;

    .line 898
    .line 899
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 900
    .line 901
    .line 902
    move-result v11

    .line 903
    cmpg-float v11, v11, v18

    .line 904
    .line 905
    if-nez v11, :cond_19

    .line 906
    .line 907
    if-eqz v10, :cond_19

    .line 908
    .line 909
    invoke-interface/range {p2 .. p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 910
    .line 911
    .line 912
    :cond_19
    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 913
    .line 914
    invoke-virtual {v9, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 915
    .line 916
    .line 917
    move-result v11

    .line 918
    invoke-virtual {v9, v6}, Ll2/t;->e(I)Z

    .line 919
    .line 920
    .line 921
    move-result v17

    .line 922
    or-int v11, v11, v17

    .line 923
    .line 924
    move-object/from16 v17, v0

    .line 925
    .line 926
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 927
    .line 928
    .line 929
    move-result-object v0

    .line 930
    if-nez v11, :cond_1a

    .line 931
    .line 932
    if-ne v0, v7, :cond_1b

    .line 933
    .line 934
    :cond_1a
    new-instance v0, Li50/r;

    .line 935
    .line 936
    const/4 v7, 0x0

    .line 937
    const/4 v11, 0x1

    .line 938
    invoke-direct {v0, v6, v11, v8, v7}, Li50/r;-><init>(IILc1/c;Lkotlin/coroutines/Continuation;)V

    .line 939
    .line 940
    .line 941
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 942
    .line 943
    .line 944
    :cond_1b
    check-cast v0, Lay0/n;

    .line 945
    .line 946
    invoke-static {v0, v10, v9}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 947
    .line 948
    .line 949
    invoke-virtual {v8}, Lc1/c;->d()Ljava/lang/Object;

    .line 950
    .line 951
    .line 952
    move-result-object v0

    .line 953
    check-cast v0, Ljava/lang/Number;

    .line 954
    .line 955
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 956
    .line 957
    .line 958
    move-result v8

    .line 959
    iget-object v0, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 960
    .line 961
    check-cast v0, Li91/c2;

    .line 962
    .line 963
    iget-object v5, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 964
    .line 965
    move-object v7, v5

    .line 966
    check-cast v7, Ljava/util/List;

    .line 967
    .line 968
    const/4 v10, 0x0

    .line 969
    move-object v5, v0

    .line 970
    invoke-static/range {v5 .. v10}, Llp/ne;->a(Li91/c2;ILjava/util/List;FLl2/o;I)V

    .line 971
    .line 972
    .line 973
    invoke-virtual {v2, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 974
    .line 975
    .line 976
    move/from16 v6, v16

    .line 977
    .line 978
    move-object/from16 v0, v17

    .line 979
    .line 980
    const/4 v11, 0x0

    .line 981
    goto/16 :goto_13

    .line 982
    .line 983
    :cond_1c
    invoke-static {}, Ljp/k1;->r()V

    .line 984
    .line 985
    .line 986
    const/4 v7, 0x0

    .line 987
    throw v7

    .line 988
    :cond_1d
    move-object/from16 v17, v0

    .line 989
    .line 990
    const/4 v0, 0x0

    .line 991
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 992
    .line 993
    .line 994
    invoke-interface/range {v17 .. v17}, Ljava/util/List;->size()I

    .line 995
    .line 996
    .line 997
    move-result v0

    .line 998
    mul-int/lit16 v0, v0, 0x28a

    .line 999
    .line 1000
    const v1, 0x46d57c3c

    .line 1001
    .line 1002
    .line 1003
    invoke-virtual {v9, v1}, Ll2/t;->Y(I)V

    .line 1004
    .line 1005
    .line 1006
    new-instance v1, Ljava/util/ArrayList;

    .line 1007
    .line 1008
    const/16 v5, 0xa

    .line 1009
    .line 1010
    invoke-static {v12, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1011
    .line 1012
    .line 1013
    move-result v2

    .line 1014
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1015
    .line 1016
    .line 1017
    invoke-virtual {v12}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1018
    .line 1019
    .line 1020
    move-result-object v2

    .line 1021
    const/4 v5, 0x0

    .line 1022
    :goto_15
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1023
    .line 1024
    .line 1025
    move-result v6

    .line 1026
    if-eqz v6, :cond_26

    .line 1027
    .line 1028
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v6

    .line 1032
    add-int/lit8 v11, v5, 0x1

    .line 1033
    .line 1034
    if-ltz v5, :cond_25

    .line 1035
    .line 1036
    check-cast v6, Li91/c2;

    .line 1037
    .line 1038
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v8

    .line 1042
    if-ne v8, v7, :cond_1e

    .line 1043
    .line 1044
    invoke-static {v15}, Lc1/d;->a(F)Lc1/c;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v8

    .line 1048
    invoke-virtual {v9, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1049
    .line 1050
    .line 1051
    :cond_1e
    check-cast v8, Lc1/c;

    .line 1052
    .line 1053
    invoke-static {v12}, Ljp/k1;->h(Ljava/util/List;)I

    .line 1054
    .line 1055
    .line 1056
    move-result v10

    .line 1057
    if-ne v5, v10, :cond_1f

    .line 1058
    .line 1059
    const/4 v10, 0x1

    .line 1060
    goto :goto_16

    .line 1061
    :cond_1f
    const/4 v10, 0x0

    .line 1062
    :goto_16
    invoke-virtual {v8}, Lc1/c;->d()Ljava/lang/Object;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v13

    .line 1066
    check-cast v13, Ljava/lang/Number;

    .line 1067
    .line 1068
    invoke-virtual {v13}, Ljava/lang/Number;->floatValue()F

    .line 1069
    .line 1070
    .line 1071
    move-result v13

    .line 1072
    cmpg-float v13, v13, v18

    .line 1073
    .line 1074
    if-nez v13, :cond_20

    .line 1075
    .line 1076
    if-eqz v10, :cond_20

    .line 1077
    .line 1078
    invoke-interface/range {p2 .. p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1079
    .line 1080
    .line 1081
    :cond_20
    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1082
    .line 1083
    invoke-virtual {v9, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1084
    .line 1085
    .line 1086
    move-result v13

    .line 1087
    invoke-virtual {v9, v0}, Ll2/t;->e(I)Z

    .line 1088
    .line 1089
    .line 1090
    move-result v16

    .line 1091
    or-int v13, v13, v16

    .line 1092
    .line 1093
    invoke-virtual {v9, v5}, Ll2/t;->e(I)Z

    .line 1094
    .line 1095
    .line 1096
    move-result v16

    .line 1097
    or-int v13, v13, v16

    .line 1098
    .line 1099
    move-object/from16 v16, v2

    .line 1100
    .line 1101
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v2

    .line 1105
    if-nez v13, :cond_21

    .line 1106
    .line 1107
    if-ne v2, v7, :cond_22

    .line 1108
    .line 1109
    :cond_21
    new-instance v2, La7/y0;

    .line 1110
    .line 1111
    const/4 v13, 0x0

    .line 1112
    invoke-direct {v2, v0, v5, v8, v13}, La7/y0;-><init>(IILc1/c;Lkotlin/coroutines/Continuation;)V

    .line 1113
    .line 1114
    .line 1115
    invoke-virtual {v9, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1116
    .line 1117
    .line 1118
    :cond_22
    check-cast v2, Lay0/n;

    .line 1119
    .line 1120
    invoke-static {v2, v10, v9}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1121
    .line 1122
    .line 1123
    invoke-interface/range {v17 .. v17}, Ljava/util/List;->isEmpty()Z

    .line 1124
    .line 1125
    .line 1126
    move-result v2

    .line 1127
    if-eqz v2, :cond_23

    .line 1128
    .line 1129
    if-nez v5, :cond_23

    .line 1130
    .line 1131
    move-object v2, v7

    .line 1132
    const/4 v7, 0x1

    .line 1133
    goto :goto_17

    .line 1134
    :cond_23
    move-object v2, v7

    .line 1135
    const/4 v7, 0x0

    .line 1136
    :goto_17
    invoke-virtual {v8}, Lc1/c;->d()Ljava/lang/Object;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v8

    .line 1140
    check-cast v8, Ljava/lang/Number;

    .line 1141
    .line 1142
    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    .line 1143
    .line 1144
    .line 1145
    move-result v8

    .line 1146
    invoke-static {v12}, Ljp/k1;->h(Ljava/util/List;)I

    .line 1147
    .line 1148
    .line 1149
    move-result v10

    .line 1150
    if-ne v5, v10, :cond_24

    .line 1151
    .line 1152
    move-object v5, v6

    .line 1153
    move v6, v8

    .line 1154
    const/4 v8, 0x1

    .line 1155
    goto :goto_18

    .line 1156
    :cond_24
    move-object v5, v6

    .line 1157
    move v6, v8

    .line 1158
    const/4 v8, 0x0

    .line 1159
    :goto_18
    const/4 v10, 0x0

    .line 1160
    invoke-static/range {v5 .. v10}, Llp/ne;->d(Li91/c2;FZZLl2/o;I)V

    .line 1161
    .line 1162
    .line 1163
    invoke-virtual {v1, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1164
    .line 1165
    .line 1166
    move-object v7, v2

    .line 1167
    move v5, v11

    .line 1168
    move-object/from16 v2, v16

    .line 1169
    .line 1170
    goto/16 :goto_15

    .line 1171
    .line 1172
    :cond_25
    invoke-static {}, Ljp/k1;->r()V

    .line 1173
    .line 1174
    .line 1175
    const/4 v7, 0x0

    .line 1176
    throw v7

    .line 1177
    :cond_26
    const/4 v0, 0x0

    .line 1178
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 1179
    .line 1180
    .line 1181
    const/4 v11, 0x1

    .line 1182
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 1183
    .line 1184
    .line 1185
    goto :goto_19

    .line 1186
    :cond_27
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 1187
    .line 1188
    .line 1189
    :goto_19
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v6

    .line 1193
    if-eqz v6, :cond_28

    .line 1194
    .line 1195
    new-instance v0, Li91/k3;

    .line 1196
    .line 1197
    const/16 v2, 0xa

    .line 1198
    .line 1199
    move-object/from16 v5, p2

    .line 1200
    .line 1201
    move/from16 v1, p4

    .line 1202
    .line 1203
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1204
    .line 1205
    .line 1206
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 1207
    .line 1208
    :cond_28
    return-void
.end method

.method public static final j(ILi91/c2;Ll2/o;I)V
    .locals 28

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x5a41879d

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3, v0}, Ll2/t;->e(I)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    const/4 v5, 0x2

    .line 22
    if-eqz v4, :cond_0

    .line 23
    .line 24
    const/4 v4, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v4, v5

    .line 27
    :goto_0
    or-int/2addr v4, v2

    .line 28
    invoke-virtual {v3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    if-eqz v6, :cond_1

    .line 33
    .line 34
    const/16 v6, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v6, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v4, v6

    .line 40
    and-int/lit8 v6, v4, 0x13

    .line 41
    .line 42
    const/16 v7, 0x12

    .line 43
    .line 44
    const/4 v8, 0x1

    .line 45
    const/4 v9, 0x0

    .line 46
    if-eq v6, v7, :cond_2

    .line 47
    .line 48
    move v6, v8

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v6, v9

    .line 51
    :goto_2
    and-int/2addr v4, v8

    .line 52
    invoke-virtual {v3, v4, v6}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_7

    .line 57
    .line 58
    const-string v4, "vhr_warning_item"

    .line 59
    .line 60
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 61
    .line 62
    invoke-static {v6, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 67
    .line 68
    sget-object v10, Lx2/c;->p:Lx2/h;

    .line 69
    .line 70
    invoke-static {v7, v10, v3, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    iget-wide v10, v3, Ll2/t;->T:J

    .line 75
    .line 76
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 77
    .line 78
    .line 79
    move-result v10

    .line 80
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 81
    .line 82
    .line 83
    move-result-object v11

    .line 84
    invoke-static {v3, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 89
    .line 90
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 94
    .line 95
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 96
    .line 97
    .line 98
    iget-boolean v13, v3, Ll2/t;->S:Z

    .line 99
    .line 100
    if-eqz v13, :cond_3

    .line 101
    .line 102
    invoke-virtual {v3, v12}, Ll2/t;->l(Lay0/a;)V

    .line 103
    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_3
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 107
    .line 108
    .line 109
    :goto_3
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 110
    .line 111
    invoke-static {v12, v7, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 112
    .line 113
    .line 114
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 115
    .line 116
    invoke-static {v7, v11, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 120
    .line 121
    iget-boolean v11, v3, Ll2/t;->S:Z

    .line 122
    .line 123
    if-nez v11, :cond_4

    .line 124
    .line 125
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v11

    .line 129
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v12

    .line 133
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v11

    .line 137
    if-nez v11, :cond_5

    .line 138
    .line 139
    :cond_4
    invoke-static {v10, v3, v10, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 140
    .line 141
    .line 142
    :cond_5
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 143
    .line 144
    invoke-static {v7, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 145
    .line 146
    .line 147
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 148
    .line 149
    if-lez v0, :cond_6

    .line 150
    .line 151
    const v7, 0x6f007eb9

    .line 152
    .line 153
    .line 154
    invoke-virtual {v3, v7}, Ll2/t;->Y(I)V

    .line 155
    .line 156
    .line 157
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 158
    .line 159
    invoke-virtual {v3, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v7

    .line 163
    check-cast v7, Lj91/e;

    .line 164
    .line 165
    invoke-virtual {v7}, Lj91/e;->c()J

    .line 166
    .line 167
    .line 168
    move-result-wide v10

    .line 169
    invoke-static {v6, v10, v11, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 170
    .line 171
    .line 172
    move-result-object v7

    .line 173
    sget-object v10, Lj91/a;->a:Ll2/u2;

    .line 174
    .line 175
    invoke-virtual {v3, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v10

    .line 179
    check-cast v10, Lj91/c;

    .line 180
    .line 181
    iget v10, v10, Lj91/c;->k:F

    .line 182
    .line 183
    const/4 v11, 0x0

    .line 184
    invoke-static {v7, v10, v11, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    invoke-static {v9, v9, v3, v5}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 189
    .line 190
    .line 191
    :goto_4
    invoke-virtual {v3, v9}, Ll2/t;->q(Z)V

    .line 192
    .line 193
    .line 194
    goto :goto_5

    .line 195
    :cond_6
    const v5, 0x6e4df595

    .line 196
    .line 197
    .line 198
    invoke-virtual {v3, v5}, Ll2/t;->Y(I)V

    .line 199
    .line 200
    .line 201
    goto :goto_4

    .line 202
    :goto_5
    iget-object v5, v1, Li91/c2;->a:Ljava/lang/String;

    .line 203
    .line 204
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 205
    .line 206
    invoke-virtual {v3, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v7

    .line 210
    check-cast v7, Lj91/f;

    .line 211
    .line 212
    invoke-virtual {v7}, Lj91/f;->a()Lg4/p0;

    .line 213
    .line 214
    .line 215
    move-result-object v7

    .line 216
    sget-object v9, Lj91/h;->a:Ll2/u2;

    .line 217
    .line 218
    invoke-virtual {v3, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v10

    .line 222
    check-cast v10, Lj91/e;

    .line 223
    .line 224
    invoke-virtual {v10}, Lj91/e;->s()J

    .line 225
    .line 226
    .line 227
    move-result-wide v10

    .line 228
    const/high16 v12, 0x3f800000    # 1.0f

    .line 229
    .line 230
    invoke-static {v6, v12}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 231
    .line 232
    .line 233
    move-result-object v6

    .line 234
    invoke-virtual {v3, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v9

    .line 238
    check-cast v9, Lj91/e;

    .line 239
    .line 240
    invoke-virtual {v9}, Lj91/e;->c()J

    .line 241
    .line 242
    .line 243
    move-result-wide v12

    .line 244
    invoke-static {v6, v12, v13, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 245
    .line 246
    .line 247
    move-result-object v4

    .line 248
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 249
    .line 250
    invoke-virtual {v3, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v9

    .line 254
    check-cast v9, Lj91/c;

    .line 255
    .line 256
    iget v9, v9, Lj91/c;->k:F

    .line 257
    .line 258
    invoke-virtual {v3, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v6

    .line 262
    check-cast v6, Lj91/c;

    .line 263
    .line 264
    iget v6, v6, Lj91/c;->d:F

    .line 265
    .line 266
    invoke-static {v4, v9, v6}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    const-string v6, "vhr_warning_item_title"

    .line 271
    .line 272
    invoke-static {v4, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 273
    .line 274
    .line 275
    move-result-object v4

    .line 276
    const/16 v23, 0x0

    .line 277
    .line 278
    const v24, 0xfff0

    .line 279
    .line 280
    .line 281
    move v6, v8

    .line 282
    const-wide/16 v8, 0x0

    .line 283
    .line 284
    move-object/from16 v21, v3

    .line 285
    .line 286
    move-object v3, v5

    .line 287
    move-object v5, v4

    .line 288
    move-object v4, v7

    .line 289
    move-wide/from16 v26, v10

    .line 290
    .line 291
    move v11, v6

    .line 292
    move-wide/from16 v6, v26

    .line 293
    .line 294
    const/4 v10, 0x0

    .line 295
    move v13, v11

    .line 296
    const-wide/16 v11, 0x0

    .line 297
    .line 298
    move v14, v13

    .line 299
    const/4 v13, 0x0

    .line 300
    move v15, v14

    .line 301
    const/4 v14, 0x0

    .line 302
    move/from16 v17, v15

    .line 303
    .line 304
    const-wide/16 v15, 0x0

    .line 305
    .line 306
    move/from16 v18, v17

    .line 307
    .line 308
    const/16 v17, 0x0

    .line 309
    .line 310
    move/from16 v19, v18

    .line 311
    .line 312
    const/16 v18, 0x0

    .line 313
    .line 314
    move/from16 v20, v19

    .line 315
    .line 316
    const/16 v19, 0x0

    .line 317
    .line 318
    move/from16 v22, v20

    .line 319
    .line 320
    const/16 v20, 0x0

    .line 321
    .line 322
    move/from16 v25, v22

    .line 323
    .line 324
    const/16 v22, 0x0

    .line 325
    .line 326
    move/from16 v0, v25

    .line 327
    .line 328
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 329
    .line 330
    .line 331
    move-object/from16 v3, v21

    .line 332
    .line 333
    invoke-virtual {v3, v0}, Ll2/t;->q(Z)V

    .line 334
    .line 335
    .line 336
    goto :goto_6

    .line 337
    :cond_7
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 338
    .line 339
    .line 340
    :goto_6
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 341
    .line 342
    .line 343
    move-result-object v0

    .line 344
    if-eqz v0, :cond_8

    .line 345
    .line 346
    new-instance v3, Ld90/h;

    .line 347
    .line 348
    const/4 v4, 0x7

    .line 349
    move/from16 v5, p0

    .line 350
    .line 351
    invoke-direct {v3, v5, v1, v2, v4}, Ld90/h;-><init>(ILjava/lang/Object;II)V

    .line 352
    .line 353
    .line 354
    iput-object v3, v0, Ll2/u1;->d:Lay0/n;

    .line 355
    .line 356
    :cond_8
    return-void
.end method
