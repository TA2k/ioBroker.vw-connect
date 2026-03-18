.class public abstract Lv3/p0;
.super Lt3/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/a1;
.implements Lt3/s0;


# instance fields
.field public i:Lv3/m0;

.field public j:Lay0/k;

.field public k:Lv3/s1;

.field public l:Z

.field public m:Z

.field public n:Z

.field public final o:Lt3/n0;

.field public p:Lca/j;

.field public q:Landroidx/collection/q0;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Lt3/e1;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lt3/n0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, v1}, Lt3/n0;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lv3/p0;->o:Lt3/n0;

    .line 11
    .line 12
    return-void
.end method

.method public static R0(Lv3/f1;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/f1;->s:Lv3/f1;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, v0, Lv3/f1;->r:Lv3/h0;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 18
    .line 19
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 20
    .line 21
    iget-object p0, p0, Lv3/y0;->B:Lv3/i0;

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/i0;->f()V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 28
    .line 29
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 30
    .line 31
    invoke-virtual {p0}, Lv3/y0;->f()Lv3/a;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    if-eqz p0, :cond_2

    .line 36
    .line 37
    check-cast p0, Lv3/y0;

    .line 38
    .line 39
    iget-object p0, p0, Lv3/y0;->B:Lv3/i0;

    .line 40
    .line 41
    if-eqz p0, :cond_2

    .line 42
    .line 43
    invoke-virtual {p0}, Lv3/i0;->f()V

    .line 44
    .line 45
    .line 46
    :cond_2
    return-void
.end method


# virtual methods
.method public final B0(Lv3/h0;Lt3/q;)V
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v0, Lv3/p0;->q:Landroidx/collection/q0;

    .line 6
    .line 7
    const/4 v7, 0x7

    .line 8
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    const/16 v10, 0x8

    .line 14
    .line 15
    if-eqz v2, :cond_a

    .line 16
    .line 17
    iget-object v12, v2, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v2, v2, Landroidx/collection/q0;->a:[J

    .line 20
    .line 21
    array-length v13, v2

    .line 22
    add-int/lit8 v13, v13, -0x2

    .line 23
    .line 24
    if-ltz v13, :cond_a

    .line 25
    .line 26
    const/4 v14, 0x0

    .line 27
    const-wide/16 v15, 0x80

    .line 28
    .line 29
    :goto_0
    aget-wide v3, v2, v14

    .line 30
    .line 31
    const-wide/16 v17, 0xff

    .line 32
    .line 33
    not-long v5, v3

    .line 34
    shl-long/2addr v5, v7

    .line 35
    and-long/2addr v5, v3

    .line 36
    and-long/2addr v5, v8

    .line 37
    cmp-long v5, v5, v8

    .line 38
    .line 39
    if-eqz v5, :cond_9

    .line 40
    .line 41
    sub-int v5, v14, v13

    .line 42
    .line 43
    not-int v5, v5

    .line 44
    ushr-int/lit8 v5, v5, 0x1f

    .line 45
    .line 46
    rsub-int/lit8 v5, v5, 0x8

    .line 47
    .line 48
    const/4 v6, 0x0

    .line 49
    :goto_1
    if-ge v6, v5, :cond_8

    .line 50
    .line 51
    and-long v19, v3, v17

    .line 52
    .line 53
    cmp-long v19, v19, v15

    .line 54
    .line 55
    if-gez v19, :cond_7

    .line 56
    .line 57
    shl-int/lit8 v19, v14, 0x3

    .line 58
    .line 59
    add-int v19, v19, v6

    .line 60
    .line 61
    aget-object v19, v12, v19

    .line 62
    .line 63
    move/from16 v20, v7

    .line 64
    .line 65
    move-object/from16 v7, v19

    .line 66
    .line 67
    check-cast v7, Landroidx/collection/r0;

    .line 68
    .line 69
    move-wide/from16 v21, v8

    .line 70
    .line 71
    iget-object v8, v7, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 72
    .line 73
    iget-object v9, v7, Landroidx/collection/r0;->a:[J

    .line 74
    .line 75
    array-length v11, v9

    .line 76
    add-int/lit8 v11, v11, -0x2

    .line 77
    .line 78
    if-ltz v11, :cond_5

    .line 79
    .line 80
    move-wide/from16 v23, v15

    .line 81
    .line 82
    const/4 v15, 0x0

    .line 83
    move/from16 v16, v10

    .line 84
    .line 85
    :goto_2
    move/from16 v25, v11

    .line 86
    .line 87
    aget-wide v10, v9, v15

    .line 88
    .line 89
    move-object/from16 v26, v2

    .line 90
    .line 91
    move-wide/from16 v27, v3

    .line 92
    .line 93
    not-long v2, v10

    .line 94
    shl-long v2, v2, v20

    .line 95
    .line 96
    and-long/2addr v2, v10

    .line 97
    and-long v2, v2, v21

    .line 98
    .line 99
    cmp-long v2, v2, v21

    .line 100
    .line 101
    if-eqz v2, :cond_4

    .line 102
    .line 103
    sub-int v2, v15, v25

    .line 104
    .line 105
    not-int v2, v2

    .line 106
    ushr-int/lit8 v2, v2, 0x1f

    .line 107
    .line 108
    rsub-int/lit8 v2, v2, 0x8

    .line 109
    .line 110
    const/4 v3, 0x0

    .line 111
    :goto_3
    if-ge v3, v2, :cond_3

    .line 112
    .line 113
    and-long v29, v10, v17

    .line 114
    .line 115
    cmp-long v4, v29, v23

    .line 116
    .line 117
    if-gez v4, :cond_2

    .line 118
    .line 119
    shl-int/lit8 v4, v15, 0x3

    .line 120
    .line 121
    add-int/2addr v4, v3

    .line 122
    aget-object v29, v8, v4

    .line 123
    .line 124
    check-cast v29, Lv3/e2;

    .line 125
    .line 126
    invoke-virtual/range {v29 .. v29}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v29

    .line 130
    check-cast v29, Lv3/h0;

    .line 131
    .line 132
    move/from16 v30, v3

    .line 133
    .line 134
    if-eqz v29, :cond_0

    .line 135
    .line 136
    invoke-virtual/range {v29 .. v29}, Lv3/h0;->I()Z

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    move/from16 v29, v6

    .line 141
    .line 142
    const/4 v6, 0x1

    .line 143
    if-ne v3, v6, :cond_1

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_0
    move/from16 v29, v6

    .line 147
    .line 148
    :cond_1
    invoke-virtual {v7, v4}, Landroidx/collection/r0;->m(I)V

    .line 149
    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_2
    move/from16 v30, v3

    .line 153
    .line 154
    move/from16 v29, v6

    .line 155
    .line 156
    :goto_4
    shr-long v10, v10, v16

    .line 157
    .line 158
    add-int/lit8 v3, v30, 0x1

    .line 159
    .line 160
    move/from16 v6, v29

    .line 161
    .line 162
    goto :goto_3

    .line 163
    :cond_3
    move/from16 v29, v6

    .line 164
    .line 165
    move/from16 v3, v16

    .line 166
    .line 167
    if-ne v2, v3, :cond_6

    .line 168
    .line 169
    :goto_5
    move/from16 v11, v25

    .line 170
    .line 171
    goto :goto_6

    .line 172
    :cond_4
    move/from16 v29, v6

    .line 173
    .line 174
    goto :goto_5

    .line 175
    :goto_6
    if-eq v15, v11, :cond_6

    .line 176
    .line 177
    add-int/lit8 v15, v15, 0x1

    .line 178
    .line 179
    move-object/from16 v2, v26

    .line 180
    .line 181
    move-wide/from16 v3, v27

    .line 182
    .line 183
    move/from16 v6, v29

    .line 184
    .line 185
    const/16 v16, 0x8

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_5
    move-object/from16 v26, v2

    .line 189
    .line 190
    move-wide/from16 v27, v3

    .line 191
    .line 192
    move/from16 v29, v6

    .line 193
    .line 194
    move-wide/from16 v23, v15

    .line 195
    .line 196
    :cond_6
    const/16 v3, 0x8

    .line 197
    .line 198
    goto :goto_7

    .line 199
    :cond_7
    move-object/from16 v26, v2

    .line 200
    .line 201
    move-wide/from16 v27, v3

    .line 202
    .line 203
    move/from16 v29, v6

    .line 204
    .line 205
    move/from16 v20, v7

    .line 206
    .line 207
    move-wide/from16 v21, v8

    .line 208
    .line 209
    move-wide/from16 v23, v15

    .line 210
    .line 211
    move v3, v10

    .line 212
    :goto_7
    shr-long v6, v27, v3

    .line 213
    .line 214
    add-int/lit8 v2, v29, 0x1

    .line 215
    .line 216
    move v10, v3

    .line 217
    move-wide v3, v6

    .line 218
    move/from16 v7, v20

    .line 219
    .line 220
    move-wide/from16 v8, v21

    .line 221
    .line 222
    move-wide/from16 v15, v23

    .line 223
    .line 224
    move v6, v2

    .line 225
    move-object/from16 v2, v26

    .line 226
    .line 227
    goto/16 :goto_1

    .line 228
    .line 229
    :cond_8
    move-object/from16 v26, v2

    .line 230
    .line 231
    move/from16 v20, v7

    .line 232
    .line 233
    move-wide/from16 v21, v8

    .line 234
    .line 235
    move v3, v10

    .line 236
    move-wide/from16 v23, v15

    .line 237
    .line 238
    if-ne v5, v3, :cond_b

    .line 239
    .line 240
    goto :goto_8

    .line 241
    :cond_9
    move-object/from16 v26, v2

    .line 242
    .line 243
    move/from16 v20, v7

    .line 244
    .line 245
    move-wide/from16 v21, v8

    .line 246
    .line 247
    move-wide/from16 v23, v15

    .line 248
    .line 249
    :goto_8
    if-eq v14, v13, :cond_b

    .line 250
    .line 251
    add-int/lit8 v14, v14, 0x1

    .line 252
    .line 253
    move/from16 v7, v20

    .line 254
    .line 255
    move-wide/from16 v8, v21

    .line 256
    .line 257
    move-wide/from16 v15, v23

    .line 258
    .line 259
    move-object/from16 v2, v26

    .line 260
    .line 261
    const/16 v10, 0x8

    .line 262
    .line 263
    goto/16 :goto_0

    .line 264
    .line 265
    :cond_a
    move/from16 v20, v7

    .line 266
    .line 267
    move-wide/from16 v21, v8

    .line 268
    .line 269
    const-wide/16 v17, 0xff

    .line 270
    .line 271
    const-wide/16 v23, 0x80

    .line 272
    .line 273
    :cond_b
    iget-object v2, v0, Lv3/p0;->q:Landroidx/collection/q0;

    .line 274
    .line 275
    if-eqz v2, :cond_f

    .line 276
    .line 277
    iget-object v3, v2, Landroidx/collection/q0;->a:[J

    .line 278
    .line 279
    array-length v4, v3

    .line 280
    add-int/lit8 v4, v4, -0x2

    .line 281
    .line 282
    if-ltz v4, :cond_f

    .line 283
    .line 284
    const/4 v5, 0x0

    .line 285
    :goto_9
    aget-wide v6, v3, v5

    .line 286
    .line 287
    not-long v8, v6

    .line 288
    shl-long v8, v8, v20

    .line 289
    .line 290
    and-long/2addr v8, v6

    .line 291
    and-long v8, v8, v21

    .line 292
    .line 293
    cmp-long v8, v8, v21

    .line 294
    .line 295
    if-eqz v8, :cond_e

    .line 296
    .line 297
    sub-int v8, v5, v4

    .line 298
    .line 299
    not-int v8, v8

    .line 300
    ushr-int/lit8 v8, v8, 0x1f

    .line 301
    .line 302
    const/16 v16, 0x8

    .line 303
    .line 304
    rsub-int/lit8 v10, v8, 0x8

    .line 305
    .line 306
    const/4 v8, 0x0

    .line 307
    :goto_a
    if-ge v8, v10, :cond_d

    .line 308
    .line 309
    and-long v11, v6, v17

    .line 310
    .line 311
    cmp-long v9, v11, v23

    .line 312
    .line 313
    if-gez v9, :cond_c

    .line 314
    .line 315
    shl-int/lit8 v9, v5, 0x3

    .line 316
    .line 317
    add-int/2addr v9, v8

    .line 318
    iget-object v11, v2, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 319
    .line 320
    aget-object v11, v11, v9

    .line 321
    .line 322
    iget-object v12, v2, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 323
    .line 324
    aget-object v12, v12, v9

    .line 325
    .line 326
    check-cast v12, Landroidx/collection/r0;

    .line 327
    .line 328
    check-cast v11, Lt3/q;

    .line 329
    .line 330
    invoke-virtual {v12}, Landroidx/collection/r0;->g()Z

    .line 331
    .line 332
    .line 333
    move-result v11

    .line 334
    if-eqz v11, :cond_c

    .line 335
    .line 336
    invoke-virtual {v2, v9}, Landroidx/collection/q0;->l(I)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    :cond_c
    const/16 v9, 0x8

    .line 340
    .line 341
    shr-long/2addr v6, v9

    .line 342
    add-int/lit8 v8, v8, 0x1

    .line 343
    .line 344
    goto :goto_a

    .line 345
    :cond_d
    const/16 v9, 0x8

    .line 346
    .line 347
    if-ne v10, v9, :cond_f

    .line 348
    .line 349
    goto :goto_b

    .line 350
    :cond_e
    const/16 v9, 0x8

    .line 351
    .line 352
    :goto_b
    if-eq v5, v4, :cond_f

    .line 353
    .line 354
    add-int/lit8 v5, v5, 0x1

    .line 355
    .line 356
    goto :goto_9

    .line 357
    :cond_f
    iget-object v2, v0, Lv3/p0;->q:Landroidx/collection/q0;

    .line 358
    .line 359
    if-nez v2, :cond_10

    .line 360
    .line 361
    new-instance v2, Landroidx/collection/q0;

    .line 362
    .line 363
    invoke-direct {v2}, Landroidx/collection/q0;-><init>()V

    .line 364
    .line 365
    .line 366
    iput-object v2, v0, Lv3/p0;->q:Landroidx/collection/q0;

    .line 367
    .line 368
    :cond_10
    invoke-virtual {v2, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    if-nez v0, :cond_11

    .line 373
    .line 374
    new-instance v0, Landroidx/collection/r0;

    .line 375
    .line 376
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 377
    .line 378
    .line 379
    invoke-virtual {v2, v1, v0}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    :cond_11
    check-cast v0, Landroidx/collection/r0;

    .line 383
    .line 384
    new-instance v1, Lv3/e2;

    .line 385
    .line 386
    move-object/from16 v2, p1

    .line 387
    .line 388
    invoke-direct {v1, v2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v0, v1}, Landroidx/collection/r0;->k(Ljava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    return-void
.end method

.method public abstract C0(Lt3/a;)I
.end method

.method public final E0(Lv3/s1;JJ)V
    .locals 23

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v7, v1, Lv3/p0;->q:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v0, v1, Lv3/p0;->p:Lca/j;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lca/j;

    .line 10
    .line 11
    invoke-direct {v0}, Lca/j;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v0, v1, Lv3/p0;->p:Lca/j;

    .line 15
    .line 16
    :cond_0
    move-object v8, v0

    .line 17
    invoke-virtual {v1}, Lv3/p0;->M0()Lv3/h0;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object v0, v0, Lv3/h0;->p:Lv3/o1;

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    check-cast v0, Lw3/t;

    .line 26
    .line 27
    invoke-virtual {v0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 28
    .line 29
    .line 30
    move-result-object v9

    .line 31
    if-eqz v9, :cond_1

    .line 32
    .line 33
    sget-object v10, Lv3/e;->h:Lv3/e;

    .line 34
    .line 35
    new-instance v0, Lv3/n0;

    .line 36
    .line 37
    move-object/from16 v6, p1

    .line 38
    .line 39
    move-wide/from16 v2, p2

    .line 40
    .line 41
    move-wide/from16 v4, p4

    .line 42
    .line 43
    invoke-direct/range {v0 .. v6}, Lv3/n0;-><init>(Lv3/p0;JJLv3/s1;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v9, v6, v10, v0}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    invoke-virtual/range {p0 .. p0}, Lv3/p0;->I()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-object v1, v8, Lca/j;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v1, Landroidx/collection/r0;

    .line 56
    .line 57
    iget-object v2, v8, Lca/j;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v2, Landroidx/collection/r0;

    .line 60
    .line 61
    iget v3, v8, Lca/j;->a:I

    .line 62
    .line 63
    const/4 v5, 0x0

    .line 64
    :goto_0
    if-ge v5, v3, :cond_4

    .line 65
    .line 66
    iget-object v6, v8, Lca/j;->d:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v6, [B

    .line 69
    .line 70
    aget-byte v6, v6, v5

    .line 71
    .line 72
    const/4 v9, 0x3

    .line 73
    if-ne v6, v9, :cond_2

    .line 74
    .line 75
    iget-object v6, v8, Lca/j;->b:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v6, [Lt3/q;

    .line 78
    .line 79
    aget-object v6, v6, v5

    .line 80
    .line 81
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v2, v6}, Landroidx/collection/r0;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_2
    if-eqz v6, :cond_3

    .line 89
    .line 90
    if-eqz v7, :cond_3

    .line 91
    .line 92
    iget-object v6, v8, Lca/j;->b:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v6, [Lt3/q;

    .line 95
    .line 96
    aget-object v6, v6, v5

    .line 97
    .line 98
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v7, v6}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    check-cast v6, Landroidx/collection/r0;

    .line 106
    .line 107
    if-eqz v6, :cond_3

    .line 108
    .line 109
    invoke-virtual {v1, v6}, Landroidx/collection/r0;->j(Landroidx/collection/r0;)V

    .line 110
    .line 111
    .line 112
    :cond_3
    :goto_1
    add-int/lit8 v5, v5, 0x1

    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_4
    iget v3, v8, Lca/j;->a:I

    .line 116
    .line 117
    const/4 v5, 0x0

    .line 118
    const/4 v6, 0x0

    .line 119
    :goto_2
    const/4 v7, 0x2

    .line 120
    if-ge v5, v3, :cond_7

    .line 121
    .line 122
    iget-object v9, v8, Lca/j;->d:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v9, [B

    .line 125
    .line 126
    aget-byte v10, v9, v5

    .line 127
    .line 128
    if-ne v10, v7, :cond_5

    .line 129
    .line 130
    add-int/lit8 v6, v6, 0x1

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_5
    if-lez v6, :cond_6

    .line 134
    .line 135
    sub-int v10, v5, v6

    .line 136
    .line 137
    iget-object v11, v8, Lca/j;->b:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v11, [Lt3/q;

    .line 140
    .line 141
    aget-object v12, v11, v5

    .line 142
    .line 143
    aput-object v12, v11, v10

    .line 144
    .line 145
    :cond_6
    :goto_3
    aput-byte v7, v9, v5

    .line 146
    .line 147
    add-int/lit8 v5, v5, 0x1

    .line 148
    .line 149
    goto :goto_2

    .line 150
    :cond_7
    iget v3, v8, Lca/j;->a:I

    .line 151
    .line 152
    sub-int v5, v3, v6

    .line 153
    .line 154
    :goto_4
    const/4 v9, 0x0

    .line 155
    if-ge v5, v3, :cond_8

    .line 156
    .line 157
    iget-object v10, v8, Lca/j;->b:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v10, [Lt3/q;

    .line 160
    .line 161
    aput-object v9, v10, v5

    .line 162
    .line 163
    add-int/lit8 v5, v5, 0x1

    .line 164
    .line 165
    goto :goto_4

    .line 166
    :cond_8
    iget v3, v8, Lca/j;->a:I

    .line 167
    .line 168
    sub-int/2addr v3, v6

    .line 169
    iput v3, v8, Lca/j;->a:I

    .line 170
    .line 171
    invoke-virtual/range {p0 .. p0}, Lv3/p0;->O0()Lv3/p0;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    iget-object v5, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 176
    .line 177
    iget-object v6, v2, Landroidx/collection/r0;->a:[J

    .line 178
    .line 179
    array-length v8, v6

    .line 180
    sub-int/2addr v8, v7

    .line 181
    const/4 v14, 0x7

    .line 182
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 183
    .line 184
    .line 185
    .line 186
    .line 187
    move/from16 p1, v7

    .line 188
    .line 189
    const/16 v7, 0x8

    .line 190
    .line 191
    if-ltz v8, :cond_12

    .line 192
    .line 193
    const-wide/16 p3, 0x80

    .line 194
    .line 195
    const/4 v9, 0x0

    .line 196
    :goto_5
    aget-wide v10, v6, v9

    .line 197
    .line 198
    const-wide/16 v17, 0xff

    .line 199
    .line 200
    not-long v12, v10

    .line 201
    shl-long/2addr v12, v14

    .line 202
    and-long/2addr v12, v10

    .line 203
    and-long/2addr v12, v15

    .line 204
    cmp-long v12, v12, v15

    .line 205
    .line 206
    if-eqz v12, :cond_11

    .line 207
    .line 208
    sub-int v12, v9, v8

    .line 209
    .line 210
    not-int v12, v12

    .line 211
    ushr-int/lit8 v12, v12, 0x1f

    .line 212
    .line 213
    rsub-int/lit8 v12, v12, 0x8

    .line 214
    .line 215
    const/4 v13, 0x0

    .line 216
    :goto_6
    if-ge v13, v12, :cond_10

    .line 217
    .line 218
    and-long v19, v10, v17

    .line 219
    .line 220
    cmp-long v19, v19, p3

    .line 221
    .line 222
    if-gez v19, :cond_e

    .line 223
    .line 224
    shl-int/lit8 v19, v9, 0x3

    .line 225
    .line 226
    add-int v19, v19, v13

    .line 227
    .line 228
    aget-object v19, v5, v19

    .line 229
    .line 230
    move/from16 p5, v14

    .line 231
    .line 232
    move-object/from16 v14, v19

    .line 233
    .line 234
    check-cast v14, Lt3/q;

    .line 235
    .line 236
    move-wide/from16 v19, v15

    .line 237
    .line 238
    if-nez v3, :cond_9

    .line 239
    .line 240
    move-object/from16 v15, p0

    .line 241
    .line 242
    goto :goto_7

    .line 243
    :cond_9
    move-object v15, v3

    .line 244
    :goto_7
    move/from16 v21, v7

    .line 245
    .line 246
    move-object v4, v15

    .line 247
    :goto_8
    iget-object v7, v4, Lv3/p0;->p:Lca/j;

    .line 248
    .line 249
    if-eqz v7, :cond_a

    .line 250
    .line 251
    iget-object v7, v7, Lca/j;->b:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast v7, [Lt3/q;

    .line 254
    .line 255
    invoke-static {v14, v7}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-result v7

    .line 259
    move/from16 v22, v0

    .line 260
    .line 261
    const/4 v0, 0x1

    .line 262
    if-ne v7, v0, :cond_b

    .line 263
    .line 264
    goto :goto_9

    .line 265
    :cond_a
    move/from16 v22, v0

    .line 266
    .line 267
    :cond_b
    invoke-virtual {v4}, Lv3/p0;->O0()Lv3/p0;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    if-nez v0, :cond_d

    .line 272
    .line 273
    :goto_9
    iget-object v0, v4, Lv3/p0;->q:Landroidx/collection/q0;

    .line 274
    .line 275
    if-eqz v0, :cond_c

    .line 276
    .line 277
    invoke-virtual {v0, v14}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v0

    .line 281
    check-cast v0, Landroidx/collection/r0;

    .line 282
    .line 283
    goto :goto_a

    .line 284
    :cond_c
    const/4 v0, 0x0

    .line 285
    :goto_a
    if-eqz v0, :cond_f

    .line 286
    .line 287
    invoke-virtual {v15, v0}, Lv3/p0;->S0(Landroidx/collection/r0;)V

    .line 288
    .line 289
    .line 290
    goto :goto_b

    .line 291
    :cond_d
    move-object v4, v0

    .line 292
    move/from16 v0, v22

    .line 293
    .line 294
    goto :goto_8

    .line 295
    :cond_e
    move/from16 v22, v0

    .line 296
    .line 297
    move/from16 v21, v7

    .line 298
    .line 299
    move/from16 p5, v14

    .line 300
    .line 301
    move-wide/from16 v19, v15

    .line 302
    .line 303
    :cond_f
    :goto_b
    shr-long v10, v10, v21

    .line 304
    .line 305
    add-int/lit8 v13, v13, 0x1

    .line 306
    .line 307
    move/from16 v14, p5

    .line 308
    .line 309
    move-wide/from16 v15, v19

    .line 310
    .line 311
    move/from16 v7, v21

    .line 312
    .line 313
    move/from16 v0, v22

    .line 314
    .line 315
    goto :goto_6

    .line 316
    :cond_10
    move/from16 v22, v0

    .line 317
    .line 318
    move v0, v7

    .line 319
    move/from16 p5, v14

    .line 320
    .line 321
    move-wide/from16 v19, v15

    .line 322
    .line 323
    if-ne v12, v0, :cond_13

    .line 324
    .line 325
    goto :goto_c

    .line 326
    :cond_11
    move/from16 v22, v0

    .line 327
    .line 328
    move/from16 p5, v14

    .line 329
    .line 330
    move-wide/from16 v19, v15

    .line 331
    .line 332
    :goto_c
    if-eq v9, v8, :cond_13

    .line 333
    .line 334
    add-int/lit8 v9, v9, 0x1

    .line 335
    .line 336
    move/from16 v14, p5

    .line 337
    .line 338
    move-wide/from16 v15, v19

    .line 339
    .line 340
    move/from16 v0, v22

    .line 341
    .line 342
    const/16 v7, 0x8

    .line 343
    .line 344
    goto/16 :goto_5

    .line 345
    .line 346
    :cond_12
    move/from16 v22, v0

    .line 347
    .line 348
    move/from16 p5, v14

    .line 349
    .line 350
    move-wide/from16 v19, v15

    .line 351
    .line 352
    const-wide/16 p3, 0x80

    .line 353
    .line 354
    const-wide/16 v17, 0xff

    .line 355
    .line 356
    :cond_13
    invoke-virtual {v2}, Landroidx/collection/r0;->b()V

    .line 357
    .line 358
    .line 359
    iget-object v0, v1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 360
    .line 361
    iget-object v2, v1, Landroidx/collection/r0;->a:[J

    .line 362
    .line 363
    array-length v3, v2

    .line 364
    add-int/lit8 v3, v3, -0x2

    .line 365
    .line 366
    if-ltz v3, :cond_18

    .line 367
    .line 368
    const/4 v4, 0x0

    .line 369
    :goto_d
    aget-wide v5, v2, v4

    .line 370
    .line 371
    not-long v7, v5

    .line 372
    shl-long v7, v7, p5

    .line 373
    .line 374
    and-long/2addr v7, v5

    .line 375
    and-long v7, v7, v19

    .line 376
    .line 377
    cmp-long v7, v7, v19

    .line 378
    .line 379
    if-eqz v7, :cond_17

    .line 380
    .line 381
    sub-int v7, v4, v3

    .line 382
    .line 383
    not-int v7, v7

    .line 384
    ushr-int/lit8 v7, v7, 0x1f

    .line 385
    .line 386
    const/16 v21, 0x8

    .line 387
    .line 388
    rsub-int/lit8 v7, v7, 0x8

    .line 389
    .line 390
    const/4 v8, 0x0

    .line 391
    :goto_e
    if-ge v8, v7, :cond_16

    .line 392
    .line 393
    and-long v9, v5, v17

    .line 394
    .line 395
    cmp-long v9, v9, p3

    .line 396
    .line 397
    if-gez v9, :cond_15

    .line 398
    .line 399
    shl-int/lit8 v9, v4, 0x3

    .line 400
    .line 401
    add-int/2addr v9, v8

    .line 402
    aget-object v9, v0, v9

    .line 403
    .line 404
    check-cast v9, Lv3/e2;

    .line 405
    .line 406
    invoke-virtual {v9}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v9

    .line 410
    check-cast v9, Lv3/h0;

    .line 411
    .line 412
    if-eqz v9, :cond_15

    .line 413
    .line 414
    if-eqz v22, :cond_14

    .line 415
    .line 416
    const/4 v10, 0x0

    .line 417
    invoke-virtual {v9, v10}, Lv3/h0;->V(Z)V

    .line 418
    .line 419
    .line 420
    goto :goto_f

    .line 421
    :cond_14
    const/4 v10, 0x0

    .line 422
    invoke-virtual {v9, v10}, Lv3/h0;->X(Z)V

    .line 423
    .line 424
    .line 425
    :goto_f
    const/16 v9, 0x8

    .line 426
    .line 427
    goto :goto_10

    .line 428
    :cond_15
    const/4 v10, 0x0

    .line 429
    goto :goto_f

    .line 430
    :goto_10
    shr-long/2addr v5, v9

    .line 431
    add-int/lit8 v8, v8, 0x1

    .line 432
    .line 433
    goto :goto_e

    .line 434
    :cond_16
    const/16 v9, 0x8

    .line 435
    .line 436
    const/4 v10, 0x0

    .line 437
    if-ne v7, v9, :cond_18

    .line 438
    .line 439
    goto :goto_11

    .line 440
    :cond_17
    const/16 v9, 0x8

    .line 441
    .line 442
    const/4 v10, 0x0

    .line 443
    :goto_11
    if-eq v4, v3, :cond_18

    .line 444
    .line 445
    add-int/lit8 v4, v4, 0x1

    .line 446
    .line 447
    goto :goto_d

    .line 448
    :cond_18
    invoke-virtual {v1}, Landroidx/collection/r0;->b()V

    .line 449
    .line 450
    .line 451
    return-void
.end method

.method public final F0(Lt3/r0;)V
    .locals 14

    .line 1
    iget-object v0, p0, Lv3/p0;->q:Landroidx/collection/q0;

    .line 2
    .line 3
    iget-boolean v1, p0, Lv3/p0;->n:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    goto/16 :goto_6

    .line 8
    .line 9
    :cond_0
    invoke-interface {p1}, Lt3/r0;->d()Lay0/k;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const/4 v2, 0x0

    .line 14
    if-nez v1, :cond_5

    .line 15
    .line 16
    if-eqz v0, :cond_b

    .line 17
    .line 18
    iget-object p1, v0, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 19
    .line 20
    iget-object v1, v0, Landroidx/collection/q0;->a:[J

    .line 21
    .line 22
    array-length v3, v1

    .line 23
    add-int/lit8 v3, v3, -0x2

    .line 24
    .line 25
    if-ltz v3, :cond_4

    .line 26
    .line 27
    move v4, v2

    .line 28
    :goto_0
    aget-wide v5, v1, v4

    .line 29
    .line 30
    not-long v7, v5

    .line 31
    const/4 v9, 0x7

    .line 32
    shl-long/2addr v7, v9

    .line 33
    and-long/2addr v7, v5

    .line 34
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v7, v9

    .line 40
    cmp-long v7, v7, v9

    .line 41
    .line 42
    if-eqz v7, :cond_3

    .line 43
    .line 44
    sub-int v7, v4, v3

    .line 45
    .line 46
    not-int v7, v7

    .line 47
    ushr-int/lit8 v7, v7, 0x1f

    .line 48
    .line 49
    const/16 v8, 0x8

    .line 50
    .line 51
    rsub-int/lit8 v7, v7, 0x8

    .line 52
    .line 53
    move v9, v2

    .line 54
    :goto_1
    if-ge v9, v7, :cond_2

    .line 55
    .line 56
    const-wide/16 v10, 0xff

    .line 57
    .line 58
    and-long/2addr v10, v5

    .line 59
    const-wide/16 v12, 0x80

    .line 60
    .line 61
    cmp-long v10, v10, v12

    .line 62
    .line 63
    if-gez v10, :cond_1

    .line 64
    .line 65
    shl-int/lit8 v10, v4, 0x3

    .line 66
    .line 67
    add-int/2addr v10, v9

    .line 68
    aget-object v10, p1, v10

    .line 69
    .line 70
    check-cast v10, Landroidx/collection/r0;

    .line 71
    .line 72
    invoke-virtual {p0, v10}, Lv3/p0;->S0(Landroidx/collection/r0;)V

    .line 73
    .line 74
    .line 75
    :cond_1
    shr-long/2addr v5, v8

    .line 76
    add-int/lit8 v9, v9, 0x1

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_2
    if-ne v7, v8, :cond_4

    .line 80
    .line 81
    :cond_3
    if-eq v4, v3, :cond_4

    .line 82
    .line 83
    add-int/lit8 v4, v4, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_4
    invoke-virtual {v0}, Landroidx/collection/q0;->a()V

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :cond_5
    iget-object v0, p0, Lv3/p0;->j:Lay0/k;

    .line 91
    .line 92
    const/4 v3, 0x1

    .line 93
    if-eq v0, v1, :cond_6

    .line 94
    .line 95
    move v0, v3

    .line 96
    goto :goto_2

    .line 97
    :cond_6
    move v0, v2

    .line 98
    :goto_2
    const-wide/16 v4, 0x0

    .line 99
    .line 100
    if-nez v0, :cond_9

    .line 101
    .line 102
    invoke-virtual {p0}, Lv3/p0;->Q0()Lv3/m0;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    iget-boolean v1, v1, Lv3/m0;->d:Z

    .line 107
    .line 108
    if-eqz v1, :cond_9

    .line 109
    .line 110
    invoke-virtual {p0}, Lv3/p0;->J0()Lt3/y;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    invoke-interface {v0, v4, v5}, Lt3/y;->K(J)J

    .line 115
    .line 116
    .line 117
    move-result-wide v4

    .line 118
    invoke-static {v4, v5}, Lkp/d9;->b(J)J

    .line 119
    .line 120
    .line 121
    move-result-wide v4

    .line 122
    invoke-interface {v0}, Lt3/y;->h()J

    .line 123
    .line 124
    .line 125
    move-result-wide v0

    .line 126
    invoke-virtual {p0}, Lv3/p0;->Q0()Lv3/m0;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    iget-wide v6, v6, Lv3/m0;->e:J

    .line 131
    .line 132
    invoke-static {v4, v5, v6, v7}, Lt4/j;->b(JJ)Z

    .line 133
    .line 134
    .line 135
    move-result v6

    .line 136
    if-eqz v6, :cond_7

    .line 137
    .line 138
    invoke-virtual {p0}, Lv3/p0;->Q0()Lv3/m0;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    iget-wide v6, v6, Lv3/m0;->f:J

    .line 143
    .line 144
    invoke-static {v0, v1, v6, v7}, Lt4/l;->a(JJ)Z

    .line 145
    .line 146
    .line 147
    move-result v6

    .line 148
    if-nez v6, :cond_8

    .line 149
    .line 150
    :cond_7
    move v2, v3

    .line 151
    :cond_8
    move-wide v3, v4

    .line 152
    move-wide v5, v0

    .line 153
    move v0, v2

    .line 154
    goto :goto_3

    .line 155
    :cond_9
    const-wide v1, 0x7fffffff7fffffffL

    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    move-wide v5, v4

    .line 161
    move-wide v3, v1

    .line 162
    :goto_3
    if-eqz v0, :cond_b

    .line 163
    .line 164
    iget-object v0, p0, Lv3/p0;->k:Lv3/s1;

    .line 165
    .line 166
    if-eqz v0, :cond_a

    .line 167
    .line 168
    iput-object p1, v0, Lv3/s1;->d:Lt3/r0;

    .line 169
    .line 170
    :goto_4
    move-object v1, p0

    .line 171
    move-object v2, v0

    .line 172
    goto :goto_5

    .line 173
    :cond_a
    new-instance v0, Lv3/s1;

    .line 174
    .line 175
    invoke-direct {v0, p1, p0}, Lv3/s1;-><init>(Lt3/r0;Lv3/p0;)V

    .line 176
    .line 177
    .line 178
    iput-object v0, p0, Lv3/p0;->k:Lv3/s1;

    .line 179
    .line 180
    goto :goto_4

    .line 181
    :goto_5
    invoke-virtual/range {v1 .. v6}, Lv3/p0;->E0(Lv3/s1;JJ)V

    .line 182
    .line 183
    .line 184
    invoke-interface {p1}, Lt3/r0;->d()Lay0/k;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    iput-object p0, v1, Lv3/p0;->j:Lay0/k;

    .line 189
    .line 190
    :cond_b
    :goto_6
    return-void
.end method

.method public abstract H0()Lv3/p0;
.end method

.method public I()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public abstract J0()Lt3/y;
.end method

.method public abstract L0()Z
.end method

.method public abstract M0()Lv3/h0;
.end method

.method public final N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;
    .locals 8

    .line 1
    const/high16 v0, -0x1000000

    .line 2
    .line 3
    and-int v1, p1, v0

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    and-int/2addr v0, p2

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "Size("

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v1, " x "

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v1, ") is out of range. Each dimension must be between 0 and 16777215."

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :goto_0
    new-instance v1, Lv3/o0;

    .line 42
    .line 43
    move-object v7, p0

    .line 44
    move v2, p1

    .line 45
    move v3, p2

    .line 46
    move-object v4, p3

    .line 47
    move-object v5, p4

    .line 48
    move-object v6, p5

    .line 49
    invoke-direct/range {v1 .. v7}, Lv3/o0;-><init>(IILjava/util/Map;Lay0/k;Lay0/k;Lv3/p0;)V

    .line 50
    .line 51
    .line 52
    return-object v1
.end method

.method public abstract N0()Lt3/r0;
.end method

.method public abstract O0()Lv3/p0;
.end method

.method public abstract P0()J
.end method

.method public final Q0()Lv3/m0;
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/p0;->i:Lv3/m0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lv3/m0;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lv3/m0;-><init>(Lv3/p0;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lv3/p0;->i:Lv3/m0;

    .line 11
    .line 12
    :cond_0
    return-object v0
.end method

.method public final S0(Landroidx/collection/r0;)V
    .locals 13

    .line 1
    iget-object v0, p1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 2
    .line 3
    iget-object p1, p1, Landroidx/collection/r0;->a:[J

    .line 4
    .line 5
    array-length v1, p1

    .line 6
    add-int/lit8 v1, v1, -0x2

    .line 7
    .line 8
    if-ltz v1, :cond_4

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    aget-wide v4, p1, v3

    .line 13
    .line 14
    not-long v6, v4

    .line 15
    const/4 v8, 0x7

    .line 16
    shl-long/2addr v6, v8

    .line 17
    and-long/2addr v6, v4

    .line 18
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    and-long/2addr v6, v8

    .line 24
    cmp-long v6, v6, v8

    .line 25
    .line 26
    if-eqz v6, :cond_3

    .line 27
    .line 28
    sub-int v6, v3, v1

    .line 29
    .line 30
    not-int v6, v6

    .line 31
    ushr-int/lit8 v6, v6, 0x1f

    .line 32
    .line 33
    const/16 v7, 0x8

    .line 34
    .line 35
    rsub-int/lit8 v6, v6, 0x8

    .line 36
    .line 37
    move v8, v2

    .line 38
    :goto_1
    if-ge v8, v6, :cond_2

    .line 39
    .line 40
    const-wide/16 v9, 0xff

    .line 41
    .line 42
    and-long/2addr v9, v4

    .line 43
    const-wide/16 v11, 0x80

    .line 44
    .line 45
    cmp-long v9, v9, v11

    .line 46
    .line 47
    if-gez v9, :cond_1

    .line 48
    .line 49
    shl-int/lit8 v9, v3, 0x3

    .line 50
    .line 51
    add-int/2addr v9, v8

    .line 52
    aget-object v9, v0, v9

    .line 53
    .line 54
    check-cast v9, Lv3/e2;

    .line 55
    .line 56
    invoke-virtual {v9}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v9

    .line 60
    check-cast v9, Lv3/h0;

    .line 61
    .line 62
    if-eqz v9, :cond_1

    .line 63
    .line 64
    invoke-virtual {p0}, Lv3/p0;->I()Z

    .line 65
    .line 66
    .line 67
    move-result v10

    .line 68
    if-eqz v10, :cond_0

    .line 69
    .line 70
    invoke-virtual {v9, v2}, Lv3/h0;->V(Z)V

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_0
    invoke-virtual {v9, v2}, Lv3/h0;->X(Z)V

    .line 75
    .line 76
    .line 77
    :cond_1
    :goto_2
    shr-long/2addr v4, v7

    .line 78
    add-int/lit8 v8, v8, 0x1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_2
    if-ne v6, v7, :cond_4

    .line 82
    .line 83
    :cond_3
    if-eq v3, v1, :cond_4

    .line 84
    .line 85
    add-int/lit8 v3, v3, 0x1

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_4
    return-void
.end method

.method public abstract T0()V
.end method

.method public final a0(Lt3/a;)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lv3/p0;->L0()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/high16 v1, -0x80000000

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0, p1}, Lv3/p0;->C0(Lt3/a;)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    :goto_0
    return v1

    .line 17
    :cond_1
    instance-of p1, p1, Lt3/r1;

    .line 18
    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    iget-wide p0, p0, Lt3/e1;->h:J

    .line 22
    .line 23
    const/16 v1, 0x20

    .line 24
    .line 25
    shr-long/2addr p0, v1

    .line 26
    :goto_1
    long-to-int p0, p0

    .line 27
    goto :goto_2

    .line 28
    :cond_2
    iget-wide p0, p0, Lt3/e1;->h:J

    .line 29
    .line 30
    const-wide v1, 0xffffffffL

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    and-long/2addr p0, v1

    .line 36
    goto :goto_1

    .line 37
    :goto_2
    add-int/2addr v0, p0

    .line 38
    return v0
.end method

.method public final p(Z)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lv3/p0;->O0()Lv3/p0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0}, Lv3/p0;->M0()Lv3/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v0, v1

    .line 14
    :goto_0
    invoke-virtual {p0}, Lv3/p0;->M0()Lv3/h0;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    iput-boolean p1, p0, Lv3/p0;->l:Z

    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    if-eqz v0, :cond_2

    .line 28
    .line 29
    iget-object v2, v0, Lv3/h0;->I:Lv3/l0;

    .line 30
    .line 31
    iget-object v2, v2, Lv3/l0;->d:Lv3/d0;

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_2
    move-object v2, v1

    .line 35
    :goto_1
    sget-object v3, Lv3/d0;->f:Lv3/d0;

    .line 36
    .line 37
    if-eq v2, v3, :cond_5

    .line 38
    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    iget-object v0, v0, Lv3/h0;->I:Lv3/l0;

    .line 42
    .line 43
    iget-object v1, v0, Lv3/l0;->d:Lv3/d0;

    .line 44
    .line 45
    :cond_3
    sget-object v0, Lv3/d0;->g:Lv3/d0;

    .line 46
    .line 47
    if-ne v1, v0, :cond_4

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_4
    return-void

    .line 51
    :cond_5
    :goto_2
    iput-boolean p1, p0, Lv3/p0;->l:Z

    .line 52
    .line 53
    return-void
.end method
