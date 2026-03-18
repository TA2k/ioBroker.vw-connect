.class public final Ll2/h0;
.super Lv2/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/t2;


# instance fields
.field public final e:Lay0/a;

.field public final f:Ll2/n2;

.field public g:Ll2/g0;


# direct methods
.method public constructor <init>(Lay0/a;Ll2/n2;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lv2/u;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/h0;->e:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Ll2/h0;->f:Ll2/n2;

    .line 7
    .line 8
    new-instance p1, Ll2/g0;

    .line 9
    .line 10
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-virtual {p2}, Lv2/f;->g()J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    invoke-direct {p1, v0, v1}, Ll2/g0;-><init>(J)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Ll2/h0;->g:Ll2/g0;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final c(Ll2/g0;Lv2/f;ZLay0/a;)Ll2/g0;
    .locals 20

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    invoke-virtual {v6, v3, v0}, Ll2/g0;->c(Ll2/h0;Lv2/f;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_9

    .line 12
    .line 13
    if-eqz p3, :cond_8

    .line 14
    .line 15
    invoke-static {}, Ll2/b;->g()Ln2/b;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    iget-object v2, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 20
    .line 21
    iget v3, v1, Ln2/b;->f:I

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    :goto_0
    if-ge v4, v3, :cond_0

    .line 25
    .line 26
    aget-object v5, v2, v4

    .line 27
    .line 28
    check-cast v5, Ll2/s;

    .line 29
    .line 30
    invoke-virtual {v5}, Ll2/s;->b()V

    .line 31
    .line 32
    .line 33
    add-int/lit8 v4, v4, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    :try_start_0
    iget-object v2, v6, Ll2/g0;->e:Landroidx/collection/h0;

    .line 37
    .line 38
    sget-object v3, Ll2/o2;->a:Lrn/i;

    .line 39
    .line 40
    invoke-virtual {v3}, Lrn/i;->get()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    check-cast v4, Lt2/d;

    .line 45
    .line 46
    if-nez v4, :cond_1

    .line 47
    .line 48
    new-instance v4, Lt2/d;

    .line 49
    .line 50
    invoke-direct {v4}, Lt2/d;-><init>()V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v3, v4}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :catchall_0
    move-exception v0

    .line 58
    goto/16 :goto_6

    .line 59
    .line 60
    :cond_1
    :goto_1
    iget v3, v4, Lt2/d;->a:I

    .line 61
    .line 62
    iget-object v5, v2, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 63
    .line 64
    iget-object v8, v2, Landroidx/collection/h0;->c:[I

    .line 65
    .line 66
    iget-object v2, v2, Landroidx/collection/h0;->a:[J

    .line 67
    .line 68
    array-length v9, v2

    .line 69
    add-int/lit8 v9, v9, -0x2

    .line 70
    .line 71
    if-ltz v9, :cond_6

    .line 72
    .line 73
    const/4 v10, 0x0

    .line 74
    :goto_2
    aget-wide v11, v2, v10

    .line 75
    .line 76
    not-long v13, v11

    .line 77
    const/4 v15, 0x7

    .line 78
    shl-long/2addr v13, v15

    .line 79
    and-long/2addr v13, v11

    .line 80
    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    and-long/2addr v13, v15

    .line 86
    cmp-long v13, v13, v15

    .line 87
    .line 88
    if-eqz v13, :cond_5

    .line 89
    .line 90
    sub-int v13, v10, v9

    .line 91
    .line 92
    not-int v13, v13

    .line 93
    ushr-int/lit8 v13, v13, 0x1f

    .line 94
    .line 95
    const/16 v14, 0x8

    .line 96
    .line 97
    rsub-int/lit8 v13, v13, 0x8

    .line 98
    .line 99
    const/4 v15, 0x0

    .line 100
    :goto_3
    if-ge v15, v13, :cond_4

    .line 101
    .line 102
    const-wide/16 v16, 0xff

    .line 103
    .line 104
    and-long v16, v11, v16

    .line 105
    .line 106
    const-wide/16 v18, 0x80

    .line 107
    .line 108
    cmp-long v16, v16, v18

    .line 109
    .line 110
    if-gez v16, :cond_2

    .line 111
    .line 112
    shl-int/lit8 v16, v10, 0x3

    .line 113
    .line 114
    add-int v16, v16, v15

    .line 115
    .line 116
    aget-object v17, v5, v16

    .line 117
    .line 118
    aget v16, v8, v16

    .line 119
    .line 120
    move-object/from16 v7, v17

    .line 121
    .line 122
    check-cast v7, Lv2/t;

    .line 123
    .line 124
    move/from16 p0, v14

    .line 125
    .line 126
    add-int v14, v3, v16

    .line 127
    .line 128
    iput v14, v4, Lt2/d;->a:I

    .line 129
    .line 130
    invoke-virtual {v0}, Lv2/f;->e()Lay0/k;

    .line 131
    .line 132
    .line 133
    move-result-object v14

    .line 134
    if-eqz v14, :cond_3

    .line 135
    .line 136
    invoke-interface {v14, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_2
    move/from16 p0, v14

    .line 141
    .line 142
    :cond_3
    :goto_4
    shr-long v11, v11, p0

    .line 143
    .line 144
    add-int/lit8 v15, v15, 0x1

    .line 145
    .line 146
    move/from16 v14, p0

    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_4
    move v7, v14

    .line 150
    if-ne v13, v7, :cond_6

    .line 151
    .line 152
    :cond_5
    if-eq v10, v9, :cond_6

    .line 153
    .line 154
    add-int/lit8 v10, v10, 0x1

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_6
    iput v3, v4, Lt2/d;->a:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 158
    .line 159
    iget-object v0, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 160
    .line 161
    iget v1, v1, Ln2/b;->f:I

    .line 162
    .line 163
    const/4 v7, 0x0

    .line 164
    :goto_5
    if-ge v7, v1, :cond_8

    .line 165
    .line 166
    aget-object v2, v0, v7

    .line 167
    .line 168
    check-cast v2, Ll2/s;

    .line 169
    .line 170
    invoke-virtual {v2}, Ll2/s;->a()V

    .line 171
    .line 172
    .line 173
    add-int/lit8 v7, v7, 0x1

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :goto_6
    iget-object v2, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 177
    .line 178
    iget v1, v1, Ln2/b;->f:I

    .line 179
    .line 180
    const/4 v7, 0x0

    .line 181
    :goto_7
    if-ge v7, v1, :cond_7

    .line 182
    .line 183
    aget-object v3, v2, v7

    .line 184
    .line 185
    check-cast v3, Ll2/s;

    .line 186
    .line 187
    invoke-virtual {v3}, Ll2/s;->a()V

    .line 188
    .line 189
    .line 190
    add-int/lit8 v7, v7, 0x1

    .line 191
    .line 192
    goto :goto_7

    .line 193
    :cond_7
    throw v0

    .line 194
    :cond_8
    return-object v6

    .line 195
    :cond_9
    new-instance v5, Landroidx/collection/h0;

    .line 196
    .line 197
    invoke-direct {v5}, Landroidx/collection/h0;-><init>()V

    .line 198
    .line 199
    .line 200
    sget-object v0, Ll2/o2;->a:Lrn/i;

    .line 201
    .line 202
    invoke-virtual {v0}, Lrn/i;->get()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    check-cast v1, Lt2/d;

    .line 207
    .line 208
    if-nez v1, :cond_a

    .line 209
    .line 210
    new-instance v1, Lt2/d;

    .line 211
    .line 212
    invoke-direct {v1}, Lt2/d;-><init>()V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, v1}, Lrn/i;->A(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    :cond_a
    move-object v4, v1

    .line 219
    iget v1, v4, Lt2/d;->a:I

    .line 220
    .line 221
    invoke-static {}, Ll2/b;->g()Ln2/b;

    .line 222
    .line 223
    .line 224
    move-result-object v7

    .line 225
    iget-object v0, v7, Ln2/b;->d:[Ljava/lang/Object;

    .line 226
    .line 227
    iget v2, v7, Ln2/b;->f:I

    .line 228
    .line 229
    const/4 v8, 0x0

    .line 230
    :goto_8
    if-ge v8, v2, :cond_b

    .line 231
    .line 232
    aget-object v9, v0, v8

    .line 233
    .line 234
    check-cast v9, Ll2/s;

    .line 235
    .line 236
    invoke-virtual {v9}, Ll2/s;->b()V

    .line 237
    .line 238
    .line 239
    add-int/lit8 v8, v8, 0x1

    .line 240
    .line 241
    goto :goto_8

    .line 242
    :cond_b
    add-int/lit8 v0, v1, 0x1

    .line 243
    .line 244
    :try_start_1
    iput v0, v4, Lt2/d;->a:I

    .line 245
    .line 246
    new-instance v0, Lda/i;

    .line 247
    .line 248
    const/4 v2, 0x2

    .line 249
    invoke-direct/range {v0 .. v5}, Lda/i;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    move-object/from16 v2, p4

    .line 253
    .line 254
    invoke-static {v2, v0}, Lgv/a;->k(Lay0/a;Lay0/k;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    iput v1, v4, Lt2/d;->a:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 259
    .line 260
    iget-object v1, v7, Ln2/b;->d:[Ljava/lang/Object;

    .line 261
    .line 262
    iget v2, v7, Ln2/b;->f:I

    .line 263
    .line 264
    const/4 v7, 0x0

    .line 265
    :goto_9
    if-ge v7, v2, :cond_c

    .line 266
    .line 267
    aget-object v4, v1, v7

    .line 268
    .line 269
    check-cast v4, Ll2/s;

    .line 270
    .line 271
    invoke-virtual {v4}, Ll2/s;->a()V

    .line 272
    .line 273
    .line 274
    add-int/lit8 v7, v7, 0x1

    .line 275
    .line 276
    goto :goto_9

    .line 277
    :cond_c
    sget-object v1, Lv2/l;->c:Ljava/lang/Object;

    .line 278
    .line 279
    monitor-enter v1

    .line 280
    :try_start_2
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    iget-object v4, v6, Ll2/g0;->f:Ljava/lang/Object;

    .line 285
    .line 286
    sget-object v7, Ll2/g0;->h:Ljava/lang/Object;

    .line 287
    .line 288
    if-eq v4, v7, :cond_d

    .line 289
    .line 290
    iget-object v7, v3, Ll2/h0;->f:Ll2/n2;

    .line 291
    .line 292
    if-eqz v7, :cond_d

    .line 293
    .line 294
    invoke-interface {v7, v0, v4}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    const/4 v7, 0x1

    .line 299
    if-ne v4, v7, :cond_d

    .line 300
    .line 301
    iput-object v5, v6, Ll2/g0;->e:Landroidx/collection/h0;

    .line 302
    .line 303
    invoke-virtual {v6, v3, v2}, Ll2/g0;->d(Ll2/h0;Lv2/f;)I

    .line 304
    .line 305
    .line 306
    move-result v0

    .line 307
    iput v0, v6, Ll2/g0;->g:I

    .line 308
    .line 309
    move-object v4, v6

    .line 310
    goto :goto_a

    .line 311
    :catchall_1
    move-exception v0

    .line 312
    goto :goto_b

    .line 313
    :cond_d
    iget-object v4, v3, Ll2/h0;->g:Ll2/g0;

    .line 314
    .line 315
    monitor-enter v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 316
    :try_start_3
    invoke-static {v4, v3}, Lv2/l;->m(Lv2/v;Lv2/t;)Lv2/v;

    .line 317
    .line 318
    .line 319
    move-result-object v6

    .line 320
    invoke-virtual {v6, v4}, Lv2/v;->a(Lv2/v;)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {v2}, Lv2/f;->g()J

    .line 324
    .line 325
    .line 326
    move-result-wide v7

    .line 327
    iput-wide v7, v6, Lv2/v;->a:J
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 328
    .line 329
    :try_start_4
    monitor-exit v1

    .line 330
    move-object v4, v6

    .line 331
    check-cast v4, Ll2/g0;

    .line 332
    .line 333
    iput-object v5, v4, Ll2/g0;->e:Landroidx/collection/h0;

    .line 334
    .line 335
    invoke-virtual {v4, v3, v2}, Ll2/g0;->d(Ll2/h0;Lv2/f;)I

    .line 336
    .line 337
    .line 338
    move-result v2

    .line 339
    iput v2, v4, Ll2/g0;->g:I

    .line 340
    .line 341
    iput-object v0, v4, Ll2/g0;->f:Ljava/lang/Object;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 342
    .line 343
    :goto_a
    monitor-exit v1

    .line 344
    sget-object v0, Ll2/o2;->a:Lrn/i;

    .line 345
    .line 346
    invoke-virtual {v0}, Lrn/i;->get()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v0

    .line 350
    check-cast v0, Lt2/d;

    .line 351
    .line 352
    if-eqz v0, :cond_e

    .line 353
    .line 354
    iget v0, v0, Lt2/d;->a:I

    .line 355
    .line 356
    if-nez v0, :cond_e

    .line 357
    .line 358
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 359
    .line 360
    .line 361
    move-result-object v0

    .line 362
    invoke-virtual {v0}, Lv2/f;->m()V

    .line 363
    .line 364
    .line 365
    monitor-enter v1

    .line 366
    :try_start_5
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 371
    .line 372
    .line 373
    move-result-wide v2

    .line 374
    iput-wide v2, v4, Ll2/g0;->c:J

    .line 375
    .line 376
    invoke-virtual {v0}, Lv2/f;->h()I

    .line 377
    .line 378
    .line 379
    move-result v0

    .line 380
    iput v0, v4, Ll2/g0;->d:I
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 381
    .line 382
    monitor-exit v1

    .line 383
    return-object v4

    .line 384
    :catchall_2
    move-exception v0

    .line 385
    monitor-exit v1

    .line 386
    throw v0

    .line 387
    :cond_e
    return-object v4

    .line 388
    :catchall_3
    move-exception v0

    .line 389
    :try_start_6
    monitor-exit v1

    .line 390
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 391
    :goto_b
    monitor-exit v1

    .line 392
    throw v0

    .line 393
    :catchall_4
    move-exception v0

    .line 394
    iget-object v1, v7, Ln2/b;->d:[Ljava/lang/Object;

    .line 395
    .line 396
    iget v2, v7, Ln2/b;->f:I

    .line 397
    .line 398
    const/4 v7, 0x0

    .line 399
    :goto_c
    if-ge v7, v2, :cond_f

    .line 400
    .line 401
    aget-object v3, v1, v7

    .line 402
    .line 403
    check-cast v3, Ll2/s;

    .line 404
    .line 405
    invoke-virtual {v3}, Ll2/s;->a()V

    .line 406
    .line 407
    .line 408
    add-int/lit8 v7, v7, 0x1

    .line 409
    .line 410
    goto :goto_c

    .line 411
    :cond_f
    throw v0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lv2/f;->e()Lay0/k;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, p0, Ll2/h0;->g:Ll2/g0;

    .line 19
    .line 20
    invoke-static {v1, v0}, Lv2/l;->j(Lv2/v;Lv2/f;)Lv2/v;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Ll2/g0;

    .line 25
    .line 26
    const/4 v2, 0x1

    .line 27
    iget-object v3, p0, Ll2/h0;->e:Lay0/a;

    .line 28
    .line 29
    invoke-virtual {p0, v1, v0, v2, v3}, Ll2/h0;->c(Ll2/g0;Lv2/f;ZLay0/a;)Ll2/g0;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    iget-object p0, p0, Ll2/g0;->f:Ljava/lang/Object;

    .line 34
    .line 35
    return-object p0
.end method

.method public final k()Lv2/v;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/h0;->g:Ll2/g0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n(Lv2/v;)V
    .locals 1

    .line 1
    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.DerivedSnapshotState.ResultRecord<T of androidx.compose.runtime.DerivedSnapshotState>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/g0;

    .line 7
    .line 8
    iput-object p1, p0, Ll2/h0;->g:Ll2/g0;

    .line 9
    .line 10
    return-void
.end method

.method public final o()Ll2/g0;
    .locals 4

    .line 1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Ll2/h0;->g:Ll2/g0;

    .line 6
    .line 7
    invoke-static {v1, v0}, Lv2/l;->j(Lv2/v;Lv2/f;)Lv2/v;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Ll2/g0;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    iget-object v3, p0, Ll2/h0;->e:Lay0/a;

    .line 15
    .line 16
    invoke-virtual {p0, v1, v0, v2, v3}, Ll2/h0;->c(Ll2/g0;Lv2/f;ZLay0/a;)Ll2/g0;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/h0;->g:Ll2/g0;

    .line 2
    .line 3
    invoke-static {v0}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ll2/g0;

    .line 8
    .line 9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v1, "DerivedState(value="

    .line 12
    .line 13
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ll2/h0;->g:Ll2/g0;

    .line 17
    .line 18
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Ll2/g0;

    .line 23
    .line 24
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v1, p0, v2}, Ll2/g0;->c(Ll2/h0;Lv2/f;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    iget-object v1, v1, Ll2/g0;->f:Ljava/lang/Object;

    .line 35
    .line 36
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const-string v1, "<Not calculated>"

    .line 42
    .line 43
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ")@"

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method
