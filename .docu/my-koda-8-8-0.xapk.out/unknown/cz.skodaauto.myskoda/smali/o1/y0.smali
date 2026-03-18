.class public final Lo1/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/k0;


# instance fields
.field public final a:I

.field public final b:Lil/g;

.field public final c:Lay0/k;

.field public d:Lt4/a;

.field public e:Lt3/m1;

.field public f:Z

.field public g:Z

.field public h:Z

.field public i:Ljava/lang/Object;

.field public j:Z

.field public k:Lo1/x0;

.field public l:Z

.field public m:J

.field public n:J

.field public o:J

.field public final synthetic p:La8/b;


# direct methods
.method public constructor <init>(La8/b;ILil/g;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo1/y0;->p:La8/b;

    .line 5
    .line 6
    iput p2, p0, Lo1/y0;->a:I

    .line 7
    .line 8
    iput-object p3, p0, Lo1/y0;->b:Lil/g;

    .line 9
    .line 10
    iput-object p4, p0, Lo1/y0;->c:Lay0/k;

    .line 11
    .line 12
    invoke-static {}, Lmy0/j;->b()J

    .line 13
    .line 14
    .line 15
    move-result-wide p1

    .line 16
    iput-wide p1, p0, Lo1/y0;->o:J

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lo1/y0;->l:Z

    .line 3
    .line 4
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    iget-object v0, p0, Lo1/y0;->e:Lt3/m1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lt3/m1;->dispose()V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Lo1/y0;->e:Lt3/m1;

    .line 10
    .line 11
    iput-object v0, p0, Lo1/y0;->k:Lo1/x0;

    .line 12
    .line 13
    return-void
.end method

.method public final c(Lh/f0;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lo1/y0;->p:La8/b;

    .line 2
    .line 3
    iget-boolean v0, v0, La8/b;->e:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-boolean v0, p0, Lo1/y0;->l:Z

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    const-string v0, "compose:lazy:prefetch:execute:urgent"

    .line 14
    .line 15
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    :try_start_0
    invoke-virtual {p0, p1}, Lo1/y0;->d(Lh/f0;)Z

    .line 19
    .line 20
    .line 21
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-virtual {p0, p1}, Lo1/y0;->d(Lh/f0;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    :goto_0
    const-string p1, "compose:lazy:prefetch:execute:item"

    .line 36
    .line 37
    const-wide/16 v0, -0x1

    .line 38
    .line 39
    invoke-static {p1, v0, v1}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 40
    .line 41
    .line 42
    return p0
.end method

.method public final cancel()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lo1/y0;->g:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lo1/y0;->g:Z

    .line 7
    .line 8
    invoke-virtual {p0}, Lo1/y0;->b()V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final d(Lh/f0;)Z
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lo1/y0;->a:I

    .line 4
    .line 5
    int-to-long v2, v1

    .line 6
    const-string v4, "compose:lazy:prefetch:execute:item"

    .line 7
    .line 8
    invoke-static {v4, v2, v3}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 9
    .line 10
    .line 11
    iget-object v5, v0, Lo1/y0;->p:La8/b;

    .line 12
    .line 13
    iget-object v6, v5, La8/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v6, Lo1/a0;

    .line 16
    .line 17
    iget-object v6, v6, Lo1/a0;->b:Lio0/f;

    .line 18
    .line 19
    invoke-virtual {v6}, Lio0/f;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    check-cast v6, Lo1/b0;

    .line 24
    .line 25
    iget-boolean v7, v0, Lo1/y0;->g:Z

    .line 26
    .line 27
    const/4 v8, 0x0

    .line 28
    if-nez v7, :cond_21

    .line 29
    .line 30
    invoke-interface {v6}, Lo1/b0;->a()I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    if-ltz v1, :cond_21

    .line 35
    .line 36
    if-ge v1, v7, :cond_21

    .line 37
    .line 38
    invoke-interface {v6, v1}, Lo1/b0;->d(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v7

    .line 42
    iget-object v9, v0, Lo1/y0;->i:Ljava/lang/Object;

    .line 43
    .line 44
    if-eqz v9, :cond_0

    .line 45
    .line 46
    invoke-virtual {v7, v9}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v9

    .line 50
    if-nez v9, :cond_0

    .line 51
    .line 52
    invoke-virtual {v0}, Lo1/y0;->b()V

    .line 53
    .line 54
    .line 55
    return v8

    .line 56
    :cond_0
    invoke-interface {v6, v1}, Lo1/b0;->b(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    iget-object v9, v0, Lo1/y0;->b:Lil/g;

    .line 61
    .line 62
    iget-object v10, v9, Lil/g;->g:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v10, Lo1/b;

    .line 65
    .line 66
    iget-object v11, v9, Lil/g;->f:Ljava/lang/Object;

    .line 67
    .line 68
    const/4 v12, -0x1

    .line 69
    if-ne v11, v6, :cond_1

    .line 70
    .line 71
    if-eqz v10, :cond_1

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    iget-object v10, v9, Lil/g;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v10, Landroidx/collection/q0;

    .line 77
    .line 78
    invoke-virtual {v10, v6}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v11

    .line 82
    if-nez v11, :cond_2

    .line 83
    .line 84
    new-instance v11, Lo1/b;

    .line 85
    .line 86
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 87
    .line 88
    .line 89
    iput v12, v11, Lo1/b;->d:I

    .line 90
    .line 91
    invoke-virtual {v10, v6, v11}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_2
    move-object v10, v11

    .line 95
    check-cast v10, Lo1/b;

    .line 96
    .line 97
    iput-object v6, v9, Lil/g;->f:Ljava/lang/Object;

    .line 98
    .line 99
    iput-object v10, v9, Lil/g;->g:Ljava/lang/Object;

    .line 100
    .line 101
    :goto_0
    invoke-virtual {v0}, Lo1/y0;->e()Z

    .line 102
    .line 103
    .line 104
    invoke-virtual/range {p1 .. p1}, Lh/f0;->a()J

    .line 105
    .line 106
    .line 107
    move-result-wide v13

    .line 108
    iput-wide v13, v0, Lo1/y0;->m:J

    .line 109
    .line 110
    invoke-static {}, Lmy0/j;->b()J

    .line 111
    .line 112
    .line 113
    move-result-wide v8

    .line 114
    iput-wide v8, v0, Lo1/y0;->o:J

    .line 115
    .line 116
    const-wide/16 v8, 0x0

    .line 117
    .line 118
    iput-wide v8, v0, Lo1/y0;->n:J

    .line 119
    .line 120
    const-string v15, "compose:lazy:prefetch:available_time_nanos"

    .line 121
    .line 122
    invoke-static {v15, v13, v14}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0}, Lo1/y0;->e()Z

    .line 126
    .line 127
    .line 128
    move-result v13

    .line 129
    const/4 v14, 0x1

    .line 130
    move-wide v15, v8

    .line 131
    if-nez v13, :cond_a

    .line 132
    .line 133
    iget-wide v8, v0, Lo1/y0;->m:J

    .line 134
    .line 135
    iget-wide v11, v10, Lo1/b;->a:J

    .line 136
    .line 137
    invoke-virtual {v0, v8, v9, v11, v12}, Lo1/y0;->h(JJ)Z

    .line 138
    .line 139
    .line 140
    move-result v8

    .line 141
    if-eqz v8, :cond_9

    .line 142
    .line 143
    const-string v8, "compose:lazy:prefetch:compose"

    .line 144
    .line 145
    invoke-static {v8}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    :try_start_0
    iget-object v8, v0, Lo1/y0;->e:Lt3/m1;

    .line 149
    .line 150
    if-nez v8, :cond_3

    .line 151
    .line 152
    goto :goto_1

    .line 153
    :cond_3
    const-string v8, "Request was already composed!"

    .line 154
    .line 155
    invoke-static {v8}, Lj1/b;->a(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :goto_1
    iget-object v8, v5, La8/b;->f:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v8, Lo1/a0;

    .line 161
    .line 162
    invoke-virtual {v8, v1, v7, v6}, Lo1/a0;->a(ILjava/lang/Object;Ljava/lang/Object;)Lay0/n;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    iput-object v7, v0, Lo1/y0;->i:Ljava/lang/Object;

    .line 167
    .line 168
    iget-object v5, v5, La8/b;->g:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v5, Lt3/o1;

    .line 171
    .line 172
    invoke-virtual {v5}, Lt3/o1;->a()Lt3/m0;

    .line 173
    .line 174
    .line 175
    move-result-object v5

    .line 176
    iget-object v6, v5, Lt3/m0;->d:Lv3/h0;

    .line 177
    .line 178
    invoke-virtual {v6}, Lv3/h0;->I()Z

    .line 179
    .line 180
    .line 181
    move-result v8

    .line 182
    if-nez v8, :cond_4

    .line 183
    .line 184
    goto :goto_3

    .line 185
    :cond_4
    invoke-virtual {v5}, Lt3/m0;->d()V

    .line 186
    .line 187
    .line 188
    iget-object v8, v5, Lt3/m0;->j:Landroidx/collection/q0;

    .line 189
    .line 190
    invoke-virtual {v8, v7}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v8

    .line 194
    if-nez v8, :cond_7

    .line 195
    .line 196
    iget-object v8, v5, Lt3/m0;->o:Landroidx/collection/q0;

    .line 197
    .line 198
    invoke-virtual {v8, v7}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    iget-object v8, v5, Lt3/m0;->m:Landroidx/collection/q0;

    .line 202
    .line 203
    invoke-virtual {v8, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v9

    .line 207
    if-nez v9, :cond_6

    .line 208
    .line 209
    invoke-virtual {v5, v7}, Lt3/m0;->j(Ljava/lang/Object;)Lv3/h0;

    .line 210
    .line 211
    .line 212
    move-result-object v9

    .line 213
    if-eqz v9, :cond_5

    .line 214
    .line 215
    invoke-virtual {v6}, Lv3/h0;->p()Ljava/util/List;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    check-cast v11, Landroidx/collection/j0;

    .line 220
    .line 221
    iget-object v11, v11, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v11, Ln2/b;

    .line 224
    .line 225
    invoke-virtual {v11, v9}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 226
    .line 227
    .line 228
    move-result v11

    .line 229
    invoke-virtual {v6}, Lv3/h0;->p()Ljava/util/List;

    .line 230
    .line 231
    .line 232
    move-result-object v12

    .line 233
    check-cast v12, Landroidx/collection/j0;

    .line 234
    .line 235
    iget-object v12, v12, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v12, Ln2/b;

    .line 238
    .line 239
    iget v12, v12, Ln2/b;->f:I

    .line 240
    .line 241
    iput-boolean v14, v6, Lv3/h0;->s:Z

    .line 242
    .line 243
    invoke-virtual {v6, v11, v12, v14}, Lv3/h0;->M(III)V

    .line 244
    .line 245
    .line 246
    const/4 v11, 0x0

    .line 247
    iput-boolean v11, v6, Lv3/h0;->s:Z

    .line 248
    .line 249
    iget v12, v5, Lt3/m0;->r:I

    .line 250
    .line 251
    add-int/2addr v12, v14

    .line 252
    iput v12, v5, Lt3/m0;->r:I

    .line 253
    .line 254
    goto :goto_2

    .line 255
    :cond_5
    invoke-virtual {v6}, Lv3/h0;->p()Ljava/util/List;

    .line 256
    .line 257
    .line 258
    move-result-object v9

    .line 259
    check-cast v9, Landroidx/collection/j0;

    .line 260
    .line 261
    iget-object v9, v9, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast v9, Ln2/b;

    .line 264
    .line 265
    iget v9, v9, Ln2/b;->f:I

    .line 266
    .line 267
    new-instance v12, Lv3/h0;

    .line 268
    .line 269
    const/4 v11, 0x2

    .line 270
    invoke-direct {v12, v11}, Lv3/h0;-><init>(I)V

    .line 271
    .line 272
    .line 273
    iput-boolean v14, v6, Lv3/h0;->s:Z

    .line 274
    .line 275
    invoke-virtual {v6, v9, v12}, Lv3/h0;->B(ILv3/h0;)V

    .line 276
    .line 277
    .line 278
    const/4 v11, 0x0

    .line 279
    iput-boolean v11, v6, Lv3/h0;->s:Z

    .line 280
    .line 281
    iget v9, v5, Lt3/m0;->r:I

    .line 282
    .line 283
    add-int/2addr v9, v14

    .line 284
    iput v9, v5, Lt3/m0;->r:I

    .line 285
    .line 286
    move-object v9, v12

    .line 287
    :goto_2
    invoke-virtual {v8, v7, v9}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    :cond_6
    check-cast v9, Lv3/h0;

    .line 291
    .line 292
    const/4 v11, 0x0

    .line 293
    invoke-virtual {v5, v9, v7, v11, v1}, Lt3/m0;->i(Lv3/h0;Ljava/lang/Object;ZLay0/n;)V

    .line 294
    .line 295
    .line 296
    :cond_7
    :goto_3
    invoke-virtual {v6}, Lv3/h0;->I()Z

    .line 297
    .line 298
    .line 299
    move-result v1

    .line 300
    if-nez v1, :cond_8

    .line 301
    .line 302
    new-instance v1, Lt3/k0;

    .line 303
    .line 304
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 305
    .line 306
    .line 307
    goto :goto_4

    .line 308
    :cond_8
    new-instance v1, Lt3/l0;

    .line 309
    .line 310
    invoke-direct {v1, v5, v7}, Lt3/l0;-><init>(Lt3/m0;Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    :goto_4
    iput-object v1, v0, Lo1/y0;->e:Lt3/m1;

    .line 314
    .line 315
    iput-boolean v14, v0, Lo1/y0;->h:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 316
    .line 317
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 318
    .line 319
    .line 320
    invoke-virtual {v0}, Lo1/y0;->i()V

    .line 321
    .line 322
    .line 323
    iget-wide v5, v0, Lo1/y0;->n:J

    .line 324
    .line 325
    iget-wide v7, v10, Lo1/b;->a:J

    .line 326
    .line 327
    invoke-static {v5, v6, v7, v8}, Lo1/b;->a(JJ)J

    .line 328
    .line 329
    .line 330
    move-result-wide v5

    .line 331
    iput-wide v5, v10, Lo1/b;->a:J

    .line 332
    .line 333
    goto :goto_5

    .line 334
    :catchall_0
    move-exception v0

    .line 335
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 336
    .line 337
    .line 338
    throw v0

    .line 339
    :cond_9
    :goto_5
    invoke-virtual {v0}, Lo1/y0;->e()Z

    .line 340
    .line 341
    .line 342
    move-result v1

    .line 343
    if-nez v1, :cond_a

    .line 344
    .line 345
    goto/16 :goto_d

    .line 346
    .line 347
    :cond_a
    iget-boolean v1, v0, Lo1/y0;->j:Z

    .line 348
    .line 349
    if-nez v1, :cond_b

    .line 350
    .line 351
    iget-wide v5, v0, Lo1/y0;->m:J

    .line 352
    .line 353
    cmp-long v1, v5, v15

    .line 354
    .line 355
    if-lez v1, :cond_19

    .line 356
    .line 357
    const-string v1, "compose:lazy:prefetch:resolve-nested"

    .line 358
    .line 359
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    :try_start_1
    invoke-virtual {v0}, Lo1/y0;->g()Lo1/x0;

    .line 363
    .line 364
    .line 365
    move-result-object v1

    .line 366
    iput-object v1, v0, Lo1/y0;->k:Lo1/x0;

    .line 367
    .line 368
    iput-boolean v14, v0, Lo1/y0;->j:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 369
    .line 370
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 371
    .line 372
    .line 373
    goto :goto_6

    .line 374
    :catchall_1
    move-exception v0

    .line 375
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 376
    .line 377
    .line 378
    throw v0

    .line 379
    :cond_b
    :goto_6
    iget-object v1, v0, Lo1/y0;->k:Lo1/x0;

    .line 380
    .line 381
    if-eqz v1, :cond_17

    .line 382
    .line 383
    iget v5, v10, Lo1/b;->d:I

    .line 384
    .line 385
    iget-boolean v6, v0, Lo1/y0;->l:Z

    .line 386
    .line 387
    iget-object v7, v1, Lo1/x0;->b:[Ljava/util/List;

    .line 388
    .line 389
    iget v8, v1, Lo1/x0;->c:I

    .line 390
    .line 391
    iget-object v9, v1, Lo1/x0;->a:Ljava/util/List;

    .line 392
    .line 393
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 394
    .line 395
    .line 396
    move-result v12

    .line 397
    if-lt v8, v12, :cond_c

    .line 398
    .line 399
    goto/16 :goto_c

    .line 400
    .line 401
    :cond_c
    iget-object v8, v1, Lo1/x0;->f:Lo1/y0;

    .line 402
    .line 403
    iget-boolean v8, v8, Lo1/y0;->g:Z

    .line 404
    .line 405
    if-eqz v8, :cond_d

    .line 406
    .line 407
    const-string v8, "Should not execute nested prefetch on canceled request"

    .line 408
    .line 409
    invoke-static {v8}, Lj1/b;->c(Ljava/lang/String;)V

    .line 410
    .line 411
    .line 412
    :cond_d
    const-string v8, "compose:lazy:prefetch:update_nested_prefetch_count"

    .line 413
    .line 414
    invoke-static {v8}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    :try_start_2
    move-object v8, v9

    .line 418
    check-cast v8, Ljava/util/Collection;

    .line 419
    .line 420
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 421
    .line 422
    .line 423
    move-result v8

    .line 424
    const/4 v12, 0x0

    .line 425
    :goto_7
    if-ge v12, v8, :cond_e

    .line 426
    .line 427
    invoke-interface {v9, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object v17

    .line 431
    move-object/from16 v11, v17

    .line 432
    .line 433
    check-cast v11, Lo1/l0;

    .line 434
    .line 435
    iput v5, v11, Lo1/l0;->d:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 436
    .line 437
    add-int/lit8 v12, v12, 0x1

    .line 438
    .line 439
    goto :goto_7

    .line 440
    :cond_e
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 441
    .line 442
    .line 443
    const-string v5, "compose:lazy:prefetch:nested"

    .line 444
    .line 445
    invoke-static {v5}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    :goto_8
    :try_start_3
    iget v5, v1, Lo1/x0;->c:I

    .line 449
    .line 450
    invoke-interface {v9}, Ljava/util/List;->size()I

    .line 451
    .line 452
    .line 453
    move-result v8

    .line 454
    if-ge v5, v8, :cond_16

    .line 455
    .line 456
    iget v5, v1, Lo1/x0;->c:I

    .line 457
    .line 458
    aget-object v5, v7, v5

    .line 459
    .line 460
    if-nez v5, :cond_11

    .line 461
    .line 462
    invoke-virtual/range {p1 .. p1}, Lh/f0;->a()J

    .line 463
    .line 464
    .line 465
    move-result-wide v11
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 466
    cmp-long v5, v11, v15

    .line 467
    .line 468
    if-gtz v5, :cond_f

    .line 469
    .line 470
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 471
    .line 472
    .line 473
    return v14

    .line 474
    :cond_f
    :try_start_4
    iget v5, v1, Lo1/x0;->c:I

    .line 475
    .line 476
    invoke-interface {v9, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v8

    .line 480
    check-cast v8, Lo1/l0;

    .line 481
    .line 482
    iget-object v11, v8, Lo1/l0;->a:Lay0/k;

    .line 483
    .line 484
    if-nez v11, :cond_10

    .line 485
    .line 486
    sget-object v8, Lmx0/s;->d:Lmx0/s;

    .line 487
    .line 488
    goto :goto_9

    .line 489
    :cond_10
    new-instance v12, Lo1/j0;

    .line 490
    .line 491
    iget v13, v8, Lo1/l0;->d:I

    .line 492
    .line 493
    invoke-direct {v12, v8, v13}, Lo1/j0;-><init>(Lo1/l0;I)V

    .line 494
    .line 495
    .line 496
    invoke-interface {v11, v12}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    iget-object v11, v12, Lo1/j0;->b:Ljava/util/ArrayList;

    .line 500
    .line 501
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 502
    .line 503
    .line 504
    move-result v12

    .line 505
    iput v12, v8, Lo1/l0;->f:I

    .line 506
    .line 507
    move-object v8, v11

    .line 508
    :goto_9
    aput-object v8, v7, v5

    .line 509
    .line 510
    :cond_11
    iget v5, v1, Lo1/x0;->c:I

    .line 511
    .line 512
    aget-object v5, v7, v5

    .line 513
    .line 514
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 515
    .line 516
    .line 517
    :goto_a
    iget v8, v1, Lo1/x0;->d:I

    .line 518
    .line 519
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 520
    .line 521
    .line 522
    move-result v11

    .line 523
    if-ge v8, v11, :cond_15

    .line 524
    .line 525
    iget v8, v1, Lo1/x0;->d:I

    .line 526
    .line 527
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 528
    .line 529
    .line 530
    move-result-object v8

    .line 531
    check-cast v8, Lo1/y0;

    .line 532
    .line 533
    if-eqz v6, :cond_13

    .line 534
    .line 535
    if-eqz v8, :cond_12

    .line 536
    .line 537
    move-object v11, v8

    .line 538
    goto :goto_b

    .line 539
    :cond_12
    const/4 v11, 0x0

    .line 540
    :goto_b
    if-eqz v11, :cond_13

    .line 541
    .line 542
    iput-boolean v14, v11, Lo1/y0;->l:Z

    .line 543
    .line 544
    :cond_13
    iput-boolean v14, v1, Lo1/x0;->e:Z

    .line 545
    .line 546
    move-object/from16 v12, p1

    .line 547
    .line 548
    invoke-virtual {v8, v12}, Lo1/y0;->c(Lh/f0;)Z

    .line 549
    .line 550
    .line 551
    move-result v8
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 552
    if-eqz v8, :cond_14

    .line 553
    .line 554
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 555
    .line 556
    .line 557
    return v14

    .line 558
    :cond_14
    :try_start_5
    iget v8, v1, Lo1/x0;->d:I

    .line 559
    .line 560
    add-int/2addr v8, v14

    .line 561
    iput v8, v1, Lo1/x0;->d:I

    .line 562
    .line 563
    goto :goto_a

    .line 564
    :cond_15
    move-object/from16 v12, p1

    .line 565
    .line 566
    const/4 v11, 0x0

    .line 567
    iput v11, v1, Lo1/x0;->d:I

    .line 568
    .line 569
    iget v5, v1, Lo1/x0;->c:I

    .line 570
    .line 571
    add-int/2addr v5, v14

    .line 572
    iput v5, v1, Lo1/x0;->c:I
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 573
    .line 574
    goto :goto_8

    .line 575
    :cond_16
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 576
    .line 577
    .line 578
    goto :goto_c

    .line 579
    :catchall_2
    move-exception v0

    .line 580
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 581
    .line 582
    .line 583
    throw v0

    .line 584
    :catchall_3
    move-exception v0

    .line 585
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 586
    .line 587
    .line 588
    throw v0

    .line 589
    :cond_17
    :goto_c
    iget-object v1, v0, Lo1/y0;->k:Lo1/x0;

    .line 590
    .line 591
    if-eqz v1, :cond_18

    .line 592
    .line 593
    iget-boolean v1, v1, Lo1/x0;->e:Z

    .line 594
    .line 595
    if-ne v1, v14, :cond_18

    .line 596
    .line 597
    invoke-virtual {v0}, Lo1/y0;->i()V

    .line 598
    .line 599
    .line 600
    invoke-static {v4, v2, v3}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 601
    .line 602
    .line 603
    iget-object v1, v0, Lo1/y0;->k:Lo1/x0;

    .line 604
    .line 605
    if-eqz v1, :cond_18

    .line 606
    .line 607
    const/4 v11, 0x0

    .line 608
    iput-boolean v11, v1, Lo1/x0;->e:Z

    .line 609
    .line 610
    :cond_18
    iget-object v1, v0, Lo1/y0;->d:Lt4/a;

    .line 611
    .line 612
    iget-boolean v2, v0, Lo1/y0;->f:Z

    .line 613
    .line 614
    if-nez v2, :cond_1a

    .line 615
    .line 616
    if-eqz v1, :cond_1a

    .line 617
    .line 618
    iget-wide v2, v0, Lo1/y0;->m:J

    .line 619
    .line 620
    iget-wide v4, v10, Lo1/b;->c:J

    .line 621
    .line 622
    invoke-virtual {v0, v2, v3, v4, v5}, Lo1/y0;->h(JJ)Z

    .line 623
    .line 624
    .line 625
    move-result v2

    .line 626
    if-eqz v2, :cond_19

    .line 627
    .line 628
    const-string v2, "compose:lazy:prefetch:measure"

    .line 629
    .line 630
    invoke-static {v2}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 631
    .line 632
    .line 633
    :try_start_6
    iget-wide v1, v1, Lt4/a;->a:J

    .line 634
    .line 635
    invoke-virtual {v0, v1, v2}, Lo1/y0;->f(J)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 636
    .line 637
    .line 638
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 639
    .line 640
    .line 641
    invoke-virtual {v0}, Lo1/y0;->i()V

    .line 642
    .line 643
    .line 644
    iget-wide v1, v0, Lo1/y0;->n:J

    .line 645
    .line 646
    iget-wide v3, v10, Lo1/b;->c:J

    .line 647
    .line 648
    invoke-static {v1, v2, v3, v4}, Lo1/b;->a(JJ)J

    .line 649
    .line 650
    .line 651
    move-result-wide v1

    .line 652
    iput-wide v1, v10, Lo1/b;->c:J

    .line 653
    .line 654
    iget-object v1, v0, Lo1/y0;->c:Lay0/k;

    .line 655
    .line 656
    if-eqz v1, :cond_1a

    .line 657
    .line 658
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 659
    .line 660
    .line 661
    goto :goto_e

    .line 662
    :catchall_4
    move-exception v0

    .line 663
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 664
    .line 665
    .line 666
    throw v0

    .line 667
    :cond_19
    :goto_d
    return v14

    .line 668
    :cond_1a
    :goto_e
    iget-object v1, v0, Lo1/y0;->k:Lo1/x0;

    .line 669
    .line 670
    iget-boolean v2, v0, Lo1/y0;->f:Z

    .line 671
    .line 672
    if-eqz v2, :cond_20

    .line 673
    .line 674
    iget-boolean v0, v0, Lo1/y0;->j:Z

    .line 675
    .line 676
    if-eqz v0, :cond_20

    .line 677
    .line 678
    if-eqz v1, :cond_20

    .line 679
    .line 680
    iget-object v0, v1, Lo1/x0;->a:Ljava/util/List;

    .line 681
    .line 682
    move-object v1, v0

    .line 683
    check-cast v1, Ljava/util/Collection;

    .line 684
    .line 685
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 686
    .line 687
    .line 688
    move-result v2

    .line 689
    const v3, 0x7fffffff

    .line 690
    .line 691
    .line 692
    move v5, v3

    .line 693
    const/4 v4, 0x0

    .line 694
    :goto_f
    if-ge v4, v2, :cond_1b

    .line 695
    .line 696
    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v6

    .line 700
    check-cast v6, Lo1/l0;

    .line 701
    .line 702
    iget v6, v6, Lo1/l0;->e:I

    .line 703
    .line 704
    invoke-static {v5, v6}, Ljava/lang/Math;->min(II)I

    .line 705
    .line 706
    .line 707
    move-result v5

    .line 708
    add-int/lit8 v4, v4, 0x1

    .line 709
    .line 710
    goto :goto_f

    .line 711
    :cond_1b
    if-ne v5, v3, :cond_1c

    .line 712
    .line 713
    const/4 v5, 0x0

    .line 714
    :cond_1c
    iget v2, v10, Lo1/b;->d:I

    .line 715
    .line 716
    const/4 v13, -0x1

    .line 717
    if-ne v2, v13, :cond_1d

    .line 718
    .line 719
    move v2, v5

    .line 720
    goto :goto_10

    .line 721
    :cond_1d
    mul-int/lit8 v2, v2, 0x3

    .line 722
    .line 723
    add-int/2addr v2, v5

    .line 724
    div-int/lit8 v2, v2, 0x4

    .line 725
    .line 726
    :goto_10
    iput v2, v10, Lo1/b;->d:I

    .line 727
    .line 728
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 729
    .line 730
    .line 731
    move-result v1

    .line 732
    move v4, v3

    .line 733
    const/4 v2, 0x0

    .line 734
    :goto_11
    if-ge v2, v1, :cond_1e

    .line 735
    .line 736
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 737
    .line 738
    .line 739
    move-result-object v6

    .line 740
    check-cast v6, Lo1/l0;

    .line 741
    .line 742
    iget v6, v6, Lo1/l0;->f:I

    .line 743
    .line 744
    invoke-static {v4, v6}, Ljava/lang/Math;->min(II)I

    .line 745
    .line 746
    .line 747
    move-result v4

    .line 748
    add-int/lit8 v2, v2, 0x1

    .line 749
    .line 750
    goto :goto_11

    .line 751
    :cond_1e
    if-ne v4, v3, :cond_1f

    .line 752
    .line 753
    const/4 v4, 0x0

    .line 754
    :cond_1f
    if-ge v4, v5, :cond_20

    .line 755
    .line 756
    move-wide v0, v15

    .line 757
    iput-wide v0, v10, Lo1/b;->c:J

    .line 758
    .line 759
    const/4 v11, 0x0

    .line 760
    return v11

    .line 761
    :cond_20
    const/4 v11, 0x0

    .line 762
    return v11

    .line 763
    :cond_21
    move v11, v8

    .line 764
    invoke-virtual {v0}, Lo1/y0;->b()V

    .line 765
    .line 766
    .line 767
    return v11
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lo1/y0;->h:Z

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x1

    .line 8
    return p0
.end method

.method public final f(J)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lo1/y0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v0, "Callers should check whether the request is still valid before calling performMeasure()"

    .line 6
    .line 7
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Lo1/y0;->f:Z

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    const-string v0, "Request was already measured!"

    .line 15
    .line 16
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lo1/y0;->f:Z

    .line 21
    .line 22
    iget-object p0, p0, Lo1/y0;->e:Lt3/m1;

    .line 23
    .line 24
    if-eqz p0, :cond_3

    .line 25
    .line 26
    invoke-interface {p0}, Lt3/m1;->b()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v1, 0x0

    .line 31
    :goto_0
    if-ge v1, v0, :cond_2

    .line 32
    .line 33
    invoke-interface {p0, v1, p1, p2}, Lt3/m1;->c(IJ)V

    .line 34
    .line 35
    .line 36
    add-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    return-void

    .line 40
    :cond_3
    const-string p0, "performComposition() must be called before performMeasure()"

    .line 41
    .line 42
    invoke-static {p0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 43
    .line 44
    .line 45
    new-instance p0, La8/r0;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 48
    .line 49
    .line 50
    throw p0
.end method

.method public final g()Lo1/x0;
    .locals 4

    .line 1
    iget-object v0, p0, Lo1/y0;->e:Lt3/m1;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    new-instance v2, Lo1/w0;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct {v2, v1, v3}, Lo1/w0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0, v2}, Lt3/m1;->d(Lo1/w0;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Ljava/util/List;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    new-instance v1, Lo1/x0;

    .line 26
    .line 27
    invoke-direct {v1, p0, v0}, Lo1/x0;-><init>(Lo1/y0;Ljava/util/List;)V

    .line 28
    .line 29
    .line 30
    return-object v1

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    return-object p0

    .line 33
    :cond_1
    const-string p0, "Should precompose before resolving nested prefetch states"

    .line 34
    .line 35
    invoke-static {p0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 36
    .line 37
    .line 38
    new-instance p0, La8/r0;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public final h(JJ)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lo1/y0;->l:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const-wide/16 p3, 0x0

    .line 6
    .line 7
    :cond_0
    cmp-long p0, p1, p3

    .line 8
    .line 9
    if-lez p0, :cond_1

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_1
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final i()V
    .locals 8

    .line 1
    invoke-static {}, Lmy0/j;->b()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-wide v2, p0, Lo1/y0;->o:J

    .line 6
    .line 7
    invoke-static {v0, v1, v2, v3}, Lmy0/l;->b(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide v2

    .line 11
    const/4 v4, 0x1

    .line 12
    shr-long v5, v2, v4

    .line 13
    .line 14
    sget v7, Lmy0/c;->g:I

    .line 15
    .line 16
    long-to-int v2, v2

    .line 17
    and-int/2addr v2, v4

    .line 18
    if-nez v2, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const-wide v2, 0x8637bd05af6L

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    cmp-long v2, v5, v2

    .line 27
    .line 28
    if-lez v2, :cond_1

    .line 29
    .line 30
    const-wide v5, 0x7fffffffffffffffL

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    const-wide v2, -0x8637bd05af6L

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    cmp-long v2, v5, v2

    .line 42
    .line 43
    if-gez v2, :cond_2

    .line 44
    .line 45
    const-wide/high16 v5, -0x8000000000000000L

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    const v2, 0xf4240

    .line 49
    .line 50
    .line 51
    int-to-long v2, v2

    .line 52
    mul-long/2addr v5, v2

    .line 53
    :goto_0
    iput-wide v5, p0, Lo1/y0;->n:J

    .line 54
    .line 55
    iget-wide v2, p0, Lo1/y0;->m:J

    .line 56
    .line 57
    sub-long/2addr v2, v5

    .line 58
    iput-wide v2, p0, Lo1/y0;->m:J

    .line 59
    .line 60
    iput-wide v0, p0, Lo1/y0;->o:J

    .line 61
    .line 62
    const-string p0, "compose:lazy:prefetch:available_time_nanos"

    .line 63
    .line 64
    invoke-static {p0, v2, v3}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "HandleAndRequestImpl { index = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lo1/y0;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", constraints = "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lo1/y0;->d:Lt4/a;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", isComposed = "

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lo1/y0;->e()Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", isMeasured = "

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-boolean v1, p0, Lo1/y0;->f:Z

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, ", isCanceled = "

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    iget-boolean p0, p0, Lo1/y0;->g:Z

    .line 51
    .line 52
    const-string v1, " }"

    .line 53
    .line 54
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method
