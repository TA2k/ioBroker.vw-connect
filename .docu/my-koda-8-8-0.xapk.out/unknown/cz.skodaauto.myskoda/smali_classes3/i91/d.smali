.class public final synthetic Li91/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(FLay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li91/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li91/d;->e:F

    iput-object p2, p0, Li91/d;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/ArrayList;F)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Li91/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/d;->f:Ljava/lang/Object;

    iput p2, p0, Li91/d;->e:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/d;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li91/d;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lay0/k;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Landroidx/compose/foundation/lazy/a;

    .line 15
    .line 16
    move-object/from16 v3, p2

    .line 17
    .line 18
    check-cast v3, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v4, p3

    .line 21
    .line 22
    check-cast v4, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    const-string v5, "$this$item"

    .line 29
    .line 30
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    and-int/lit8 v2, v4, 0x11

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    const/16 v6, 0x10

    .line 37
    .line 38
    if-eq v2, v6, :cond_0

    .line 39
    .line 40
    move v2, v5

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v2, 0x0

    .line 43
    :goto_0
    and-int/2addr v4, v5

    .line 44
    move-object v12, v3

    .line 45
    check-cast v12, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {v12, v4, v2}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-eqz v2, :cond_6

    .line 52
    .line 53
    const/16 v2, 0x20

    .line 54
    .line 55
    int-to-float v2, v2

    .line 56
    int-to-float v3, v6

    .line 57
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    iget v0, v0, Li91/d;->e:F

    .line 60
    .line 61
    invoke-static {v4, v3, v2, v3, v0}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const/high16 v2, 0x3f800000    # 1.0f

    .line 66
    .line 67
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    const-string v2, "upgrade_follow_up_text"

    .line 72
    .line 73
    invoke-static {v0, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sget-object v2, Lk1/j;->g:Lk1/f;

    .line 78
    .line 79
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 80
    .line 81
    const/16 v6, 0x36

    .line 82
    .line 83
    invoke-static {v2, v3, v12, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    iget-wide v6, v12, Ll2/t;->T:J

    .line 88
    .line 89
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    invoke-static {v12, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 102
    .line 103
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 107
    .line 108
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 109
    .line 110
    .line 111
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 112
    .line 113
    if-eqz v8, :cond_1

    .line 114
    .line 115
    invoke-virtual {v12, v7}, Ll2/t;->l(Lay0/a;)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_1
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 120
    .line 121
    .line 122
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 123
    .line 124
    invoke-static {v7, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 125
    .line 126
    .line 127
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 128
    .line 129
    invoke-static {v2, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 133
    .line 134
    iget-boolean v6, v12, Ll2/t;->S:Z

    .line 135
    .line 136
    if-nez v6, :cond_2

    .line 137
    .line 138
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object v7

    .line 146
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v6

    .line 150
    if-nez v6, :cond_3

    .line 151
    .line 152
    :cond_2
    invoke-static {v3, v12, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 153
    .line 154
    .line 155
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 156
    .line 157
    invoke-static {v2, v0, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 158
    .line 159
    .line 160
    const v0, 0x7f120a92

    .line 161
    .line 162
    .line 163
    invoke-static {v12, v0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v11

    .line 167
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    if-nez v0, :cond_4

    .line 176
    .line 177
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 178
    .line 179
    if-ne v2, v0, :cond_5

    .line 180
    .line 181
    :cond_4
    new-instance v2, Lok/a;

    .line 182
    .line 183
    const/16 v0, 0x17

    .line 184
    .line 185
    invoke-direct {v2, v0, v1}, Lok/a;-><init>(ILay0/k;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v12, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    :cond_5
    move-object v9, v2

    .line 192
    check-cast v9, Lay0/a;

    .line 193
    .line 194
    const-string v0, "upgrade_follow_up_cta"

    .line 195
    .line 196
    invoke-static {v4, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 197
    .line 198
    .line 199
    move-result-object v13

    .line 200
    const/16 v7, 0x180

    .line 201
    .line 202
    const/16 v8, 0x18

    .line 203
    .line 204
    const/4 v10, 0x0

    .line 205
    const/4 v14, 0x0

    .line 206
    invoke-static/range {v7 .. v14}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 210
    .line 211
    .line 212
    goto :goto_2

    .line 213
    :cond_6
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 214
    .line 215
    .line 216
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 217
    .line 218
    return-object v0

    .line 219
    :pswitch_0
    iget-object v1, v0, Li91/d;->f:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v1, Ljava/util/ArrayList;

    .line 222
    .line 223
    move-object/from16 v2, p1

    .line 224
    .line 225
    check-cast v2, Lk1/h1;

    .line 226
    .line 227
    move-object/from16 v3, p2

    .line 228
    .line 229
    check-cast v3, Ll2/o;

    .line 230
    .line 231
    move-object/from16 v4, p3

    .line 232
    .line 233
    check-cast v4, Ljava/lang/Integer;

    .line 234
    .line 235
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 236
    .line 237
    .line 238
    move-result v4

    .line 239
    const-string v5, "$this$NavigationBar"

    .line 240
    .line 241
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    and-int/lit8 v5, v4, 0x6

    .line 245
    .line 246
    if-nez v5, :cond_8

    .line 247
    .line 248
    move-object v5, v3

    .line 249
    check-cast v5, Ll2/t;

    .line 250
    .line 251
    invoke-virtual {v5, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v5

    .line 255
    if-eqz v5, :cond_7

    .line 256
    .line 257
    const/4 v5, 0x4

    .line 258
    goto :goto_3

    .line 259
    :cond_7
    const/4 v5, 0x2

    .line 260
    :goto_3
    or-int/2addr v4, v5

    .line 261
    :cond_8
    move/from16 v18, v4

    .line 262
    .line 263
    and-int/lit8 v4, v18, 0x13

    .line 264
    .line 265
    const/16 v5, 0x12

    .line 266
    .line 267
    const/4 v6, 0x0

    .line 268
    if-eq v4, v5, :cond_9

    .line 269
    .line 270
    const/4 v4, 0x1

    .line 271
    goto :goto_4

    .line 272
    :cond_9
    move v4, v6

    .line 273
    :goto_4
    and-int/lit8 v5, v18, 0x1

    .line 274
    .line 275
    check-cast v3, Ll2/t;

    .line 276
    .line 277
    invoke-virtual {v3, v5, v4}, Ll2/t;->O(IZ)Z

    .line 278
    .line 279
    .line 280
    move-result v4

    .line 281
    if-eqz v4, :cond_b

    .line 282
    .line 283
    const/4 v4, 0x5

    .line 284
    invoke-static {v1, v4}, Lmx0/q;->q0(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    check-cast v1, Ljava/lang/Iterable;

    .line 289
    .line 290
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 291
    .line 292
    .line 293
    move-result-object v1

    .line 294
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    if-eqz v4, :cond_c

    .line 299
    .line 300
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v4

    .line 304
    add-int/lit8 v19, v6, 0x1

    .line 305
    .line 306
    if-ltz v6, :cond_a

    .line 307
    .line 308
    check-cast v4, Li91/g1;

    .line 309
    .line 310
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 311
    .line 312
    .line 313
    new-instance v5, Ljava/lang/StringBuilder;

    .line 314
    .line 315
    const-string v7, "navigation_action_"

    .line 316
    .line 317
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 318
    .line 319
    .line 320
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 321
    .line 322
    .line 323
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    const-string v7, "defaultTestTag"

    .line 328
    .line 329
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 333
    .line 334
    invoke-static {v7, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 335
    .line 336
    .line 337
    move-result-object v5

    .line 338
    iget-boolean v7, v4, Li91/g1;->d:Z

    .line 339
    .line 340
    iget-object v8, v4, Li91/g1;->e:Lay0/a;

    .line 341
    .line 342
    sget-object v9, Lj91/h;->a:Ll2/u2;

    .line 343
    .line 344
    invoke-virtual {v3, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v10

    .line 348
    check-cast v10, Lj91/e;

    .line 349
    .line 350
    invoke-virtual {v10}, Lj91/e;->e()J

    .line 351
    .line 352
    .line 353
    move-result-wide v11

    .line 354
    invoke-virtual {v3, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v9

    .line 358
    check-cast v9, Lj91/e;

    .line 359
    .line 360
    invoke-virtual {v9}, Lj91/e;->q()J

    .line 361
    .line 362
    .line 363
    move-result-wide v13

    .line 364
    new-instance v9, Lh2/y5;

    .line 365
    .line 366
    const/16 v10, 0xe

    .line 367
    .line 368
    invoke-direct {v9, v4, v10}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 369
    .line 370
    .line 371
    const v10, 0x3d83e9f7

    .line 372
    .line 373
    .line 374
    invoke-static {v10, v3, v9}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 375
    .line 376
    .line 377
    move-result-object v9

    .line 378
    new-instance v10, Ld90/h;

    .line 379
    .line 380
    const/4 v15, 0x4

    .line 381
    invoke-direct {v10, v4, v6, v15}, Ld90/h;-><init>(Ljava/lang/Object;II)V

    .line 382
    .line 383
    .line 384
    const v4, 0x72e6b7a

    .line 385
    .line 386
    .line 387
    invoke-static {v4, v3, v10}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 388
    .line 389
    .line 390
    move-result-object v4

    .line 391
    and-int/lit8 v6, v18, 0xe

    .line 392
    .line 393
    const v10, 0x180c00

    .line 394
    .line 395
    .line 396
    or-int v17, v6, v10

    .line 397
    .line 398
    move-object/from16 v16, v3

    .line 399
    .line 400
    move v3, v7

    .line 401
    const/4 v7, 0x0

    .line 402
    move-object v6, v5

    .line 403
    move-object v5, v9

    .line 404
    const/4 v9, 0x0

    .line 405
    const/4 v10, 0x0

    .line 406
    iget v15, v0, Li91/d;->e:F

    .line 407
    .line 408
    move-object/from16 v20, v8

    .line 409
    .line 410
    move-object v8, v4

    .line 411
    move-object/from16 v4, v20

    .line 412
    .line 413
    invoke-static/range {v2 .. v17}, Li91/j0;->l(Lk1/h1;ZLay0/a;Lt2/b;Lx2/s;ZLay0/n;ZLi1/l;JJFLl2/o;I)V

    .line 414
    .line 415
    .line 416
    move-object/from16 v3, v16

    .line 417
    .line 418
    move/from16 v6, v19

    .line 419
    .line 420
    goto :goto_5

    .line 421
    :cond_a
    invoke-static {}, Ljp/k1;->r()V

    .line 422
    .line 423
    .line 424
    const/4 v0, 0x0

    .line 425
    throw v0

    .line 426
    :cond_b
    move-object/from16 v16, v3

    .line 427
    .line 428
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 429
    .line 430
    .line 431
    :cond_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 432
    .line 433
    return-object v0

    .line 434
    nop

    .line 435
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
