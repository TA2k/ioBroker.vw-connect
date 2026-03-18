.class public final synthetic Lpr0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;ILay0/k;II)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lpr0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lpr0/c;->h:Ljava/lang/Object;

    iput p2, p0, Lpr0/c;->e:I

    iput-object p3, p0, Lpr0/c;->i:Llx0/e;

    iput p4, p0, Lpr0/c;->f:I

    iput p5, p0, Lpr0/c;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lor0/a;IIILay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lpr0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lpr0/c;->h:Ljava/lang/Object;

    iput p2, p0, Lpr0/c;->e:I

    iput p3, p0, Lpr0/c;->f:I

    iput p4, p0, Lpr0/c;->g:I

    iput-object p5, p0, Lpr0/c;->i:Llx0/e;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lpr0/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lpr0/c;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Ljava/util/List;

    .line 12
    .line 13
    iget-object v1, v0, Lpr0/c;->i:Llx0/e;

    .line 14
    .line 15
    move-object v4, v1

    .line 16
    check-cast v4, Lay0/k;

    .line 17
    .line 18
    move-object/from16 v5, p1

    .line 19
    .line 20
    check-cast v5, Ll2/o;

    .line 21
    .line 22
    move-object/from16 v1, p2

    .line 23
    .line 24
    check-cast v1, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget v1, v0, Lpr0/c;->f:I

    .line 30
    .line 31
    or-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    iget v3, v0, Lpr0/c;->e:I

    .line 38
    .line 39
    iget v7, v0, Lpr0/c;->g:I

    .line 40
    .line 41
    invoke-static/range {v2 .. v7}, Lx80/a;->b(Ljava/util/List;ILay0/k;Ll2/o;II)V

    .line 42
    .line 43
    .line 44
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object v0

    .line 47
    :pswitch_0
    iget-object v1, v0, Lpr0/c;->h:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v1, Lor0/a;

    .line 50
    .line 51
    iget-object v2, v0, Lpr0/c;->i:Llx0/e;

    .line 52
    .line 53
    move-object v5, v2

    .line 54
    check-cast v5, Lay0/a;

    .line 55
    .line 56
    move-object/from16 v2, p1

    .line 57
    .line 58
    check-cast v2, Ll2/o;

    .line 59
    .line 60
    move-object/from16 v3, p2

    .line 61
    .line 62
    check-cast v3, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    and-int/lit8 v4, v3, 0x3

    .line 69
    .line 70
    const/4 v6, 0x2

    .line 71
    const/4 v11, 0x1

    .line 72
    const/4 v7, 0x0

    .line 73
    if-eq v4, v6, :cond_0

    .line 74
    .line 75
    move v4, v11

    .line 76
    goto :goto_0

    .line 77
    :cond_0
    move v4, v7

    .line 78
    :goto_0
    and-int/2addr v3, v11

    .line 79
    move-object v15, v2

    .line 80
    check-cast v15, Ll2/t;

    .line 81
    .line 82
    invoke-virtual {v15, v3, v4}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-eqz v2, :cond_9

    .line 87
    .line 88
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 89
    .line 90
    invoke-static {v2, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    iget-wide v3, v15, Ll2/t;->T:J

    .line 95
    .line 96
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 105
    .line 106
    invoke-static {v15, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 111
    .line 112
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 116
    .line 117
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 118
    .line 119
    .line 120
    iget-boolean v10, v15, Ll2/t;->S:Z

    .line 121
    .line 122
    if-eqz v10, :cond_1

    .line 123
    .line 124
    invoke-virtual {v15, v9}, Ll2/t;->l(Lay0/a;)V

    .line 125
    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_1
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 129
    .line 130
    .line 131
    :goto_1
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 132
    .line 133
    invoke-static {v10, v2, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    .line 135
    .line 136
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 137
    .line 138
    invoke-static {v2, v4, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 142
    .line 143
    iget-boolean v12, v15, Ll2/t;->S:Z

    .line 144
    .line 145
    if-nez v12, :cond_2

    .line 146
    .line 147
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v12

    .line 151
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 152
    .line 153
    .line 154
    move-result-object v13

    .line 155
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v12

    .line 159
    if-nez v12, :cond_3

    .line 160
    .line 161
    :cond_2
    invoke-static {v3, v15, v3, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 162
    .line 163
    .line 164
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 165
    .line 166
    invoke-static {v3, v8, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 167
    .line 168
    .line 169
    iget-boolean v1, v1, Lor0/a;->a:Z

    .line 170
    .line 171
    if-eqz v1, :cond_4

    .line 172
    .line 173
    const v1, -0x52e6d7d1

    .line 174
    .line 175
    .line 176
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 177
    .line 178
    .line 179
    const/4 v12, 0x6

    .line 180
    const/4 v13, 0x6

    .line 181
    const-string v14, "test_drive_player"

    .line 182
    .line 183
    const/16 v16, 0x0

    .line 184
    .line 185
    const/16 v17, 0x0

    .line 186
    .line 187
    invoke-static/range {v12 .. v17}, Llp/qa;->a(IILjava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 188
    .line 189
    .line 190
    :goto_2
    invoke-virtual {v15, v7}, Ll2/t;->q(Z)V

    .line 191
    .line 192
    .line 193
    goto :goto_3

    .line 194
    :cond_4
    const v1, -0x5315283a

    .line 195
    .line 196
    .line 197
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 198
    .line 199
    .line 200
    goto :goto_2

    .line 201
    :goto_3
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 202
    .line 203
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    check-cast v8, Lj91/c;

    .line 208
    .line 209
    iget v8, v8, Lj91/c;->d:F

    .line 210
    .line 211
    invoke-static {v6, v8}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 212
    .line 213
    .line 214
    move-result-object v8

    .line 215
    sget-object v12, Lk1/j;->c:Lk1/e;

    .line 216
    .line 217
    sget-object v13, Lx2/c;->p:Lx2/h;

    .line 218
    .line 219
    invoke-static {v12, v13, v15, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 220
    .line 221
    .line 222
    move-result-object v7

    .line 223
    iget-wide v12, v15, Ll2/t;->T:J

    .line 224
    .line 225
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 226
    .line 227
    .line 228
    move-result v12

    .line 229
    invoke-virtual {v15}, Ll2/t;->m()Ll2/p1;

    .line 230
    .line 231
    .line 232
    move-result-object v13

    .line 233
    invoke-static {v15, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 234
    .line 235
    .line 236
    move-result-object v8

    .line 237
    invoke-virtual {v15}, Ll2/t;->c0()V

    .line 238
    .line 239
    .line 240
    iget-boolean v14, v15, Ll2/t;->S:Z

    .line 241
    .line 242
    if-eqz v14, :cond_5

    .line 243
    .line 244
    invoke-virtual {v15, v9}, Ll2/t;->l(Lay0/a;)V

    .line 245
    .line 246
    .line 247
    goto :goto_4

    .line 248
    :cond_5
    invoke-virtual {v15}, Ll2/t;->m0()V

    .line 249
    .line 250
    .line 251
    :goto_4
    invoke-static {v10, v7, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 252
    .line 253
    .line 254
    invoke-static {v2, v13, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 255
    .line 256
    .line 257
    iget-boolean v2, v15, Ll2/t;->S:Z

    .line 258
    .line 259
    if-nez v2, :cond_6

    .line 260
    .line 261
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 266
    .line 267
    .line 268
    move-result-object v7

    .line 269
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result v2

    .line 273
    if-nez v2, :cond_7

    .line 274
    .line 275
    :cond_6
    invoke-static {v12, v15, v12, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 276
    .line 277
    .line 278
    :cond_7
    invoke-static {v3, v8, v15}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 279
    .line 280
    .line 281
    const/high16 v2, 0x3f800000    # 1.0f

    .line 282
    .line 283
    float-to-double v3, v2

    .line 284
    const-wide/16 v7, 0x0

    .line 285
    .line 286
    cmpl-double v3, v3, v7

    .line 287
    .line 288
    if-lez v3, :cond_8

    .line 289
    .line 290
    goto :goto_5

    .line 291
    :cond_8
    const-string v3, "invalid weight; must be greater than zero"

    .line 292
    .line 293
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    :goto_5
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 297
    .line 298
    invoke-direct {v3, v2, v11}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 299
    .line 300
    .line 301
    invoke-static {v15, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 302
    .line 303
    .line 304
    const-string v2, "test_drive_card_title"

    .line 305
    .line 306
    invoke-static {v6, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 307
    .line 308
    .line 309
    move-result-object v14

    .line 310
    iget v2, v0, Lpr0/c;->e:I

    .line 311
    .line 312
    invoke-static {v15, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v12

    .line 316
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 317
    .line 318
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v3

    .line 322
    check-cast v3, Lj91/f;

    .line 323
    .line 324
    invoke-virtual {v3}, Lj91/f;->j()Lg4/p0;

    .line 325
    .line 326
    .line 327
    move-result-object v13

    .line 328
    move-object/from16 v30, v15

    .line 329
    .line 330
    sget-wide v15, Le3/s;->e:J

    .line 331
    .line 332
    const/16 v32, 0x6180

    .line 333
    .line 334
    const v33, 0xaff0

    .line 335
    .line 336
    .line 337
    const-wide/16 v17, 0x0

    .line 338
    .line 339
    const/16 v19, 0x0

    .line 340
    .line 341
    const-wide/16 v20, 0x0

    .line 342
    .line 343
    const/16 v22, 0x0

    .line 344
    .line 345
    const/16 v23, 0x0

    .line 346
    .line 347
    const-wide/16 v24, 0x0

    .line 348
    .line 349
    const/16 v26, 0x2

    .line 350
    .line 351
    const/16 v27, 0x0

    .line 352
    .line 353
    const/16 v28, 0x2

    .line 354
    .line 355
    const/16 v29, 0x0

    .line 356
    .line 357
    const/16 v31, 0xd80

    .line 358
    .line 359
    invoke-static/range {v12 .. v33}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 360
    .line 361
    .line 362
    move-object/from16 v15, v30

    .line 363
    .line 364
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v3

    .line 368
    check-cast v3, Lj91/c;

    .line 369
    .line 370
    iget v3, v3, Lj91/c;->c:F

    .line 371
    .line 372
    const-string v4, "test_drive_card_body"

    .line 373
    .line 374
    invoke-static {v6, v3, v15, v6, v4}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 375
    .line 376
    .line 377
    move-result-object v14

    .line 378
    iget v3, v0, Lpr0/c;->f:I

    .line 379
    .line 380
    invoke-static {v15, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object v12

    .line 384
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v2

    .line 388
    check-cast v2, Lj91/f;

    .line 389
    .line 390
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 391
    .line 392
    .line 393
    move-result-object v13

    .line 394
    const-wide v2, 0xffc4c6c7L

    .line 395
    .line 396
    .line 397
    .line 398
    .line 399
    invoke-static {v2, v3}, Le3/j0;->e(J)J

    .line 400
    .line 401
    .line 402
    move-result-wide v2

    .line 403
    const/16 v32, 0x0

    .line 404
    .line 405
    const v33, 0xfff0

    .line 406
    .line 407
    .line 408
    const/16 v26, 0x0

    .line 409
    .line 410
    const/16 v28, 0x0

    .line 411
    .line 412
    move-wide v15, v2

    .line 413
    invoke-static/range {v12 .. v33}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 414
    .line 415
    .line 416
    move-object/from16 v15, v30

    .line 417
    .line 418
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v1

    .line 422
    check-cast v1, Lj91/c;

    .line 423
    .line 424
    iget v1, v1, Lj91/c;->d:F

    .line 425
    .line 426
    const-string v2, "test_drive_card_button"

    .line 427
    .line 428
    invoke-static {v6, v1, v15, v6, v2}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 429
    .line 430
    .line 431
    move-result-object v9

    .line 432
    iget v0, v0, Lpr0/c;->g:I

    .line 433
    .line 434
    invoke-static {v15, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 435
    .line 436
    .line 437
    move-result-object v7

    .line 438
    const/16 v3, 0x180

    .line 439
    .line 440
    const/16 v4, 0x18

    .line 441
    .line 442
    const/4 v6, 0x0

    .line 443
    const/4 v10, 0x0

    .line 444
    move-object v8, v15

    .line 445
    invoke-static/range {v3 .. v10}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 446
    .line 447
    .line 448
    invoke-virtual {v15, v11}, Ll2/t;->q(Z)V

    .line 449
    .line 450
    .line 451
    invoke-virtual {v15, v11}, Ll2/t;->q(Z)V

    .line 452
    .line 453
    .line 454
    goto :goto_6

    .line 455
    :cond_9
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 456
    .line 457
    .line 458
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 459
    .line 460
    return-object v0

    .line 461
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
