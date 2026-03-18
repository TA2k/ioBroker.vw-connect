.class public final Lf2/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lt2/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lf2/c0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/c0;->e:Lt2/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lf2/c0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_1

    .line 31
    .line 32
    const/4 p2, 0x6

    .line 33
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 38
    .line 39
    sget-object v0, Lk1/k0;->a:Lk1/k0;

    .line 40
    .line 41
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 46
    .line 47
    .line 48
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 52
    .line 53
    check-cast p2, Ljava/lang/Number;

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    and-int/lit8 v0, p2, 0x3

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    const/4 v2, 0x1

    .line 63
    const/4 v3, 0x0

    .line 64
    if-eq v0, v1, :cond_2

    .line 65
    .line 66
    move v0, v2

    .line 67
    goto :goto_2

    .line 68
    :cond_2
    move v0, v3

    .line 69
    :goto_2
    and-int/2addr p2, v2

    .line 70
    check-cast p1, Ll2/t;

    .line 71
    .line 72
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    if-eqz p2, :cond_8

    .line 77
    .line 78
    const/high16 p2, 0x3f800000    # 1.0f

    .line 79
    .line 80
    float-to-double v0, p2

    .line 81
    const-wide/16 v4, 0x0

    .line 82
    .line 83
    cmpl-double v0, v0, v4

    .line 84
    .line 85
    if-lez v0, :cond_3

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_3
    const-string v0, "invalid weight; must be greater than zero"

    .line 89
    .line 90
    invoke-static {v0}, Ll1/a;->a(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :goto_3
    new-instance v4, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 94
    .line 95
    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 96
    .line 97
    .line 98
    cmpl-float v1, p2, v0

    .line 99
    .line 100
    if-lez v1, :cond_4

    .line 101
    .line 102
    move p2, v0

    .line 103
    :cond_4
    invoke-direct {v4, p2, v2}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 104
    .line 105
    .line 106
    int-to-float v5, v3

    .line 107
    int-to-float v7, v3

    .line 108
    const/4 v8, 0x0

    .line 109
    const/16 v9, 0xa

    .line 110
    .line 111
    const/4 v6, 0x0

    .line 112
    invoke-static/range {v4 .. v9}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 117
    .line 118
    invoke-static {v0, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    iget-wide v4, p1, Ll2/t;->T:J

    .line 123
    .line 124
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 137
    .line 138
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 142
    .line 143
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 144
    .line 145
    .line 146
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 147
    .line 148
    if-eqz v6, :cond_5

    .line 149
    .line 150
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 151
    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_5
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 155
    .line 156
    .line 157
    :goto_4
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 158
    .line 159
    invoke-static {v5, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 160
    .line 161
    .line 162
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 163
    .line 164
    invoke-static {v0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 165
    .line 166
    .line 167
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 168
    .line 169
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 170
    .line 171
    if-nez v4, :cond_6

    .line 172
    .line 173
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v4

    .line 177
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    if-nez v4, :cond_7

    .line 186
    .line 187
    :cond_6
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 188
    .line 189
    .line 190
    :cond_7
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 191
    .line 192
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 193
    .line 194
    .line 195
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 196
    .line 197
    invoke-static {v3, p0, p1, v2}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 198
    .line 199
    .line 200
    goto :goto_5

    .line 201
    :cond_8
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 202
    .line 203
    .line 204
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 205
    .line 206
    return-object p0

    .line 207
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 208
    .line 209
    check-cast p2, Ljava/lang/Number;

    .line 210
    .line 211
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 212
    .line 213
    .line 214
    move-result p2

    .line 215
    and-int/lit8 v0, p2, 0x3

    .line 216
    .line 217
    const/4 v1, 0x2

    .line 218
    const/4 v2, 0x1

    .line 219
    if-eq v0, v1, :cond_9

    .line 220
    .line 221
    move v0, v2

    .line 222
    goto :goto_6

    .line 223
    :cond_9
    const/4 v0, 0x0

    .line 224
    :goto_6
    and-int/2addr p2, v2

    .line 225
    check-cast p1, Ll2/t;

    .line 226
    .line 227
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 228
    .line 229
    .line 230
    move-result p2

    .line 231
    if-eqz p2, :cond_a

    .line 232
    .line 233
    sget p2, Lh2/f2;->b:F

    .line 234
    .line 235
    sget v0, Lh2/f2;->c:F

    .line 236
    .line 237
    new-instance v1, Lf2/c0;

    .line 238
    .line 239
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 240
    .line 241
    const/4 v2, 0x6

    .line 242
    invoke-direct {v1, p0, v2}, Lf2/c0;-><init>(Lt2/b;I)V

    .line 243
    .line 244
    .line 245
    const p0, -0x7606e600

    .line 246
    .line 247
    .line 248
    invoke-static {p0, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    const/16 v1, 0x1b6

    .line 253
    .line 254
    invoke-static {p2, v0, p0, p1, v1}, Lh2/j;->b(FFLt2/b;Ll2/o;I)V

    .line 255
    .line 256
    .line 257
    goto :goto_7

    .line 258
    :cond_a
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 259
    .line 260
    .line 261
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    return-object p0

    .line 264
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 265
    .line 266
    check-cast p2, Ljava/lang/Number;

    .line 267
    .line 268
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 269
    .line 270
    .line 271
    move-result p2

    .line 272
    const/4 v0, 0x0

    .line 273
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    and-int/lit8 v2, p2, 0x3

    .line 278
    .line 279
    const/4 v3, 0x2

    .line 280
    const/4 v4, 0x1

    .line 281
    if-eq v2, v3, :cond_b

    .line 282
    .line 283
    move v2, v4

    .line 284
    goto :goto_8

    .line 285
    :cond_b
    move v2, v0

    .line 286
    :goto_8
    and-int/2addr p2, v4

    .line 287
    check-cast p1, Ll2/t;

    .line 288
    .line 289
    invoke-virtual {p1, p2, v2}, Ll2/t;->O(IZ)Z

    .line 290
    .line 291
    .line 292
    move-result p2

    .line 293
    if-eqz p2, :cond_c

    .line 294
    .line 295
    const p2, 0x13395559

    .line 296
    .line 297
    .line 298
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 302
    .line 303
    .line 304
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 305
    .line 306
    invoke-virtual {p0, p1, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    goto :goto_9

    .line 310
    :cond_c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 311
    .line 312
    .line 313
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 314
    .line 315
    return-object p0

    .line 316
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 317
    .line 318
    check-cast p2, Ljava/lang/Number;

    .line 319
    .line 320
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 321
    .line 322
    .line 323
    move-result p2

    .line 324
    and-int/lit8 v0, p2, 0x3

    .line 325
    .line 326
    const/4 v1, 0x2

    .line 327
    const/4 v2, 0x0

    .line 328
    const/4 v3, 0x1

    .line 329
    if-eq v0, v1, :cond_d

    .line 330
    .line 331
    move v0, v3

    .line 332
    goto :goto_a

    .line 333
    :cond_d
    move v0, v2

    .line 334
    :goto_a
    and-int/2addr p2, v3

    .line 335
    check-cast p1, Ll2/t;

    .line 336
    .line 337
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 338
    .line 339
    .line 340
    move-result p2

    .line 341
    if-eqz p2, :cond_11

    .line 342
    .line 343
    sget-object p2, Lk1/j;->c:Lk1/e;

    .line 344
    .line 345
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 346
    .line 347
    invoke-static {p2, v0, p1, v2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 348
    .line 349
    .line 350
    move-result-object p2

    .line 351
    iget-wide v0, p1, Ll2/t;->T:J

    .line 352
    .line 353
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 354
    .line 355
    .line 356
    move-result v0

    .line 357
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 358
    .line 359
    .line 360
    move-result-object v1

    .line 361
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 362
    .line 363
    invoke-static {p1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 364
    .line 365
    .line 366
    move-result-object v2

    .line 367
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 368
    .line 369
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 370
    .line 371
    .line 372
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 373
    .line 374
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 375
    .line 376
    .line 377
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 378
    .line 379
    if-eqz v5, :cond_e

    .line 380
    .line 381
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 382
    .line 383
    .line 384
    goto :goto_b

    .line 385
    :cond_e
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 386
    .line 387
    .line 388
    :goto_b
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 389
    .line 390
    invoke-static {v4, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 391
    .line 392
    .line 393
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 394
    .line 395
    invoke-static {p2, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 396
    .line 397
    .line 398
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 399
    .line 400
    iget-boolean v1, p1, Ll2/t;->S:Z

    .line 401
    .line 402
    if-nez v1, :cond_f

    .line 403
    .line 404
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 409
    .line 410
    .line 411
    move-result-object v4

    .line 412
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 413
    .line 414
    .line 415
    move-result v1

    .line 416
    if-nez v1, :cond_10

    .line 417
    .line 418
    :cond_f
    invoke-static {v0, p1, v0, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 419
    .line 420
    .line 421
    :cond_10
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 422
    .line 423
    invoke-static {p2, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 424
    .line 425
    .line 426
    const/4 p2, 0x6

    .line 427
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 428
    .line 429
    .line 430
    move-result-object p2

    .line 431
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 432
    .line 433
    sget-object v0, Lk1/t;->a:Lk1/t;

    .line 434
    .line 435
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 439
    .line 440
    .line 441
    goto :goto_c

    .line 442
    :cond_11
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 443
    .line 444
    .line 445
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 446
    .line 447
    return-object p0

    .line 448
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 449
    .line 450
    check-cast p2, Ljava/lang/Number;

    .line 451
    .line 452
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 453
    .line 454
    .line 455
    move-result p2

    .line 456
    and-int/lit8 v0, p2, 0x3

    .line 457
    .line 458
    const/4 v1, 0x2

    .line 459
    const/4 v2, 0x0

    .line 460
    const/4 v3, 0x1

    .line 461
    if-eq v0, v1, :cond_12

    .line 462
    .line 463
    move v0, v3

    .line 464
    goto :goto_d

    .line 465
    :cond_12
    move v0, v2

    .line 466
    :goto_d
    and-int/2addr p2, v3

    .line 467
    check-cast p1, Ll2/t;

    .line 468
    .line 469
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 470
    .line 471
    .line 472
    move-result p2

    .line 473
    if-eqz p2, :cond_16

    .line 474
    .line 475
    sget-object p2, Lk1/j;->c:Lk1/e;

    .line 476
    .line 477
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 478
    .line 479
    invoke-static {p2, v0, p1, v2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 480
    .line 481
    .line 482
    move-result-object p2

    .line 483
    iget-wide v0, p1, Ll2/t;->T:J

    .line 484
    .line 485
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 486
    .line 487
    .line 488
    move-result v0

    .line 489
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 490
    .line 491
    .line 492
    move-result-object v1

    .line 493
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 494
    .line 495
    invoke-static {p1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 496
    .line 497
    .line 498
    move-result-object v2

    .line 499
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 500
    .line 501
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 502
    .line 503
    .line 504
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 505
    .line 506
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 507
    .line 508
    .line 509
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 510
    .line 511
    if-eqz v5, :cond_13

    .line 512
    .line 513
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 514
    .line 515
    .line 516
    goto :goto_e

    .line 517
    :cond_13
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 518
    .line 519
    .line 520
    :goto_e
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 521
    .line 522
    invoke-static {v4, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 523
    .line 524
    .line 525
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 526
    .line 527
    invoke-static {p2, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 528
    .line 529
    .line 530
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 531
    .line 532
    iget-boolean v1, p1, Ll2/t;->S:Z

    .line 533
    .line 534
    if-nez v1, :cond_14

    .line 535
    .line 536
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object v1

    .line 540
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 541
    .line 542
    .line 543
    move-result-object v4

    .line 544
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 545
    .line 546
    .line 547
    move-result v1

    .line 548
    if-nez v1, :cond_15

    .line 549
    .line 550
    :cond_14
    invoke-static {v0, p1, v0, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 551
    .line 552
    .line 553
    :cond_15
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 554
    .line 555
    invoke-static {p2, v2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 556
    .line 557
    .line 558
    const/4 p2, 0x6

    .line 559
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 560
    .line 561
    .line 562
    move-result-object p2

    .line 563
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 564
    .line 565
    sget-object v0, Lk1/t;->a:Lk1/t;

    .line 566
    .line 567
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 568
    .line 569
    .line 570
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 571
    .line 572
    .line 573
    goto :goto_f

    .line 574
    :cond_16
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 575
    .line 576
    .line 577
    :goto_f
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 578
    .line 579
    return-object p0

    .line 580
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 581
    .line 582
    check-cast p2, Ljava/lang/Number;

    .line 583
    .line 584
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 585
    .line 586
    .line 587
    move-result p2

    .line 588
    and-int/lit8 v0, p2, 0x3

    .line 589
    .line 590
    const/4 v1, 0x2

    .line 591
    const/4 v2, 0x1

    .line 592
    if-eq v0, v1, :cond_17

    .line 593
    .line 594
    move v0, v2

    .line 595
    goto :goto_10

    .line 596
    :cond_17
    const/4 v0, 0x0

    .line 597
    :goto_10
    and-int/2addr p2, v2

    .line 598
    check-cast p1, Ll2/t;

    .line 599
    .line 600
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 601
    .line 602
    .line 603
    move-result p2

    .line 604
    if-eqz p2, :cond_18

    .line 605
    .line 606
    sget p2, Lh2/j;->c:F

    .line 607
    .line 608
    sget v0, Lh2/j;->d:F

    .line 609
    .line 610
    new-instance v1, Lf2/c0;

    .line 611
    .line 612
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 613
    .line 614
    const/4 v2, 0x2

    .line 615
    invoke-direct {v1, p0, v2}, Lf2/c0;-><init>(Lt2/b;I)V

    .line 616
    .line 617
    .line 618
    const p0, -0x1b6383e2

    .line 619
    .line 620
    .line 621
    invoke-static {p0, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 622
    .line 623
    .line 624
    move-result-object p0

    .line 625
    const/16 v1, 0x1b6

    .line 626
    .line 627
    invoke-static {p2, v0, p0, p1, v1}, Lh2/j;->b(FFLt2/b;Ll2/o;I)V

    .line 628
    .line 629
    .line 630
    goto :goto_11

    .line 631
    :cond_18
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 632
    .line 633
    .line 634
    :goto_11
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 635
    .line 636
    return-object p0

    .line 637
    :pswitch_6
    check-cast p1, Ll2/o;

    .line 638
    .line 639
    check-cast p2, Ljava/lang/Number;

    .line 640
    .line 641
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 642
    .line 643
    .line 644
    move-result p2

    .line 645
    const/4 v0, 0x0

    .line 646
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 647
    .line 648
    .line 649
    move-result-object v1

    .line 650
    and-int/lit8 v2, p2, 0x3

    .line 651
    .line 652
    const/4 v3, 0x2

    .line 653
    const/4 v4, 0x1

    .line 654
    if-eq v2, v3, :cond_19

    .line 655
    .line 656
    move v2, v4

    .line 657
    goto :goto_12

    .line 658
    :cond_19
    move v2, v0

    .line 659
    :goto_12
    and-int/2addr p2, v4

    .line 660
    check-cast p1, Ll2/t;

    .line 661
    .line 662
    invoke-virtual {p1, p2, v2}, Ll2/t;->O(IZ)Z

    .line 663
    .line 664
    .line 665
    move-result p2

    .line 666
    if-eqz p2, :cond_1a

    .line 667
    .line 668
    const p2, -0x41afc885

    .line 669
    .line 670
    .line 671
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 672
    .line 673
    .line 674
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 675
    .line 676
    .line 677
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 678
    .line 679
    invoke-virtual {p0, p1, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 680
    .line 681
    .line 682
    goto :goto_13

    .line 683
    :cond_1a
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 684
    .line 685
    .line 686
    :goto_13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 687
    .line 688
    return-object p0

    .line 689
    :pswitch_7
    check-cast p1, Ll2/o;

    .line 690
    .line 691
    check-cast p2, Ljava/lang/Number;

    .line 692
    .line 693
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 694
    .line 695
    .line 696
    move-result p2

    .line 697
    and-int/lit8 v0, p2, 0x3

    .line 698
    .line 699
    const/4 v1, 0x2

    .line 700
    const/4 v2, 0x0

    .line 701
    const/4 v3, 0x1

    .line 702
    if-eq v0, v1, :cond_1b

    .line 703
    .line 704
    move v0, v3

    .line 705
    goto :goto_14

    .line 706
    :cond_1b
    move v0, v2

    .line 707
    :goto_14
    and-int/2addr p2, v3

    .line 708
    check-cast p1, Ll2/t;

    .line 709
    .line 710
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 711
    .line 712
    .line 713
    move-result p2

    .line 714
    if-eqz p2, :cond_1e

    .line 715
    .line 716
    const p2, -0x64d7dfd1

    .line 717
    .line 718
    .line 719
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 720
    .line 721
    .line 722
    sget-object p2, Lf2/k;->a:Ll2/e0;

    .line 723
    .line 724
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 725
    .line 726
    .line 727
    move-result-object p2

    .line 728
    check-cast p2, Le3/s;

    .line 729
    .line 730
    iget-wide v0, p2, Le3/s;->a:J

    .line 731
    .line 732
    sget-object p2, Lf2/h;->a:Ll2/u2;

    .line 733
    .line 734
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    move-result-object p2

    .line 738
    check-cast p2, Lf2/g;

    .line 739
    .line 740
    invoke-virtual {p2}, Lf2/g;->d()Z

    .line 741
    .line 742
    .line 743
    move-result p2

    .line 744
    const-wide/high16 v3, 0x3fe0000000000000L    # 0.5

    .line 745
    .line 746
    if-eqz p2, :cond_1c

    .line 747
    .line 748
    invoke-static {v0, v1}, Le3/j0;->r(J)F

    .line 749
    .line 750
    .line 751
    move-result p2

    .line 752
    float-to-double v0, p2

    .line 753
    cmpl-double p2, v0, v3

    .line 754
    .line 755
    if-lez p2, :cond_1d

    .line 756
    .line 757
    goto :goto_15

    .line 758
    :cond_1c
    invoke-static {v0, v1}, Le3/j0;->r(J)F

    .line 759
    .line 760
    .line 761
    move-result p2

    .line 762
    float-to-double v0, p2

    .line 763
    cmpg-double p2, v0, v3

    .line 764
    .line 765
    if-gez p2, :cond_1d

    .line 766
    .line 767
    :goto_15
    const/high16 p2, 0x3f800000    # 1.0f

    .line 768
    .line 769
    goto :goto_16

    .line 770
    :cond_1d
    const p2, 0x3f5eb852    # 0.87f

    .line 771
    .line 772
    .line 773
    :goto_16
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 774
    .line 775
    .line 776
    sget-object v0, Lf2/i;->a:Ll2/e0;

    .line 777
    .line 778
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 779
    .line 780
    .line 781
    move-result-object p2

    .line 782
    invoke-virtual {v0, p2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 783
    .line 784
    .line 785
    move-result-object p2

    .line 786
    new-instance v0, Lf2/c0;

    .line 787
    .line 788
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 789
    .line 790
    const/4 v1, 0x0

    .line 791
    invoke-direct {v0, p0, v1}, Lf2/c0;-><init>(Lt2/b;I)V

    .line 792
    .line 793
    .line 794
    const p0, -0x125dfbb5

    .line 795
    .line 796
    .line 797
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 798
    .line 799
    .line 800
    move-result-object p0

    .line 801
    const/16 v0, 0x38

    .line 802
    .line 803
    invoke-static {p2, p0, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 804
    .line 805
    .line 806
    goto :goto_17

    .line 807
    :cond_1e
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 808
    .line 809
    .line 810
    :goto_17
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 811
    .line 812
    return-object p0

    .line 813
    :pswitch_8
    check-cast p1, Ll2/o;

    .line 814
    .line 815
    check-cast p2, Ljava/lang/Number;

    .line 816
    .line 817
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 818
    .line 819
    .line 820
    move-result p2

    .line 821
    and-int/lit8 v0, p2, 0x3

    .line 822
    .line 823
    const/4 v1, 0x2

    .line 824
    const/4 v2, 0x0

    .line 825
    const/4 v3, 0x1

    .line 826
    if-eq v0, v1, :cond_1f

    .line 827
    .line 828
    move v0, v3

    .line 829
    goto :goto_18

    .line 830
    :cond_1f
    move v0, v2

    .line 831
    :goto_18
    and-int/2addr p2, v3

    .line 832
    check-cast p1, Ll2/t;

    .line 833
    .line 834
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 835
    .line 836
    .line 837
    move-result p2

    .line 838
    if-eqz p2, :cond_20

    .line 839
    .line 840
    sget-object p2, Lk1/i1;->a:Lk1/i1;

    .line 841
    .line 842
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 843
    .line 844
    .line 845
    move-result-object v0

    .line 846
    iget-object p0, p0, Lf2/c0;->e:Lt2/b;

    .line 847
    .line 848
    invoke-virtual {p0, p2, p1, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 849
    .line 850
    .line 851
    goto :goto_19

    .line 852
    :cond_20
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 853
    .line 854
    .line 855
    :goto_19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 856
    .line 857
    return-object p0

    .line 858
    nop

    .line 859
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
