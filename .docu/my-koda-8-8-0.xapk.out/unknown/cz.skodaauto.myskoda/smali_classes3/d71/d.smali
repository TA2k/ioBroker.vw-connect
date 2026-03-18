.class public final synthetic Ld71/d;
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
    iput p2, p0, Ld71/d;->d:I

    iput-object p1, p0, Ld71/d;->e:Lt2/b;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lt2/b;II)V
    .locals 0

    .line 2
    iput p3, p0, Ld71/d;->d:I

    iput-object p1, p0, Ld71/d;->e:Lt2/b;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ld71/d;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

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
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x1

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v2

    .line 24
    :goto_0
    and-int/2addr p2, v3

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_1

    .line 32
    .line 33
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 38
    .line 39
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 44
    .line 45
    .line 46
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    const/4 p2, 0x7

    .line 53
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 58
    .line 59
    invoke-static {p0, p1, p2}, Lzb/l;->a(Lt2/b;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 66
    .line 67
    .line 68
    move-result p2

    .line 69
    and-int/lit8 v0, p2, 0x3

    .line 70
    .line 71
    const/4 v1, 0x2

    .line 72
    const/4 v2, 0x0

    .line 73
    const/4 v3, 0x1

    .line 74
    if-eq v0, v1, :cond_2

    .line 75
    .line 76
    move v0, v3

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    move v0, v2

    .line 79
    :goto_2
    and-int/2addr p2, v3

    .line 80
    check-cast p1, Ll2/t;

    .line 81
    .line 82
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result p2

    .line 86
    if-eqz p2, :cond_3

    .line 87
    .line 88
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 93
    .line 94
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 99
    .line 100
    .line 101
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    and-int/lit8 v0, p2, 0x3

    .line 109
    .line 110
    const/4 v1, 0x2

    .line 111
    const/4 v2, 0x1

    .line 112
    const/4 v3, 0x0

    .line 113
    if-eq v0, v1, :cond_4

    .line 114
    .line 115
    move v0, v2

    .line 116
    goto :goto_4

    .line 117
    :cond_4
    move v0, v3

    .line 118
    :goto_4
    and-int/2addr p2, v2

    .line 119
    check-cast p1, Ll2/t;

    .line 120
    .line 121
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    if-eqz p2, :cond_5

    .line 126
    .line 127
    const p2, 0x59f86bca

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 131
    .line 132
    .line 133
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 138
    .line 139
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 143
    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 147
    .line 148
    .line 149
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    and-int/lit8 v0, p2, 0x3

    .line 157
    .line 158
    const/4 v1, 0x2

    .line 159
    const/4 v2, 0x0

    .line 160
    const/4 v3, 0x1

    .line 161
    if-eq v0, v1, :cond_6

    .line 162
    .line 163
    move v0, v3

    .line 164
    goto :goto_6

    .line 165
    :cond_6
    move v0, v2

    .line 166
    :goto_6
    and-int/2addr p2, v3

    .line 167
    check-cast p1, Ll2/t;

    .line 168
    .line 169
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 170
    .line 171
    .line 172
    move-result p2

    .line 173
    if-eqz p2, :cond_7

    .line 174
    .line 175
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 176
    .line 177
    .line 178
    move-result-object p2

    .line 179
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 180
    .line 181
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    goto :goto_7

    .line 185
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 186
    .line 187
    .line 188
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 192
    .line 193
    .line 194
    move-result p2

    .line 195
    and-int/lit8 v0, p2, 0x3

    .line 196
    .line 197
    const/4 v1, 0x2

    .line 198
    const/4 v2, 0x0

    .line 199
    const/4 v3, 0x1

    .line 200
    if-eq v0, v1, :cond_8

    .line 201
    .line 202
    move v0, v3

    .line 203
    goto :goto_8

    .line 204
    :cond_8
    move v0, v2

    .line 205
    :goto_8
    and-int/2addr p2, v3

    .line 206
    check-cast p1, Ll2/t;

    .line 207
    .line 208
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    if-eqz p2, :cond_c

    .line 213
    .line 214
    const/16 p2, 0x40

    .line 215
    .line 216
    int-to-float p2, p2

    .line 217
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 218
    .line 219
    invoke-static {v0, p2, p2}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 220
    .line 221
    .line 222
    move-result-object p2

    .line 223
    sget-object v0, Lx2/c;->h:Lx2/j;

    .line 224
    .line 225
    invoke-static {v0, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    iget-wide v4, p1, Ll2/t;->T:J

    .line 230
    .line 231
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 232
    .line 233
    .line 234
    move-result v1

    .line 235
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 240
    .line 241
    .line 242
    move-result-object p2

    .line 243
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 244
    .line 245
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 246
    .line 247
    .line 248
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 249
    .line 250
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 251
    .line 252
    .line 253
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 254
    .line 255
    if-eqz v6, :cond_9

    .line 256
    .line 257
    invoke-virtual {p1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 258
    .line 259
    .line 260
    goto :goto_9

    .line 261
    :cond_9
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 262
    .line 263
    .line 264
    :goto_9
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 265
    .line 266
    invoke-static {v5, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 267
    .line 268
    .line 269
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 270
    .line 271
    invoke-static {v0, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 272
    .line 273
    .line 274
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 275
    .line 276
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 277
    .line 278
    if-nez v4, :cond_a

    .line 279
    .line 280
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v4

    .line 284
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    move-result v4

    .line 292
    if-nez v4, :cond_b

    .line 293
    .line 294
    :cond_a
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 295
    .line 296
    .line 297
    :cond_b
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 298
    .line 299
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 300
    .line 301
    .line 302
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 303
    .line 304
    invoke-static {v2, p0, p1, v3}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 305
    .line 306
    .line 307
    goto :goto_a

    .line 308
    :cond_c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 309
    .line 310
    .line 311
    :goto_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 312
    .line 313
    return-object p0

    .line 314
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 315
    .line 316
    .line 317
    move-result p2

    .line 318
    and-int/lit8 v0, p2, 0x3

    .line 319
    .line 320
    const/4 v1, 0x2

    .line 321
    const/4 v2, 0x1

    .line 322
    if-eq v0, v1, :cond_d

    .line 323
    .line 324
    move v0, v2

    .line 325
    goto :goto_b

    .line 326
    :cond_d
    const/4 v0, 0x0

    .line 327
    :goto_b
    and-int/2addr p2, v2

    .line 328
    check-cast p1, Ll2/t;

    .line 329
    .line 330
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 331
    .line 332
    .line 333
    move-result p2

    .line 334
    if-eqz p2, :cond_e

    .line 335
    .line 336
    sget-object p2, Lh2/ec;->a:Ll2/u2;

    .line 337
    .line 338
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object p2

    .line 342
    check-cast p2, Lh2/dc;

    .line 343
    .line 344
    iget-object p2, p2, Lh2/dc;->b:Lg4/p0;

    .line 345
    .line 346
    new-instance v0, Ld71/d;

    .line 347
    .line 348
    const/16 v1, 0x18

    .line 349
    .line 350
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 351
    .line 352
    invoke-direct {v0, p0, v1}, Ld71/d;-><init>(Lt2/b;I)V

    .line 353
    .line 354
    .line 355
    const p0, 0x388b6e66

    .line 356
    .line 357
    .line 358
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 359
    .line 360
    .line 361
    move-result-object p0

    .line 362
    const/16 v0, 0x30

    .line 363
    .line 364
    invoke-static {p2, p0, p1, v0}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 365
    .line 366
    .line 367
    goto :goto_c

    .line 368
    :cond_e
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 369
    .line 370
    .line 371
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 372
    .line 373
    return-object p0

    .line 374
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 375
    .line 376
    .line 377
    const/4 p2, 0x7

    .line 378
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 379
    .line 380
    .line 381
    move-result p2

    .line 382
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 383
    .line 384
    invoke-static {p0, p1, p2}, Lxf0/g0;->b(Lt2/b;Ll2/o;I)V

    .line 385
    .line 386
    .line 387
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 388
    .line 389
    return-object p0

    .line 390
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 391
    .line 392
    .line 393
    move-result p2

    .line 394
    and-int/lit8 v0, p2, 0x3

    .line 395
    .line 396
    const/4 v1, 0x2

    .line 397
    const/4 v2, 0x0

    .line 398
    const/4 v3, 0x1

    .line 399
    if-eq v0, v1, :cond_f

    .line 400
    .line 401
    move v0, v3

    .line 402
    goto :goto_d

    .line 403
    :cond_f
    move v0, v2

    .line 404
    :goto_d
    and-int/2addr p2, v3

    .line 405
    check-cast p1, Ll2/t;

    .line 406
    .line 407
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 408
    .line 409
    .line 410
    move-result p2

    .line 411
    if-eqz p2, :cond_10

    .line 412
    .line 413
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 414
    .line 415
    .line 416
    move-result-object p2

    .line 417
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 418
    .line 419
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    goto :goto_e

    .line 423
    :cond_10
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 424
    .line 425
    .line 426
    :goto_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 427
    .line 428
    return-object p0

    .line 429
    :pswitch_8
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 430
    .line 431
    .line 432
    move-result p2

    .line 433
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 434
    .line 435
    invoke-static {p0, p1, p2}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->A(Lt2/b;Ll2/o;I)Llx0/b0;

    .line 436
    .line 437
    .line 438
    move-result-object p0

    .line 439
    return-object p0

    .line 440
    :pswitch_9
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 441
    .line 442
    .line 443
    const/4 p2, 0x7

    .line 444
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 445
    .line 446
    .line 447
    move-result p2

    .line 448
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 449
    .line 450
    invoke-static {p0, p1, p2}, Lqk/b;->d(Lt2/b;Ll2/o;I)V

    .line 451
    .line 452
    .line 453
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 454
    .line 455
    return-object p0

    .line 456
    :pswitch_a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 457
    .line 458
    .line 459
    const/4 p2, 0x7

    .line 460
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 461
    .line 462
    .line 463
    move-result p2

    .line 464
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 465
    .line 466
    invoke-static {p0, p1, p2}, Lo1/y;->c(Lt2/b;Ll2/o;I)V

    .line 467
    .line 468
    .line 469
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 470
    .line 471
    return-object p0

    .line 472
    :pswitch_b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 473
    .line 474
    .line 475
    const/4 p2, 0x7

    .line 476
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 477
    .line 478
    .line 479
    move-result p2

    .line 480
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 481
    .line 482
    invoke-static {p0, p1, p2}, Llp/pb;->c(Lt2/b;Ll2/o;I)V

    .line 483
    .line 484
    .line 485
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 486
    .line 487
    return-object p0

    .line 488
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 489
    .line 490
    .line 491
    move-result p2

    .line 492
    and-int/lit8 v0, p2, 0x3

    .line 493
    .line 494
    const/4 v1, 0x2

    .line 495
    const/4 v2, 0x0

    .line 496
    const/4 v3, 0x1

    .line 497
    if-eq v0, v1, :cond_11

    .line 498
    .line 499
    move v0, v3

    .line 500
    goto :goto_f

    .line 501
    :cond_11
    move v0, v2

    .line 502
    :goto_f
    and-int/2addr p2, v3

    .line 503
    check-cast p1, Ll2/t;

    .line 504
    .line 505
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 506
    .line 507
    .line 508
    move-result p2

    .line 509
    if-eqz p2, :cond_12

    .line 510
    .line 511
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 512
    .line 513
    .line 514
    move-result-object p2

    .line 515
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 516
    .line 517
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    goto :goto_10

    .line 521
    :cond_12
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 522
    .line 523
    .line 524
    :goto_10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 525
    .line 526
    return-object p0

    .line 527
    :pswitch_d
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 528
    .line 529
    .line 530
    move-result p2

    .line 531
    and-int/lit8 v0, p2, 0x3

    .line 532
    .line 533
    const/4 v1, 0x2

    .line 534
    const/4 v2, 0x0

    .line 535
    const/4 v3, 0x1

    .line 536
    if-eq v0, v1, :cond_13

    .line 537
    .line 538
    move v0, v3

    .line 539
    goto :goto_11

    .line 540
    :cond_13
    move v0, v2

    .line 541
    :goto_11
    and-int/2addr p2, v3

    .line 542
    check-cast p1, Ll2/t;

    .line 543
    .line 544
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 545
    .line 546
    .line 547
    move-result p2

    .line 548
    if-eqz p2, :cond_14

    .line 549
    .line 550
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 551
    .line 552
    .line 553
    move-result-object p2

    .line 554
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 555
    .line 556
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 557
    .line 558
    .line 559
    goto :goto_12

    .line 560
    :cond_14
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 561
    .line 562
    .line 563
    :goto_12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 564
    .line 565
    return-object p0

    .line 566
    :pswitch_e
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 567
    .line 568
    .line 569
    move-result p2

    .line 570
    and-int/lit8 v0, p2, 0x3

    .line 571
    .line 572
    const/4 v1, 0x2

    .line 573
    const/4 v2, 0x0

    .line 574
    const/4 v3, 0x1

    .line 575
    if-eq v0, v1, :cond_15

    .line 576
    .line 577
    move v0, v3

    .line 578
    goto :goto_13

    .line 579
    :cond_15
    move v0, v2

    .line 580
    :goto_13
    and-int/2addr p2, v3

    .line 581
    check-cast p1, Ll2/t;

    .line 582
    .line 583
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 584
    .line 585
    .line 586
    move-result p2

    .line 587
    if-eqz p2, :cond_16

    .line 588
    .line 589
    new-instance p2, Ld71/d;

    .line 590
    .line 591
    const/16 v0, 0xf

    .line 592
    .line 593
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 594
    .line 595
    invoke-direct {p2, p0, v0}, Ld71/d;-><init>(Lt2/b;I)V

    .line 596
    .line 597
    .line 598
    const p0, -0x5f358d5a    # -3.4296E-19f

    .line 599
    .line 600
    .line 601
    invoke-static {p0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 602
    .line 603
    .line 604
    move-result-object p0

    .line 605
    const/16 p2, 0x30

    .line 606
    .line 607
    invoke-static {v2, p0, p1, p2}, Llp/pb;->a(ZLt2/b;Ll2/o;I)V

    .line 608
    .line 609
    .line 610
    goto :goto_14

    .line 611
    :cond_16
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 612
    .line 613
    .line 614
    :goto_14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 615
    .line 616
    return-object p0

    .line 617
    :pswitch_f
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 618
    .line 619
    .line 620
    move-result p2

    .line 621
    and-int/lit8 v0, p2, 0x3

    .line 622
    .line 623
    const/4 v1, 0x2

    .line 624
    const/4 v2, 0x1

    .line 625
    if-eq v0, v1, :cond_17

    .line 626
    .line 627
    move v0, v2

    .line 628
    goto :goto_15

    .line 629
    :cond_17
    const/4 v0, 0x0

    .line 630
    :goto_15
    and-int/2addr p2, v2

    .line 631
    check-cast p1, Ll2/t;

    .line 632
    .line 633
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 634
    .line 635
    .line 636
    move-result p2

    .line 637
    if-eqz p2, :cond_18

    .line 638
    .line 639
    new-instance p2, Ld71/d;

    .line 640
    .line 641
    const/16 v0, 0xe

    .line 642
    .line 643
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 644
    .line 645
    invoke-direct {p2, p0, v0}, Ld71/d;-><init>(Lt2/b;I)V

    .line 646
    .line 647
    .line 648
    const p0, 0x54c79669

    .line 649
    .line 650
    .line 651
    invoke-static {p0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 652
    .line 653
    .line 654
    move-result-object p0

    .line 655
    const/4 p2, 0x6

    .line 656
    invoke-static {p0, p1, p2}, Llp/pb;->c(Lt2/b;Ll2/o;I)V

    .line 657
    .line 658
    .line 659
    goto :goto_16

    .line 660
    :cond_18
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 661
    .line 662
    .line 663
    :goto_16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 664
    .line 665
    return-object p0

    .line 666
    :pswitch_10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 667
    .line 668
    .line 669
    move-result p2

    .line 670
    and-int/lit8 v0, p2, 0x3

    .line 671
    .line 672
    const/4 v1, 0x2

    .line 673
    const/4 v2, 0x0

    .line 674
    const/4 v3, 0x1

    .line 675
    if-eq v0, v1, :cond_19

    .line 676
    .line 677
    move v0, v3

    .line 678
    goto :goto_17

    .line 679
    :cond_19
    move v0, v2

    .line 680
    :goto_17
    and-int/2addr p2, v3

    .line 681
    check-cast p1, Ll2/t;

    .line 682
    .line 683
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 684
    .line 685
    .line 686
    move-result p2

    .line 687
    if-eqz p2, :cond_1a

    .line 688
    .line 689
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 690
    .line 691
    .line 692
    move-result-object p2

    .line 693
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 694
    .line 695
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 696
    .line 697
    .line 698
    goto :goto_18

    .line 699
    :cond_1a
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 700
    .line 701
    .line 702
    :goto_18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 703
    .line 704
    return-object p0

    .line 705
    :pswitch_11
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 706
    .line 707
    .line 708
    move-result p2

    .line 709
    and-int/lit8 v0, p2, 0x3

    .line 710
    .line 711
    const/4 v1, 0x2

    .line 712
    const/4 v2, 0x1

    .line 713
    if-eq v0, v1, :cond_1b

    .line 714
    .line 715
    move v0, v2

    .line 716
    goto :goto_19

    .line 717
    :cond_1b
    const/4 v0, 0x0

    .line 718
    :goto_19
    and-int/2addr p2, v2

    .line 719
    check-cast p1, Ll2/t;

    .line 720
    .line 721
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 722
    .line 723
    .line 724
    move-result p2

    .line 725
    if-eqz p2, :cond_1c

    .line 726
    .line 727
    sget-object p2, Lj91/h;->a:Ll2/u2;

    .line 728
    .line 729
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 730
    .line 731
    .line 732
    move-result-object p2

    .line 733
    check-cast p2, Lj91/e;

    .line 734
    .line 735
    invoke-virtual {p2}, Lj91/e;->o()J

    .line 736
    .line 737
    .line 738
    move-result-wide v0

    .line 739
    new-instance p2, Ld71/d;

    .line 740
    .line 741
    const/16 v2, 0xd

    .line 742
    .line 743
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 744
    .line 745
    invoke-direct {p2, p0, v2}, Ld71/d;-><init>(Lt2/b;I)V

    .line 746
    .line 747
    .line 748
    const p0, 0x3a5101c9

    .line 749
    .line 750
    .line 751
    invoke-static {p0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 752
    .line 753
    .line 754
    move-result-object p0

    .line 755
    const/16 p2, 0x30

    .line 756
    .line 757
    invoke-static {v0, v1, p0, p1, p2}, Llp/ob;->a(JLt2/b;Ll2/o;I)V

    .line 758
    .line 759
    .line 760
    goto :goto_1a

    .line 761
    :cond_1c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 762
    .line 763
    .line 764
    :goto_1a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 765
    .line 766
    return-object p0

    .line 767
    :pswitch_12
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 768
    .line 769
    .line 770
    move-result p2

    .line 771
    and-int/lit8 v0, p2, 0x3

    .line 772
    .line 773
    const/4 v1, 0x2

    .line 774
    const/4 v2, 0x0

    .line 775
    const/4 v3, 0x1

    .line 776
    if-eq v0, v1, :cond_1d

    .line 777
    .line 778
    move v0, v3

    .line 779
    goto :goto_1b

    .line 780
    :cond_1d
    move v0, v2

    .line 781
    :goto_1b
    and-int/2addr p2, v3

    .line 782
    check-cast p1, Ll2/t;

    .line 783
    .line 784
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 785
    .line 786
    .line 787
    move-result p2

    .line 788
    if-eqz p2, :cond_1e

    .line 789
    .line 790
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 791
    .line 792
    .line 793
    move-result-object p2

    .line 794
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 795
    .line 796
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 797
    .line 798
    .line 799
    goto :goto_1c

    .line 800
    :cond_1e
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 801
    .line 802
    .line 803
    :goto_1c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 804
    .line 805
    return-object p0

    .line 806
    :pswitch_13
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 807
    .line 808
    .line 809
    move-result p2

    .line 810
    and-int/lit8 v0, p2, 0x3

    .line 811
    .line 812
    const/4 v1, 0x2

    .line 813
    const/4 v2, 0x0

    .line 814
    const/4 v3, 0x1

    .line 815
    if-eq v0, v1, :cond_1f

    .line 816
    .line 817
    move v0, v3

    .line 818
    goto :goto_1d

    .line 819
    :cond_1f
    move v0, v2

    .line 820
    :goto_1d
    and-int/2addr p2, v3

    .line 821
    check-cast p1, Ll2/t;

    .line 822
    .line 823
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 824
    .line 825
    .line 826
    move-result p2

    .line 827
    if-eqz p2, :cond_20

    .line 828
    .line 829
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 830
    .line 831
    .line 832
    move-result-object p2

    .line 833
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 834
    .line 835
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 836
    .line 837
    .line 838
    goto :goto_1e

    .line 839
    :cond_20
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 840
    .line 841
    .line 842
    :goto_1e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 843
    .line 844
    return-object p0

    .line 845
    :pswitch_14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 846
    .line 847
    .line 848
    const/4 p2, 0x7

    .line 849
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 850
    .line 851
    .line 852
    move-result p2

    .line 853
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 854
    .line 855
    invoke-static {p0, p1, p2}, Li71/c;->a(Lt2/b;Ll2/o;I)V

    .line 856
    .line 857
    .line 858
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 859
    .line 860
    return-object p0

    .line 861
    :pswitch_15
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 862
    .line 863
    .line 864
    move-result p2

    .line 865
    and-int/lit8 v0, p2, 0x3

    .line 866
    .line 867
    const/4 v1, 0x2

    .line 868
    const/4 v2, 0x0

    .line 869
    const/4 v3, 0x1

    .line 870
    if-eq v0, v1, :cond_21

    .line 871
    .line 872
    move v0, v3

    .line 873
    goto :goto_1f

    .line 874
    :cond_21
    move v0, v2

    .line 875
    :goto_1f
    and-int/2addr p2, v3

    .line 876
    check-cast p1, Ll2/t;

    .line 877
    .line 878
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 879
    .line 880
    .line 881
    move-result p2

    .line 882
    if-eqz p2, :cond_22

    .line 883
    .line 884
    new-instance p2, Ld71/d;

    .line 885
    .line 886
    const/16 v0, 0x9

    .line 887
    .line 888
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 889
    .line 890
    invoke-direct {p2, p0, v0}, Ld71/d;-><init>(Lt2/b;I)V

    .line 891
    .line 892
    .line 893
    const p0, -0x5388483e

    .line 894
    .line 895
    .line 896
    invoke-static {p0, p1, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 897
    .line 898
    .line 899
    move-result-object p0

    .line 900
    const/16 p2, 0x30

    .line 901
    .line 902
    invoke-static {v2, p0, p1, p2, v3}, Llp/pb;->b(ZLt2/b;Ll2/o;II)V

    .line 903
    .line 904
    .line 905
    goto :goto_20

    .line 906
    :cond_22
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 907
    .line 908
    .line 909
    :goto_20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 910
    .line 911
    return-object p0

    .line 912
    :pswitch_16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 913
    .line 914
    .line 915
    const/16 p2, 0x37

    .line 916
    .line 917
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 918
    .line 919
    .line 920
    move-result p2

    .line 921
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 922
    .line 923
    invoke-static {p0, p1, p2}, Lh2/m8;->a(Lt2/b;Ll2/o;I)V

    .line 924
    .line 925
    .line 926
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 927
    .line 928
    return-object p0

    .line 929
    :pswitch_17
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 930
    .line 931
    .line 932
    const/4 p2, 0x7

    .line 933
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 934
    .line 935
    .line 936
    move-result p2

    .line 937
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 938
    .line 939
    invoke-static {p0, p1, p2}, Lkp/u8;->a(Lt2/b;Ll2/o;I)V

    .line 940
    .line 941
    .line 942
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 943
    .line 944
    return-object p0

    .line 945
    :pswitch_18
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 946
    .line 947
    .line 948
    const/4 p2, 0x7

    .line 949
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 950
    .line 951
    .line 952
    move-result p2

    .line 953
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 954
    .line 955
    invoke-static {p0, p1, p2}, Lkp/r;->a(Lt2/b;Ll2/o;I)V

    .line 956
    .line 957
    .line 958
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 959
    .line 960
    return-object p0

    .line 961
    :pswitch_19
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 962
    .line 963
    .line 964
    const/4 p2, 0x7

    .line 965
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 966
    .line 967
    .line 968
    move-result p2

    .line 969
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 970
    .line 971
    invoke-static {p0, p1, p2}, Ldk/b;->i(Lt2/b;Ll2/o;I)V

    .line 972
    .line 973
    .line 974
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 975
    .line 976
    return-object p0

    .line 977
    :pswitch_1a
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 978
    .line 979
    .line 980
    move-result p2

    .line 981
    and-int/lit8 v0, p2, 0x3

    .line 982
    .line 983
    const/4 v1, 0x2

    .line 984
    const/4 v2, 0x0

    .line 985
    const/4 v3, 0x1

    .line 986
    if-eq v0, v1, :cond_23

    .line 987
    .line 988
    move v0, v3

    .line 989
    goto :goto_21

    .line 990
    :cond_23
    move v0, v2

    .line 991
    :goto_21
    and-int/2addr p2, v3

    .line 992
    check-cast p1, Ll2/t;

    .line 993
    .line 994
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 995
    .line 996
    .line 997
    move-result p2

    .line 998
    if-eqz p2, :cond_24

    .line 999
    .line 1000
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1001
    .line 1002
    .line 1003
    move-result-object p2

    .line 1004
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 1005
    .line 1006
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1007
    .line 1008
    .line 1009
    goto :goto_22

    .line 1010
    :cond_24
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 1011
    .line 1012
    .line 1013
    :goto_22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1014
    .line 1015
    return-object p0

    .line 1016
    :pswitch_1b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1017
    .line 1018
    .line 1019
    const/4 p2, 0x7

    .line 1020
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 1021
    .line 1022
    .line 1023
    move-result p2

    .line 1024
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 1025
    .line 1026
    invoke-static {p0, p1, p2}, Ld71/e;->a(Lt2/b;Ll2/o;I)V

    .line 1027
    .line 1028
    .line 1029
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1030
    .line 1031
    return-object p0

    .line 1032
    :pswitch_1c
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 1033
    .line 1034
    .line 1035
    move-result p2

    .line 1036
    and-int/lit8 v0, p2, 0x3

    .line 1037
    .line 1038
    const/4 v1, 0x2

    .line 1039
    const/4 v2, 0x0

    .line 1040
    const/4 v3, 0x1

    .line 1041
    if-eq v0, v1, :cond_25

    .line 1042
    .line 1043
    move v0, v3

    .line 1044
    goto :goto_23

    .line 1045
    :cond_25
    move v0, v2

    .line 1046
    :goto_23
    and-int/2addr p2, v3

    .line 1047
    check-cast p1, Ll2/t;

    .line 1048
    .line 1049
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 1050
    .line 1051
    .line 1052
    move-result p2

    .line 1053
    if-eqz p2, :cond_26

    .line 1054
    .line 1055
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1056
    .line 1057
    .line 1058
    move-result-object p2

    .line 1059
    iget-object p0, p0, Ld71/d;->e:Lt2/b;

    .line 1060
    .line 1061
    invoke-virtual {p0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1062
    .line 1063
    .line 1064
    goto :goto_24

    .line 1065
    :cond_26
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 1066
    .line 1067
    .line 1068
    :goto_24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1069
    .line 1070
    return-object p0

    .line 1071
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
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
