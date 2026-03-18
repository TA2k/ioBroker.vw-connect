.class public final synthetic Ldl/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lt2/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Ldl/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldl/g;->e:Lt2/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Ldl/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lzb/f;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    const-string v0, "$this$BottomSheet"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, p3, 0x6

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    if-nez v0, :cond_2

    .line 25
    .line 26
    and-int/lit8 v0, p3, 0x8

    .line 27
    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    move-object v0, p2

    .line 31
    check-cast v0, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move-object v0, p2

    .line 39
    check-cast v0, Ll2/t;

    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    :goto_0
    if-eqz v0, :cond_1

    .line 46
    .line 47
    const/4 v0, 0x4

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v0, v1

    .line 50
    :goto_1
    or-int/2addr p3, v0

    .line 51
    :cond_2
    and-int/lit8 v0, p3, 0x13

    .line 52
    .line 53
    const/16 v2, 0x12

    .line 54
    .line 55
    const/4 v3, 0x1

    .line 56
    if-eq v0, v2, :cond_3

    .line 57
    .line 58
    move v0, v3

    .line 59
    goto :goto_2

    .line 60
    :cond_3
    const/4 v0, 0x0

    .line 61
    :goto_2
    and-int/2addr p3, v3

    .line 62
    check-cast p2, Ll2/t;

    .line 63
    .line 64
    invoke-virtual {p2, p3, v0}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result p3

    .line 68
    if-eqz p3, :cond_7

    .line 69
    .line 70
    sget-object p3, Lj91/a;->a:Ll2/u2;

    .line 71
    .line 72
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast v0, Lj91/c;

    .line 77
    .line 78
    iget v0, v0, Lj91/c;->d:F

    .line 79
    .line 80
    const/4 v2, 0x0

    .line 81
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 82
    .line 83
    invoke-static {v4, v0, v2, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 88
    .line 89
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Lj91/e;

    .line 94
    .line 95
    invoke-virtual {v1}, Lj91/e;->d()J

    .line 96
    .line 97
    .line 98
    move-result-wide v1

    .line 99
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    check-cast v4, Lj91/c;

    .line 104
    .line 105
    iget v4, v4, Lj91/c;->b:F

    .line 106
    .line 107
    invoke-static {v4}, Ls1/f;->b(F)Ls1/e;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    invoke-static {v0, v1, v2, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    iget-object v9, p1, Lzb/f;->a:Lay0/a;

    .line 116
    .line 117
    const/16 v10, 0xf

    .line 118
    .line 119
    const/4 v6, 0x0

    .line 120
    const/4 v7, 0x0

    .line 121
    const/4 v8, 0x0

    .line 122
    invoke-static/range {v5 .. v10}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    check-cast p3, Lj91/c;

    .line 131
    .line 132
    iget p3, p3, Lj91/c;->d:F

    .line 133
    .line 134
    invoke-static {p1, p3}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    sget-object p3, Lk1/j;->c:Lk1/e;

    .line 139
    .line 140
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 141
    .line 142
    const/16 v1, 0x36

    .line 143
    .line 144
    invoke-static {p3, v0, p2, v1}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 145
    .line 146
    .line 147
    move-result-object p3

    .line 148
    iget-wide v0, p2, Ll2/t;->T:J

    .line 149
    .line 150
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    invoke-virtual {p2}, Ll2/t;->m()Ll2/p1;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-static {p2, p1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    sget-object v2, Lv3/k;->m1:Lv3/j;

    .line 163
    .line 164
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 165
    .line 166
    .line 167
    sget-object v2, Lv3/j;->b:Lv3/i;

    .line 168
    .line 169
    invoke-virtual {p2}, Ll2/t;->c0()V

    .line 170
    .line 171
    .line 172
    iget-boolean v4, p2, Ll2/t;->S:Z

    .line 173
    .line 174
    if-eqz v4, :cond_4

    .line 175
    .line 176
    invoke-virtual {p2, v2}, Ll2/t;->l(Lay0/a;)V

    .line 177
    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_4
    invoke-virtual {p2}, Ll2/t;->m0()V

    .line 181
    .line 182
    .line 183
    :goto_3
    sget-object v2, Lv3/j;->g:Lv3/h;

    .line 184
    .line 185
    invoke-static {v2, p3, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 186
    .line 187
    .line 188
    sget-object p3, Lv3/j;->f:Lv3/h;

    .line 189
    .line 190
    invoke-static {p3, v1, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 191
    .line 192
    .line 193
    sget-object p3, Lv3/j;->j:Lv3/h;

    .line 194
    .line 195
    iget-boolean v1, p2, Ll2/t;->S:Z

    .line 196
    .line 197
    if-nez v1, :cond_5

    .line 198
    .line 199
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    if-nez v1, :cond_6

    .line 212
    .line 213
    :cond_5
    invoke-static {v0, p2, v0, p3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 214
    .line 215
    .line 216
    :cond_6
    sget-object p3, Lv3/j;->d:Lv3/h;

    .line 217
    .line 218
    invoke-static {p3, p1, p2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 219
    .line 220
    .line 221
    sget-object p1, Lk1/t;->a:Lk1/t;

    .line 222
    .line 223
    const/4 p3, 0x6

    .line 224
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 225
    .line 226
    .line 227
    move-result-object p3

    .line 228
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 229
    .line 230
    invoke-virtual {p0, p1, p2, p3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    invoke-virtual {p2, v3}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    goto :goto_4

    .line 237
    :cond_7
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 238
    .line 239
    .line 240
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 241
    .line 242
    return-object p0

    .line 243
    :pswitch_0
    check-cast p1, Lb1/a0;

    .line 244
    .line 245
    check-cast p2, Ll2/o;

    .line 246
    .line 247
    check-cast p3, Ljava/lang/Integer;

    .line 248
    .line 249
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 250
    .line 251
    .line 252
    const-string p3, "$this$AnimatedVisibility"

    .line 253
    .line 254
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    const/4 p1, 0x0

    .line 258
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 259
    .line 260
    .line 261
    move-result-object p1

    .line 262
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 263
    .line 264
    invoke-virtual {p0, p2, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    return-object p0

    .line 270
    :pswitch_1
    check-cast p1, Lk1/z0;

    .line 271
    .line 272
    check-cast p2, Ll2/o;

    .line 273
    .line 274
    check-cast p3, Ljava/lang/Integer;

    .line 275
    .line 276
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 277
    .line 278
    .line 279
    move-result p3

    .line 280
    const-string v0, "padding"

    .line 281
    .line 282
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    and-int/lit8 v0, p3, 0x6

    .line 286
    .line 287
    if-nez v0, :cond_9

    .line 288
    .line 289
    move-object v0, p2

    .line 290
    check-cast v0, Ll2/t;

    .line 291
    .line 292
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result v0

    .line 296
    if-eqz v0, :cond_8

    .line 297
    .line 298
    const/4 v0, 0x4

    .line 299
    goto :goto_6

    .line 300
    :cond_8
    const/4 v0, 0x2

    .line 301
    :goto_6
    or-int/2addr p3, v0

    .line 302
    :cond_9
    and-int/lit8 v0, p3, 0x13

    .line 303
    .line 304
    const/16 v1, 0x12

    .line 305
    .line 306
    if-eq v0, v1, :cond_a

    .line 307
    .line 308
    const/4 v0, 0x1

    .line 309
    goto :goto_7

    .line 310
    :cond_a
    const/4 v0, 0x0

    .line 311
    :goto_7
    and-int/lit8 v1, p3, 0x1

    .line 312
    .line 313
    check-cast p2, Ll2/t;

    .line 314
    .line 315
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 316
    .line 317
    .line 318
    move-result v0

    .line 319
    if-eqz v0, :cond_b

    .line 320
    .line 321
    and-int/lit8 p3, p3, 0xe

    .line 322
    .line 323
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 324
    .line 325
    .line 326
    move-result-object p3

    .line 327
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 328
    .line 329
    invoke-virtual {p0, p1, p2, p3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    goto :goto_8

    .line 333
    :cond_b
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 334
    .line 335
    .line 336
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 337
    .line 338
    return-object p0

    .line 339
    :pswitch_2
    check-cast p1, Lk1/k0;

    .line 340
    .line 341
    check-cast p2, Ll2/o;

    .line 342
    .line 343
    check-cast p3, Ljava/lang/Integer;

    .line 344
    .line 345
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 346
    .line 347
    .line 348
    move-result p3

    .line 349
    const-string v0, "$this$FlowRow"

    .line 350
    .line 351
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    and-int/lit8 p1, p3, 0x11

    .line 355
    .line 356
    const/16 v0, 0x10

    .line 357
    .line 358
    const/4 v1, 0x0

    .line 359
    const/4 v2, 0x1

    .line 360
    if-eq p1, v0, :cond_c

    .line 361
    .line 362
    move p1, v2

    .line 363
    goto :goto_9

    .line 364
    :cond_c
    move p1, v1

    .line 365
    :goto_9
    and-int/2addr p3, v2

    .line 366
    check-cast p2, Ll2/t;

    .line 367
    .line 368
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 369
    .line 370
    .line 371
    move-result p1

    .line 372
    if-eqz p1, :cond_d

    .line 373
    .line 374
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 375
    .line 376
    .line 377
    move-result-object p1

    .line 378
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 379
    .line 380
    invoke-virtual {p0, p2, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    goto :goto_a

    .line 384
    :cond_d
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 385
    .line 386
    .line 387
    :goto_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 388
    .line 389
    return-object p0

    .line 390
    :pswitch_3
    check-cast p1, Lk1/z0;

    .line 391
    .line 392
    check-cast p2, Ll2/o;

    .line 393
    .line 394
    check-cast p3, Ljava/lang/Integer;

    .line 395
    .line 396
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 397
    .line 398
    .line 399
    move-result p3

    .line 400
    const-string v0, "it"

    .line 401
    .line 402
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    and-int/lit8 p1, p3, 0x11

    .line 406
    .line 407
    const/16 v0, 0x10

    .line 408
    .line 409
    const/4 v1, 0x0

    .line 410
    const/4 v2, 0x1

    .line 411
    if-eq p1, v0, :cond_e

    .line 412
    .line 413
    move p1, v2

    .line 414
    goto :goto_b

    .line 415
    :cond_e
    move p1, v1

    .line 416
    :goto_b
    and-int/2addr p3, v2

    .line 417
    check-cast p2, Ll2/t;

    .line 418
    .line 419
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 420
    .line 421
    .line 422
    move-result p1

    .line 423
    if-eqz p1, :cond_f

    .line 424
    .line 425
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 426
    .line 427
    .line 428
    move-result-object p1

    .line 429
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 430
    .line 431
    invoke-virtual {p0, p2, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    goto :goto_c

    .line 435
    :cond_f
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 436
    .line 437
    .line 438
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 439
    .line 440
    return-object p0

    .line 441
    :pswitch_4
    check-cast p1, Lb1/a0;

    .line 442
    .line 443
    check-cast p2, Ll2/o;

    .line 444
    .line 445
    check-cast p3, Ljava/lang/Integer;

    .line 446
    .line 447
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 448
    .line 449
    .line 450
    const-string p3, "$this$AnimatedVisibility"

    .line 451
    .line 452
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 453
    .line 454
    .line 455
    const/4 p1, 0x0

    .line 456
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 457
    .line 458
    .line 459
    move-result-object p1

    .line 460
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 461
    .line 462
    invoke-virtual {p0, p2, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    goto/16 :goto_5

    .line 466
    .line 467
    :pswitch_5
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 468
    .line 469
    check-cast p2, Ll2/o;

    .line 470
    .line 471
    check-cast p3, Ljava/lang/Integer;

    .line 472
    .line 473
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 474
    .line 475
    .line 476
    move-result p3

    .line 477
    const-string v0, "$this$item"

    .line 478
    .line 479
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 480
    .line 481
    .line 482
    and-int/lit8 p1, p3, 0x11

    .line 483
    .line 484
    const/16 v0, 0x10

    .line 485
    .line 486
    const/4 v1, 0x0

    .line 487
    const/4 v2, 0x1

    .line 488
    if-eq p1, v0, :cond_10

    .line 489
    .line 490
    move p1, v2

    .line 491
    goto :goto_d

    .line 492
    :cond_10
    move p1, v1

    .line 493
    :goto_d
    and-int/2addr p3, v2

    .line 494
    check-cast p2, Ll2/t;

    .line 495
    .line 496
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 497
    .line 498
    .line 499
    move-result p1

    .line 500
    if-eqz p1, :cond_11

    .line 501
    .line 502
    const/16 p1, 0x20

    .line 503
    .line 504
    int-to-float p1, p1

    .line 505
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 506
    .line 507
    invoke-static {p3, p1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 508
    .line 509
    .line 510
    move-result-object v0

    .line 511
    invoke-static {p2, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 512
    .line 513
    .line 514
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 515
    .line 516
    .line 517
    move-result-object v0

    .line 518
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 519
    .line 520
    invoke-virtual {p0, p2, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 521
    .line 522
    .line 523
    invoke-static {p3, p1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 524
    .line 525
    .line 526
    move-result-object p0

    .line 527
    invoke-static {p2, p0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 528
    .line 529
    .line 530
    goto :goto_e

    .line 531
    :cond_11
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 532
    .line 533
    .line 534
    :goto_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 535
    .line 536
    return-object p0

    .line 537
    :pswitch_6
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 538
    .line 539
    check-cast p2, Ll2/o;

    .line 540
    .line 541
    check-cast p3, Ljava/lang/Integer;

    .line 542
    .line 543
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 544
    .line 545
    .line 546
    move-result p3

    .line 547
    const-string v0, "$this$item"

    .line 548
    .line 549
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 550
    .line 551
    .line 552
    and-int/lit8 p1, p3, 0x11

    .line 553
    .line 554
    const/16 v0, 0x10

    .line 555
    .line 556
    const/4 v1, 0x0

    .line 557
    const/4 v2, 0x1

    .line 558
    if-eq p1, v0, :cond_12

    .line 559
    .line 560
    move p1, v2

    .line 561
    goto :goto_f

    .line 562
    :cond_12
    move p1, v1

    .line 563
    :goto_f
    and-int/2addr p3, v2

    .line 564
    check-cast p2, Ll2/t;

    .line 565
    .line 566
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 567
    .line 568
    .line 569
    move-result p1

    .line 570
    if-eqz p1, :cond_13

    .line 571
    .line 572
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 573
    .line 574
    .line 575
    move-result-object p1

    .line 576
    iget-object p0, p0, Ldl/g;->e:Lt2/b;

    .line 577
    .line 578
    invoke-virtual {p0, p2, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    const/16 p0, 0x20

    .line 582
    .line 583
    int-to-float p0, p0

    .line 584
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 585
    .line 586
    invoke-static {p1, p0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 587
    .line 588
    .line 589
    move-result-object p0

    .line 590
    invoke-static {p2, p0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 591
    .line 592
    .line 593
    goto :goto_10

    .line 594
    :cond_13
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 595
    .line 596
    .line 597
    :goto_10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 598
    .line 599
    return-object p0

    .line 600
    nop

    .line 601
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
