.class public final Lkn/i0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lkn/i0;->f:I

    iput-object p3, p0, Lkn/i0;->g:Ljava/lang/Object;

    iput-object p4, p0, Lkn/i0;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 2
    iput p1, p0, Lkn/i0;->f:I

    iput-object p2, p0, Lkn/i0;->g:Ljava/lang/Object;

    iput-object p3, p0, Lkn/i0;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lkn/i0;->f:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x1

    .line 6
    iget-object v4, p0, Lkn/i0;->g:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p0, p0, Lkn/i0;->h:Ljava/lang/Object;

    .line 9
    .line 10
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    check-cast p1, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    check-cast p2, Ld4/q;

    .line 22
    .line 23
    check-cast p0, Lz2/e;

    .line 24
    .line 25
    check-cast v4, Lw3/a2;

    .line 26
    .line 27
    iget-object v0, v4, Lw3/a2;->b:Landroidx/collection/c0;

    .line 28
    .line 29
    iget v1, p2, Ld4/q;->g:I

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Landroidx/collection/c0;->b(I)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {p0, p1, p2}, Lz2/e;->i(ILd4/q;)V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lz2/e;->k:Lxy0/j;

    .line 41
    .line 42
    invoke-interface {p0, v5}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    :cond_0
    return-object v5

    .line 46
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 47
    .line 48
    check-cast p2, Ljava/lang/Number;

    .line 49
    .line 50
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    check-cast v4, Lx4/t;

    .line 55
    .line 56
    and-int/lit8 v0, p2, 0x3

    .line 57
    .line 58
    if-eq v0, v1, :cond_1

    .line 59
    .line 60
    move v0, v3

    .line 61
    goto :goto_0

    .line 62
    :cond_1
    move v0, v2

    .line 63
    :goto_0
    and-int/2addr p2, v3

    .line 64
    check-cast p1, Ll2/t;

    .line 65
    .line 66
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_a

    .line 71
    .line 72
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 77
    .line 78
    if-ne p2, v0, :cond_2

    .line 79
    .line 80
    sget-object p2, Lx4/c;->j:Lx4/c;

    .line 81
    .line 82
    invoke-virtual {p1, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_2
    check-cast p2, Lay0/k;

    .line 86
    .line 87
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 88
    .line 89
    invoke-static {v1, v2, p2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    invoke-virtual {p1, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    if-nez v1, :cond_3

    .line 102
    .line 103
    if-ne v6, v0, :cond_4

    .line 104
    .line 105
    :cond_3
    new-instance v6, Lx4/h;

    .line 106
    .line 107
    invoke-direct {v6, v4, v3}, Lx4/h;-><init>(Lx4/t;I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_4
    check-cast v6, Lay0/k;

    .line 114
    .line 115
    invoke-static {p2, v6}, Landroidx/compose/ui/layout/a;->f(Lx2/s;Lay0/k;)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object p2

    .line 119
    invoke-virtual {v4}, Lx4/t;->getCanCalculatePosition()Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    if-eqz v1, :cond_5

    .line 124
    .line 125
    const/high16 v1, 0x3f800000    # 1.0f

    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_5
    const/4 v1, 0x0

    .line 129
    :goto_1
    invoke-static {p2, v1}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    check-cast p0, Ll2/b1;

    .line 134
    .line 135
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p0, Lay0/n;

    .line 140
    .line 141
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    if-ne v1, v0, :cond_6

    .line 146
    .line 147
    sget-object v1, Lx4/e;->c:Lx4/e;

    .line 148
    .line 149
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    :cond_6
    check-cast v1, Lt3/q0;

    .line 153
    .line 154
    iget-wide v6, p1, Ll2/t;->T:J

    .line 155
    .line 156
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 157
    .line 158
    .line 159
    move-result v0

    .line 160
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object p2

    .line 168
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 169
    .line 170
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 171
    .line 172
    .line 173
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 174
    .line 175
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 176
    .line 177
    .line 178
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 179
    .line 180
    if-eqz v7, :cond_7

    .line 181
    .line 182
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 183
    .line 184
    .line 185
    goto :goto_2

    .line 186
    :cond_7
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 187
    .line 188
    .line 189
    :goto_2
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 190
    .line 191
    invoke-static {v6, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 192
    .line 193
    .line 194
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 195
    .line 196
    invoke-static {v1, v4, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 197
    .line 198
    .line 199
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 200
    .line 201
    iget-boolean v4, p1, Ll2/t;->S:Z

    .line 202
    .line 203
    if-nez v4, :cond_8

    .line 204
    .line 205
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v4

    .line 217
    if-nez v4, :cond_9

    .line 218
    .line 219
    :cond_8
    invoke-static {v0, p1, v0, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 220
    .line 221
    .line 222
    :cond_9
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 223
    .line 224
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 225
    .line 226
    .line 227
    invoke-static {v2, p0, p1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 228
    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_a
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 232
    .line 233
    .line 234
    :goto_3
    return-object v5

    .line 235
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 236
    .line 237
    check-cast p2, Ljava/lang/Number;

    .line 238
    .line 239
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 240
    .line 241
    .line 242
    check-cast v4, Lw3/t;

    .line 243
    .line 244
    check-cast p0, Lay0/n;

    .line 245
    .line 246
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 247
    .line 248
    .line 249
    move-result p2

    .line 250
    invoke-static {v4, p0, p1, p2}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a(Lw3/t;Lay0/n;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    return-object v5

    .line 254
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 255
    .line 256
    check-cast p2, Ljava/lang/Number;

    .line 257
    .line 258
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 259
    .line 260
    .line 261
    move-result p2

    .line 262
    and-int/lit8 p2, p2, 0xb

    .line 263
    .line 264
    if-ne p2, v1, :cond_c

    .line 265
    .line 266
    move-object p2, p1

    .line 267
    check-cast p2, Ll2/t;

    .line 268
    .line 269
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 270
    .line 271
    .line 272
    move-result v0

    .line 273
    if-nez v0, :cond_b

    .line 274
    .line 275
    goto :goto_4

    .line 276
    :cond_b
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 277
    .line 278
    .line 279
    goto :goto_5

    .line 280
    :cond_c
    :goto_4
    check-cast v4, Lay0/k;

    .line 281
    .line 282
    check-cast p0, Lvv/a1;

    .line 283
    .line 284
    invoke-interface {v4, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    check-cast p0, Lx2/s;

    .line 289
    .line 290
    invoke-static {p0, p1, v2}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 291
    .line 292
    .line 293
    :goto_5
    return-object v5

    .line 294
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 295
    .line 296
    check-cast p2, Ljava/lang/Number;

    .line 297
    .line 298
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 299
    .line 300
    .line 301
    check-cast v4, Lvv/n0;

    .line 302
    .line 303
    check-cast p0, Lt2/b;

    .line 304
    .line 305
    const/16 p2, 0x181

    .line 306
    .line 307
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 308
    .line 309
    .line 310
    move-result p2

    .line 311
    invoke-static {v4, p0, p1, p2}, Lvv/o0;->a(Lvv/n0;Lt2/b;Ll2/o;I)V

    .line 312
    .line 313
    .line 314
    return-object v5

    .line 315
    :pswitch_4
    check-cast p1, Le3/r;

    .line 316
    .line 317
    check-cast p2, Lh3/c;

    .line 318
    .line 319
    check-cast v4, Lv3/f1;

    .line 320
    .line 321
    iget-object v0, v4, Lv3/f1;->r:Lv3/h0;

    .line 322
    .line 323
    invoke-virtual {v0}, Lv3/h0;->J()Z

    .line 324
    .line 325
    .line 326
    move-result v1

    .line 327
    if-eqz v1, :cond_d

    .line 328
    .line 329
    iput-object p1, v4, Lv3/f1;->H:Le3/r;

    .line 330
    .line 331
    iput-object p2, v4, Lv3/f1;->G:Lh3/c;

    .line 332
    .line 333
    invoke-static {v0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 334
    .line 335
    .line 336
    move-result-object p1

    .line 337
    check-cast p1, Lw3/t;

    .line 338
    .line 339
    invoke-virtual {p1}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 340
    .line 341
    .line 342
    move-result-object p1

    .line 343
    sget-object p2, Lv3/f1;->N:Le3/k0;

    .line 344
    .line 345
    sget-object p2, Lv3/e;->i:Lv3/e;

    .line 346
    .line 347
    check-cast p0, Lv3/c1;

    .line 348
    .line 349
    invoke-virtual {p1, v4, p2, p0}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 350
    .line 351
    .line 352
    iput-boolean v2, v4, Lv3/f1;->K:Z

    .line 353
    .line 354
    goto :goto_6

    .line 355
    :cond_d
    iput-boolean v3, v4, Lv3/f1;->K:Z

    .line 356
    .line 357
    :goto_6
    return-object v5

    .line 358
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 359
    .line 360
    check-cast p2, Ljava/lang/Number;

    .line 361
    .line 362
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 363
    .line 364
    .line 365
    check-cast v4, Lvv/m0;

    .line 366
    .line 367
    check-cast p0, Ljava/lang/String;

    .line 368
    .line 369
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 370
    .line 371
    .line 372
    move-result p2

    .line 373
    invoke-static {v4, p0, p1, p2}, Llp/j0;->a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V

    .line 374
    .line 375
    .line 376
    return-object v5

    .line 377
    :pswitch_6
    check-cast p1, Ll2/o;

    .line 378
    .line 379
    check-cast p2, Ljava/lang/Number;

    .line 380
    .line 381
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 382
    .line 383
    .line 384
    move-result p2

    .line 385
    and-int/lit8 v0, p2, 0x3

    .line 386
    .line 387
    if-eq v0, v1, :cond_e

    .line 388
    .line 389
    move v0, v3

    .line 390
    goto :goto_7

    .line 391
    :cond_e
    move v0, v2

    .line 392
    :goto_7
    and-int/2addr p2, v3

    .line 393
    check-cast p1, Ll2/t;

    .line 394
    .line 395
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 396
    .line 397
    .line 398
    move-result p2

    .line 399
    if-eqz p2, :cond_14

    .line 400
    .line 401
    check-cast v4, Lt3/f0;

    .line 402
    .line 403
    iget-object p2, v4, Lt3/f0;->g:Ll2/j1;

    .line 404
    .line 405
    invoke-virtual {p2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    move-result-object p2

    .line 409
    check-cast p2, Ljava/lang/Boolean;

    .line 410
    .line 411
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 412
    .line 413
    .line 414
    move-result v0

    .line 415
    check-cast p0, Lay0/n;

    .line 416
    .line 417
    invoke-virtual {p1, p2}, Ll2/t;->b0(Ljava/lang/Object;)V

    .line 418
    .line 419
    .line 420
    invoke-virtual {p1, v0}, Ll2/t;->h(Z)Z

    .line 421
    .line 422
    .line 423
    move-result p2

    .line 424
    if-eqz v0, :cond_f

    .line 425
    .line 426
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 427
    .line 428
    .line 429
    move-result-object p2

    .line 430
    invoke-interface {p0, p1, p2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    goto :goto_9

    .line 434
    :cond_f
    iget p0, p1, Ll2/t;->l:I

    .line 435
    .line 436
    if-nez p0, :cond_10

    .line 437
    .line 438
    goto :goto_8

    .line 439
    :cond_10
    const-string p0, "No nodes can be emitted before calling dactivateToEndGroup"

    .line 440
    .line 441
    invoke-static {p0}, Ll2/v;->c(Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    :goto_8
    iget-boolean p0, p1, Ll2/t;->S:Z

    .line 445
    .line 446
    if-nez p0, :cond_12

    .line 447
    .line 448
    if-nez p2, :cond_11

    .line 449
    .line 450
    invoke-virtual {p1}, Ll2/t;->Q()V

    .line 451
    .line 452
    .line 453
    goto :goto_9

    .line 454
    :cond_11
    iget-object p0, p1, Ll2/t;->G:Ll2/e2;

    .line 455
    .line 456
    iget p2, p0, Ll2/e2;->g:I

    .line 457
    .line 458
    iget p0, p0, Ll2/e2;->h:I

    .line 459
    .line 460
    iget-object v0, p1, Ll2/t;->M:Lm2/b;

    .line 461
    .line 462
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 463
    .line 464
    .line 465
    invoke-virtual {v0, v2}, Lm2/b;->d(Z)V

    .line 466
    .line 467
    .line 468
    iget-object v0, v0, Lm2/b;->b:Lm2/a;

    .line 469
    .line 470
    iget-object v0, v0, Lm2/a;->b:Lm2/l0;

    .line 471
    .line 472
    sget-object v1, Lm2/i;->c:Lm2/i;

    .line 473
    .line 474
    invoke-virtual {v0, v1}, Lm2/l0;->h(Lm2/j0;)V

    .line 475
    .line 476
    .line 477
    iget-object v0, p1, Ll2/t;->s:Ljava/util/ArrayList;

    .line 478
    .line 479
    invoke-static {p2, p0, v0}, Ll2/v;->a(IILjava/util/List;)V

    .line 480
    .line 481
    .line 482
    iget-object p0, p1, Ll2/t;->G:Ll2/e2;

    .line 483
    .line 484
    invoke-virtual {p0}, Ll2/e2;->t()V

    .line 485
    .line 486
    .line 487
    :cond_12
    :goto_9
    iget-boolean p0, p1, Ll2/t;->y:Z

    .line 488
    .line 489
    if-eqz p0, :cond_13

    .line 490
    .line 491
    iget-object p0, p1, Ll2/t;->G:Ll2/e2;

    .line 492
    .line 493
    iget p0, p0, Ll2/e2;->i:I

    .line 494
    .line 495
    iget p2, p1, Ll2/t;->z:I

    .line 496
    .line 497
    if-ne p0, p2, :cond_13

    .line 498
    .line 499
    const/4 p0, -0x1

    .line 500
    iput p0, p1, Ll2/t;->z:I

    .line 501
    .line 502
    iput-boolean v2, p1, Ll2/t;->y:Z

    .line 503
    .line 504
    :cond_13
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 505
    .line 506
    .line 507
    goto :goto_a

    .line 508
    :cond_14
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 509
    .line 510
    .line 511
    :goto_a
    return-object v5

    .line 512
    :pswitch_7
    check-cast p1, Ll2/o;

    .line 513
    .line 514
    check-cast p2, Ljava/lang/Number;

    .line 515
    .line 516
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 517
    .line 518
    .line 519
    check-cast v4, Lx2/s;

    .line 520
    .line 521
    check-cast p0, Lt2/b;

    .line 522
    .line 523
    const/16 p2, 0x31

    .line 524
    .line 525
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 526
    .line 527
    .line 528
    move-result p2

    .line 529
    invoke-static {v4, p0, p1, p2}, Llp/vd;->a(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 530
    .line 531
    .line 532
    return-object v5

    .line 533
    :pswitch_data_0
    .packed-switch 0x0
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
