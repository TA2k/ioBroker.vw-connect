.class public final Lh2/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    iput p1, p0, Lh2/e;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lh2/e;->e:Lay0/n;

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
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x1

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v6

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    and-int/2addr v2, v6

    .line 31
    check-cast v1, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_4

    .line 38
    .line 39
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 40
    .line 41
    const-string v3, "Container"

    .line 42
    .line 43
    invoke-static {v2, v3}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 48
    .line 49
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    iget-wide v7, v1, Ll2/t;->T:J

    .line 54
    .line 55
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 68
    .line 69
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 73
    .line 74
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 75
    .line 76
    .line 77
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 78
    .line 79
    if-eqz v9, :cond_1

    .line 80
    .line 81
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 86
    .line 87
    .line 88
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 89
    .line 90
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 91
    .line 92
    .line 93
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 94
    .line 95
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 96
    .line 97
    .line 98
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 99
    .line 100
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 101
    .line 102
    if-nez v7, :cond_2

    .line 103
    .line 104
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 109
    .line 110
    .line 111
    move-result-object v8

    .line 112
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v7

    .line 116
    if-nez v7, :cond_3

    .line 117
    .line 118
    :cond_2
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 119
    .line 120
    .line 121
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 122
    .line 123
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 124
    .line 125
    .line 126
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 127
    .line 128
    invoke-static {v5, v0, v1, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 129
    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 133
    .line 134
    .line 135
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    return-object v0

    .line 138
    :pswitch_0
    move-object/from16 v1, p1

    .line 139
    .line 140
    check-cast v1, Ll2/o;

    .line 141
    .line 142
    move-object/from16 v2, p2

    .line 143
    .line 144
    check-cast v2, Ljava/lang/Number;

    .line 145
    .line 146
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 147
    .line 148
    .line 149
    move-result v2

    .line 150
    and-int/lit8 v3, v2, 0x3

    .line 151
    .line 152
    const/4 v4, 0x2

    .line 153
    const/4 v5, 0x0

    .line 154
    const/4 v6, 0x1

    .line 155
    if-eq v3, v4, :cond_5

    .line 156
    .line 157
    move v3, v6

    .line 158
    goto :goto_3

    .line 159
    :cond_5
    move v3, v5

    .line 160
    :goto_3
    and-int/2addr v2, v6

    .line 161
    check-cast v1, Ll2/t;

    .line 162
    .line 163
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    if-eqz v2, :cond_6

    .line 168
    .line 169
    sget-object v2, Lk2/c0;->e:Lk2/p0;

    .line 170
    .line 171
    invoke-static {v2, v1}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    const/16 v19, 0x0

    .line 176
    .line 177
    const v20, 0xff7fff

    .line 178
    .line 179
    .line 180
    const-wide/16 v7, 0x0

    .line 181
    .line 182
    const-wide/16 v9, 0x0

    .line 183
    .line 184
    const/4 v11, 0x0

    .line 185
    const/4 v12, 0x0

    .line 186
    const-wide/16 v13, 0x0

    .line 187
    .line 188
    const/4 v15, 0x3

    .line 189
    const-wide/16 v16, 0x0

    .line 190
    .line 191
    const/16 v18, 0x0

    .line 192
    .line 193
    invoke-static/range {v6 .. v20}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 198
    .line 199
    invoke-static {v2, v0, v1, v5}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 200
    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_6
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 204
    .line 205
    .line 206
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 207
    .line 208
    return-object v0

    .line 209
    :pswitch_1
    move-object/from16 v1, p1

    .line 210
    .line 211
    check-cast v1, Ll2/o;

    .line 212
    .line 213
    move-object/from16 v2, p2

    .line 214
    .line 215
    check-cast v2, Ljava/lang/Number;

    .line 216
    .line 217
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 218
    .line 219
    .line 220
    move-result v2

    .line 221
    and-int/lit8 v3, v2, 0x3

    .line 222
    .line 223
    const/4 v4, 0x2

    .line 224
    const/4 v5, 0x1

    .line 225
    const/4 v6, 0x0

    .line 226
    if-eq v3, v4, :cond_7

    .line 227
    .line 228
    move v3, v5

    .line 229
    goto :goto_5

    .line 230
    :cond_7
    move v3, v6

    .line 231
    :goto_5
    and-int/2addr v2, v5

    .line 232
    check-cast v1, Ll2/t;

    .line 233
    .line 234
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 235
    .line 236
    .line 237
    move-result v2

    .line 238
    if-eqz v2, :cond_b

    .line 239
    .line 240
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 241
    .line 242
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    iget-wide v3, v1, Ll2/t;->T:J

    .line 247
    .line 248
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 249
    .line 250
    .line 251
    move-result v3

    .line 252
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 257
    .line 258
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 259
    .line 260
    .line 261
    move-result-object v7

    .line 262
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 263
    .line 264
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 265
    .line 266
    .line 267
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 268
    .line 269
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 270
    .line 271
    .line 272
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 273
    .line 274
    if-eqz v9, :cond_8

    .line 275
    .line 276
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 277
    .line 278
    .line 279
    goto :goto_6

    .line 280
    :cond_8
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 281
    .line 282
    .line 283
    :goto_6
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 284
    .line 285
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 286
    .line 287
    .line 288
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 289
    .line 290
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 291
    .line 292
    .line 293
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 294
    .line 295
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 296
    .line 297
    if-nez v4, :cond_9

    .line 298
    .line 299
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v4

    .line 303
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 304
    .line 305
    .line 306
    move-result-object v8

    .line 307
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    if-nez v4, :cond_a

    .line 312
    .line 313
    :cond_9
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 314
    .line 315
    .line 316
    :cond_a
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 317
    .line 318
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 319
    .line 320
    .line 321
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 322
    .line 323
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 324
    .line 325
    .line 326
    goto :goto_7

    .line 327
    :cond_b
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 328
    .line 329
    .line 330
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 331
    .line 332
    return-object v0

    .line 333
    :pswitch_2
    move-object/from16 v1, p1

    .line 334
    .line 335
    check-cast v1, Ll2/o;

    .line 336
    .line 337
    move-object/from16 v2, p2

    .line 338
    .line 339
    check-cast v2, Ljava/lang/Number;

    .line 340
    .line 341
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    and-int/lit8 v3, v2, 0x3

    .line 346
    .line 347
    const/4 v4, 0x2

    .line 348
    const/4 v5, 0x1

    .line 349
    const/4 v6, 0x0

    .line 350
    if-eq v3, v4, :cond_c

    .line 351
    .line 352
    move v3, v5

    .line 353
    goto :goto_8

    .line 354
    :cond_c
    move v3, v6

    .line 355
    :goto_8
    and-int/2addr v2, v5

    .line 356
    check-cast v1, Ll2/t;

    .line 357
    .line 358
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 359
    .line 360
    .line 361
    move-result v2

    .line 362
    if-eqz v2, :cond_10

    .line 363
    .line 364
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 365
    .line 366
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    iget-wide v3, v1, Ll2/t;->T:J

    .line 371
    .line 372
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 373
    .line 374
    .line 375
    move-result v3

    .line 376
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 377
    .line 378
    .line 379
    move-result-object v4

    .line 380
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 381
    .line 382
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 383
    .line 384
    .line 385
    move-result-object v7

    .line 386
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 387
    .line 388
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 389
    .line 390
    .line 391
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 392
    .line 393
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 394
    .line 395
    .line 396
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 397
    .line 398
    if-eqz v9, :cond_d

    .line 399
    .line 400
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 401
    .line 402
    .line 403
    goto :goto_9

    .line 404
    :cond_d
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 405
    .line 406
    .line 407
    :goto_9
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 408
    .line 409
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 410
    .line 411
    .line 412
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 413
    .line 414
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 415
    .line 416
    .line 417
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 418
    .line 419
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 420
    .line 421
    if-nez v4, :cond_e

    .line 422
    .line 423
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v4

    .line 427
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 428
    .line 429
    .line 430
    move-result-object v8

    .line 431
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    move-result v4

    .line 435
    if-nez v4, :cond_f

    .line 436
    .line 437
    :cond_e
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 438
    .line 439
    .line 440
    :cond_f
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 441
    .line 442
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 443
    .line 444
    .line 445
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 446
    .line 447
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 448
    .line 449
    .line 450
    goto :goto_a

    .line 451
    :cond_10
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 452
    .line 453
    .line 454
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 455
    .line 456
    return-object v0

    .line 457
    :pswitch_3
    move-object/from16 v1, p1

    .line 458
    .line 459
    check-cast v1, Ll2/o;

    .line 460
    .line 461
    move-object/from16 v2, p2

    .line 462
    .line 463
    check-cast v2, Ljava/lang/Number;

    .line 464
    .line 465
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 466
    .line 467
    .line 468
    move-result v2

    .line 469
    and-int/lit8 v3, v2, 0x3

    .line 470
    .line 471
    const/4 v4, 0x2

    .line 472
    const/4 v5, 0x1

    .line 473
    const/4 v6, 0x0

    .line 474
    if-eq v3, v4, :cond_11

    .line 475
    .line 476
    move v3, v5

    .line 477
    goto :goto_b

    .line 478
    :cond_11
    move v3, v6

    .line 479
    :goto_b
    and-int/2addr v2, v5

    .line 480
    check-cast v1, Ll2/t;

    .line 481
    .line 482
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 483
    .line 484
    .line 485
    move-result v2

    .line 486
    if-eqz v2, :cond_15

    .line 487
    .line 488
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 489
    .line 490
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 491
    .line 492
    .line 493
    move-result-object v2

    .line 494
    iget-wide v3, v1, Ll2/t;->T:J

    .line 495
    .line 496
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 497
    .line 498
    .line 499
    move-result v3

    .line 500
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 501
    .line 502
    .line 503
    move-result-object v4

    .line 504
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 505
    .line 506
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 507
    .line 508
    .line 509
    move-result-object v7

    .line 510
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 511
    .line 512
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 513
    .line 514
    .line 515
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 516
    .line 517
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 518
    .line 519
    .line 520
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 521
    .line 522
    if-eqz v9, :cond_12

    .line 523
    .line 524
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 525
    .line 526
    .line 527
    goto :goto_c

    .line 528
    :cond_12
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 529
    .line 530
    .line 531
    :goto_c
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 532
    .line 533
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 534
    .line 535
    .line 536
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 537
    .line 538
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 539
    .line 540
    .line 541
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 542
    .line 543
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 544
    .line 545
    if-nez v4, :cond_13

    .line 546
    .line 547
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 548
    .line 549
    .line 550
    move-result-object v4

    .line 551
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 552
    .line 553
    .line 554
    move-result-object v8

    .line 555
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 556
    .line 557
    .line 558
    move-result v4

    .line 559
    if-nez v4, :cond_14

    .line 560
    .line 561
    :cond_13
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 562
    .line 563
    .line 564
    :cond_14
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 565
    .line 566
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 567
    .line 568
    .line 569
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 570
    .line 571
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 572
    .line 573
    .line 574
    goto :goto_d

    .line 575
    :cond_15
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 576
    .line 577
    .line 578
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 579
    .line 580
    return-object v0

    .line 581
    :pswitch_4
    move-object/from16 v1, p1

    .line 582
    .line 583
    check-cast v1, Ll2/o;

    .line 584
    .line 585
    move-object/from16 v2, p2

    .line 586
    .line 587
    check-cast v2, Ljava/lang/Number;

    .line 588
    .line 589
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 590
    .line 591
    .line 592
    move-result v2

    .line 593
    and-int/lit8 v3, v2, 0x3

    .line 594
    .line 595
    const/4 v4, 0x2

    .line 596
    const/4 v5, 0x1

    .line 597
    const/4 v6, 0x0

    .line 598
    if-eq v3, v4, :cond_16

    .line 599
    .line 600
    move v3, v5

    .line 601
    goto :goto_e

    .line 602
    :cond_16
    move v3, v6

    .line 603
    :goto_e
    and-int/2addr v2, v5

    .line 604
    check-cast v1, Ll2/t;

    .line 605
    .line 606
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 607
    .line 608
    .line 609
    move-result v2

    .line 610
    if-eqz v2, :cond_1a

    .line 611
    .line 612
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 613
    .line 614
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 615
    .line 616
    .line 617
    move-result-object v2

    .line 618
    iget-wide v3, v1, Ll2/t;->T:J

    .line 619
    .line 620
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 621
    .line 622
    .line 623
    move-result v3

    .line 624
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 625
    .line 626
    .line 627
    move-result-object v4

    .line 628
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 629
    .line 630
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 631
    .line 632
    .line 633
    move-result-object v7

    .line 634
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 635
    .line 636
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 637
    .line 638
    .line 639
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 640
    .line 641
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 642
    .line 643
    .line 644
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 645
    .line 646
    if-eqz v9, :cond_17

    .line 647
    .line 648
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 649
    .line 650
    .line 651
    goto :goto_f

    .line 652
    :cond_17
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 653
    .line 654
    .line 655
    :goto_f
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 656
    .line 657
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 658
    .line 659
    .line 660
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 661
    .line 662
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 663
    .line 664
    .line 665
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 666
    .line 667
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 668
    .line 669
    if-nez v4, :cond_18

    .line 670
    .line 671
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    move-result-object v4

    .line 675
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 676
    .line 677
    .line 678
    move-result-object v8

    .line 679
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 680
    .line 681
    .line 682
    move-result v4

    .line 683
    if-nez v4, :cond_19

    .line 684
    .line 685
    :cond_18
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 686
    .line 687
    .line 688
    :cond_19
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 689
    .line 690
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 691
    .line 692
    .line 693
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 694
    .line 695
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 696
    .line 697
    .line 698
    goto :goto_10

    .line 699
    :cond_1a
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 700
    .line 701
    .line 702
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 703
    .line 704
    return-object v0

    .line 705
    :pswitch_5
    move-object/from16 v1, p1

    .line 706
    .line 707
    check-cast v1, Ll2/o;

    .line 708
    .line 709
    move-object/from16 v2, p2

    .line 710
    .line 711
    check-cast v2, Ljava/lang/Number;

    .line 712
    .line 713
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 714
    .line 715
    .line 716
    move-result v2

    .line 717
    and-int/lit8 v3, v2, 0x3

    .line 718
    .line 719
    const/4 v4, 0x2

    .line 720
    const/4 v5, 0x1

    .line 721
    const/4 v6, 0x0

    .line 722
    if-eq v3, v4, :cond_1b

    .line 723
    .line 724
    move v3, v5

    .line 725
    goto :goto_11

    .line 726
    :cond_1b
    move v3, v6

    .line 727
    :goto_11
    and-int/2addr v2, v5

    .line 728
    check-cast v1, Ll2/t;

    .line 729
    .line 730
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 731
    .line 732
    .line 733
    move-result v2

    .line 734
    if-eqz v2, :cond_1f

    .line 735
    .line 736
    sget-object v2, Lx2/c;->j:Lx2/j;

    .line 737
    .line 738
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 739
    .line 740
    .line 741
    move-result-object v2

    .line 742
    iget-wide v3, v1, Ll2/t;->T:J

    .line 743
    .line 744
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 745
    .line 746
    .line 747
    move-result v3

    .line 748
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 749
    .line 750
    .line 751
    move-result-object v4

    .line 752
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 753
    .line 754
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 755
    .line 756
    .line 757
    move-result-object v7

    .line 758
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 759
    .line 760
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 761
    .line 762
    .line 763
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 764
    .line 765
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 766
    .line 767
    .line 768
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 769
    .line 770
    if-eqz v9, :cond_1c

    .line 771
    .line 772
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 773
    .line 774
    .line 775
    goto :goto_12

    .line 776
    :cond_1c
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 777
    .line 778
    .line 779
    :goto_12
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 780
    .line 781
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 782
    .line 783
    .line 784
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 785
    .line 786
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 787
    .line 788
    .line 789
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 790
    .line 791
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 792
    .line 793
    if-nez v4, :cond_1d

    .line 794
    .line 795
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 796
    .line 797
    .line 798
    move-result-object v4

    .line 799
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 800
    .line 801
    .line 802
    move-result-object v8

    .line 803
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 804
    .line 805
    .line 806
    move-result v4

    .line 807
    if-nez v4, :cond_1e

    .line 808
    .line 809
    :cond_1d
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 810
    .line 811
    .line 812
    :cond_1e
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 813
    .line 814
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 815
    .line 816
    .line 817
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 818
    .line 819
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 820
    .line 821
    .line 822
    goto :goto_13

    .line 823
    :cond_1f
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 824
    .line 825
    .line 826
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 827
    .line 828
    return-object v0

    .line 829
    :pswitch_6
    move-object/from16 v1, p1

    .line 830
    .line 831
    check-cast v1, Ll2/o;

    .line 832
    .line 833
    move-object/from16 v2, p2

    .line 834
    .line 835
    check-cast v2, Ljava/lang/Number;

    .line 836
    .line 837
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 838
    .line 839
    .line 840
    move-result v2

    .line 841
    and-int/lit8 v3, v2, 0x3

    .line 842
    .line 843
    const/4 v4, 0x2

    .line 844
    const/4 v5, 0x1

    .line 845
    const/4 v6, 0x0

    .line 846
    if-eq v3, v4, :cond_20

    .line 847
    .line 848
    move v3, v5

    .line 849
    goto :goto_14

    .line 850
    :cond_20
    move v3, v6

    .line 851
    :goto_14
    and-int/2addr v2, v5

    .line 852
    check-cast v1, Ll2/t;

    .line 853
    .line 854
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 855
    .line 856
    .line 857
    move-result v2

    .line 858
    if-eqz v2, :cond_26

    .line 859
    .line 860
    const/high16 v2, 0x3f800000    # 1.0f

    .line 861
    .line 862
    float-to-double v3, v2

    .line 863
    const-wide/16 v7, 0x0

    .line 864
    .line 865
    cmpl-double v3, v3, v7

    .line 866
    .line 867
    if-lez v3, :cond_21

    .line 868
    .line 869
    goto :goto_15

    .line 870
    :cond_21
    const-string v3, "invalid weight; must be greater than zero"

    .line 871
    .line 872
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 873
    .line 874
    .line 875
    :goto_15
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 876
    .line 877
    const v4, 0x7f7fffff    # Float.MAX_VALUE

    .line 878
    .line 879
    .line 880
    cmpl-float v7, v2, v4

    .line 881
    .line 882
    if-lez v7, :cond_22

    .line 883
    .line 884
    move v2, v4

    .line 885
    :cond_22
    invoke-direct {v3, v2, v5}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 886
    .line 887
    .line 888
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 889
    .line 890
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 891
    .line 892
    .line 893
    move-result-object v2

    .line 894
    iget-wide v7, v1, Ll2/t;->T:J

    .line 895
    .line 896
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 897
    .line 898
    .line 899
    move-result v4

    .line 900
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 901
    .line 902
    .line 903
    move-result-object v7

    .line 904
    invoke-static {v1, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 905
    .line 906
    .line 907
    move-result-object v3

    .line 908
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 909
    .line 910
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 911
    .line 912
    .line 913
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 914
    .line 915
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 916
    .line 917
    .line 918
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 919
    .line 920
    if-eqz v9, :cond_23

    .line 921
    .line 922
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 923
    .line 924
    .line 925
    goto :goto_16

    .line 926
    :cond_23
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 927
    .line 928
    .line 929
    :goto_16
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 930
    .line 931
    invoke-static {v8, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 932
    .line 933
    .line 934
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 935
    .line 936
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 937
    .line 938
    .line 939
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 940
    .line 941
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 942
    .line 943
    if-nez v7, :cond_24

    .line 944
    .line 945
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 946
    .line 947
    .line 948
    move-result-object v7

    .line 949
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 950
    .line 951
    .line 952
    move-result-object v8

    .line 953
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 954
    .line 955
    .line 956
    move-result v7

    .line 957
    if-nez v7, :cond_25

    .line 958
    .line 959
    :cond_24
    invoke-static {v4, v1, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 960
    .line 961
    .line 962
    :cond_25
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 963
    .line 964
    invoke-static {v2, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 965
    .line 966
    .line 967
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 968
    .line 969
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 970
    .line 971
    .line 972
    goto :goto_17

    .line 973
    :cond_26
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 974
    .line 975
    .line 976
    :goto_17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 977
    .line 978
    return-object v0

    .line 979
    :pswitch_7
    move-object/from16 v1, p1

    .line 980
    .line 981
    check-cast v1, Ll2/o;

    .line 982
    .line 983
    move-object/from16 v2, p2

    .line 984
    .line 985
    check-cast v2, Ljava/lang/Number;

    .line 986
    .line 987
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 988
    .line 989
    .line 990
    move-result v2

    .line 991
    and-int/lit8 v3, v2, 0x3

    .line 992
    .line 993
    const/4 v4, 0x2

    .line 994
    const/4 v5, 0x1

    .line 995
    const/4 v6, 0x0

    .line 996
    if-eq v3, v4, :cond_27

    .line 997
    .line 998
    move v3, v5

    .line 999
    goto :goto_18

    .line 1000
    :cond_27
    move v3, v6

    .line 1001
    :goto_18
    and-int/2addr v2, v5

    .line 1002
    check-cast v1, Ll2/t;

    .line 1003
    .line 1004
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1005
    .line 1006
    .line 1007
    move-result v2

    .line 1008
    if-eqz v2, :cond_2c

    .line 1009
    .line 1010
    const/high16 v2, 0x3f800000    # 1.0f

    .line 1011
    .line 1012
    float-to-double v3, v2

    .line 1013
    const-wide/16 v7, 0x0

    .line 1014
    .line 1015
    cmpl-double v3, v3, v7

    .line 1016
    .line 1017
    if-lez v3, :cond_28

    .line 1018
    .line 1019
    goto :goto_19

    .line 1020
    :cond_28
    const-string v3, "invalid weight; must be greater than zero"

    .line 1021
    .line 1022
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 1023
    .line 1024
    .line 1025
    :goto_19
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 1026
    .line 1027
    invoke-direct {v3, v2, v6}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 1028
    .line 1029
    .line 1030
    sget-object v2, Lh2/j;->g:Lk1/a1;

    .line 1031
    .line 1032
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v2

    .line 1036
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 1037
    .line 1038
    invoke-static {v3, v2}, Lia/b;->p(Lx2/h;Lx2/s;)Lx2/s;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v2

    .line 1042
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 1043
    .line 1044
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v3

    .line 1048
    iget-wide v7, v1, Ll2/t;->T:J

    .line 1049
    .line 1050
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 1051
    .line 1052
    .line 1053
    move-result v4

    .line 1054
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v7

    .line 1058
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v2

    .line 1062
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 1063
    .line 1064
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1065
    .line 1066
    .line 1067
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 1068
    .line 1069
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 1070
    .line 1071
    .line 1072
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 1073
    .line 1074
    if-eqz v9, :cond_29

    .line 1075
    .line 1076
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 1077
    .line 1078
    .line 1079
    goto :goto_1a

    .line 1080
    :cond_29
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 1081
    .line 1082
    .line 1083
    :goto_1a
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 1084
    .line 1085
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1086
    .line 1087
    .line 1088
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 1089
    .line 1090
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1091
    .line 1092
    .line 1093
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 1094
    .line 1095
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 1096
    .line 1097
    if-nez v7, :cond_2a

    .line 1098
    .line 1099
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v7

    .line 1103
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1104
    .line 1105
    .line 1106
    move-result-object v8

    .line 1107
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1108
    .line 1109
    .line 1110
    move-result v7

    .line 1111
    if-nez v7, :cond_2b

    .line 1112
    .line 1113
    :cond_2a
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1114
    .line 1115
    .line 1116
    :cond_2b
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 1117
    .line 1118
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1119
    .line 1120
    .line 1121
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 1122
    .line 1123
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 1124
    .line 1125
    .line 1126
    goto :goto_1b

    .line 1127
    :cond_2c
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1128
    .line 1129
    .line 1130
    :goto_1b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1131
    .line 1132
    return-object v0

    .line 1133
    :pswitch_8
    move-object/from16 v1, p1

    .line 1134
    .line 1135
    check-cast v1, Ll2/o;

    .line 1136
    .line 1137
    move-object/from16 v2, p2

    .line 1138
    .line 1139
    check-cast v2, Ljava/lang/Number;

    .line 1140
    .line 1141
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1142
    .line 1143
    .line 1144
    move-result v2

    .line 1145
    and-int/lit8 v3, v2, 0x3

    .line 1146
    .line 1147
    const/4 v4, 0x2

    .line 1148
    const/4 v5, 0x1

    .line 1149
    const/4 v6, 0x0

    .line 1150
    if-eq v3, v4, :cond_2d

    .line 1151
    .line 1152
    move v3, v5

    .line 1153
    goto :goto_1c

    .line 1154
    :cond_2d
    move v3, v6

    .line 1155
    :goto_1c
    and-int/2addr v2, v5

    .line 1156
    check-cast v1, Ll2/t;

    .line 1157
    .line 1158
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1159
    .line 1160
    .line 1161
    move-result v2

    .line 1162
    if-eqz v2, :cond_31

    .line 1163
    .line 1164
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 1165
    .line 1166
    sget-object v3, Lh2/j;->f:Lk1/a1;

    .line 1167
    .line 1168
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v2

    .line 1172
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 1173
    .line 1174
    invoke-static {v3, v2}, Lia/b;->p(Lx2/h;Lx2/s;)Lx2/s;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v2

    .line 1178
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 1179
    .line 1180
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v3

    .line 1184
    iget-wide v7, v1, Ll2/t;->T:J

    .line 1185
    .line 1186
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 1187
    .line 1188
    .line 1189
    move-result v4

    .line 1190
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 1191
    .line 1192
    .line 1193
    move-result-object v7

    .line 1194
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1195
    .line 1196
    .line 1197
    move-result-object v2

    .line 1198
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 1199
    .line 1200
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1201
    .line 1202
    .line 1203
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 1204
    .line 1205
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 1206
    .line 1207
    .line 1208
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 1209
    .line 1210
    if-eqz v9, :cond_2e

    .line 1211
    .line 1212
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 1213
    .line 1214
    .line 1215
    goto :goto_1d

    .line 1216
    :cond_2e
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 1217
    .line 1218
    .line 1219
    :goto_1d
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 1220
    .line 1221
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1222
    .line 1223
    .line 1224
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 1225
    .line 1226
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1227
    .line 1228
    .line 1229
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 1230
    .line 1231
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 1232
    .line 1233
    if-nez v7, :cond_2f

    .line 1234
    .line 1235
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1236
    .line 1237
    .line 1238
    move-result-object v7

    .line 1239
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1240
    .line 1241
    .line 1242
    move-result-object v8

    .line 1243
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1244
    .line 1245
    .line 1246
    move-result v7

    .line 1247
    if-nez v7, :cond_30

    .line 1248
    .line 1249
    :cond_2f
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1250
    .line 1251
    .line 1252
    :cond_30
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 1253
    .line 1254
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1255
    .line 1256
    .line 1257
    iget-object v0, v0, Lh2/e;->e:Lay0/n;

    .line 1258
    .line 1259
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 1260
    .line 1261
    .line 1262
    goto :goto_1e

    .line 1263
    :cond_31
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1264
    .line 1265
    .line 1266
    :goto_1e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1267
    .line 1268
    return-object v0

    .line 1269
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
