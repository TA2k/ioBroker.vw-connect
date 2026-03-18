.class public final synthetic Ly21/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz21/g;


# direct methods
.method public synthetic constructor <init>(Lz21/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly21/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly21/b;->e:Lz21/g;

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
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ly21/b;->d:I

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
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

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
    const/4 v5, 0x1

    .line 24
    const/4 v6, 0x0

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v5

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v6

    .line 30
    :goto_0
    and-int/2addr v2, v5

    .line 31
    move-object v13, v1

    .line 32
    check-cast v13, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_8

    .line 39
    .line 40
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 41
    .line 42
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 51
    .line 52
    if-nez v1, :cond_1

    .line 53
    .line 54
    if-ne v2, v3, :cond_2

    .line 55
    .line 56
    :cond_1
    new-instance v2, Ly21/c;

    .line 57
    .line 58
    const/4 v1, 0x3

    .line 59
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    move-object/from16 v20, v2

    .line 66
    .line 67
    check-cast v20, Lay0/a;

    .line 68
    .line 69
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    if-eqz v1, :cond_7

    .line 74
    .line 75
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 76
    .line 77
    .line 78
    move-result-object v17

    .line 79
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 80
    .line 81
    .line 82
    move-result-object v19

    .line 83
    const v2, -0x6040e0aa

    .line 84
    .line 85
    .line 86
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 87
    .line 88
    .line 89
    const-class v2, Lt31/n;

    .line 90
    .line 91
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 92
    .line 93
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 94
    .line 95
    .line 96
    move-result-object v14

    .line 97
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 98
    .line 99
    .line 100
    move-result-object v15

    .line 101
    const/16 v16, 0x0

    .line 102
    .line 103
    const/16 v18, 0x0

    .line 104
    .line 105
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 110
    .line 111
    .line 112
    check-cast v1, Lt31/n;

    .line 113
    .line 114
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    if-nez v2, :cond_3

    .line 123
    .line 124
    if-ne v4, v3, :cond_4

    .line 125
    .line 126
    :cond_3
    new-instance v4, Lt31/j;

    .line 127
    .line 128
    const/4 v2, 0x1

    .line 129
    invoke-direct {v4, v1, v2}, Lt31/j;-><init>(Lt31/n;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :cond_4
    check-cast v4, Lay0/k;

    .line 136
    .line 137
    const/4 v2, 0x0

    .line 138
    invoke-static {v1, v2, v4, v13, v6}, Ljp/ba;->a(Ljava/lang/Object;Landroidx/lifecycle/x;Lay0/k;Ll2/o;I)V

    .line 139
    .line 140
    .line 141
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 142
    .line 143
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 148
    .line 149
    iget-object v4, v4, Lg1/q;->b:Ljava/lang/Object;

    .line 150
    .line 151
    move-object v8, v4

    .line 152
    check-cast v8, Lz70/d;

    .line 153
    .line 154
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 155
    .line 156
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    move-object v10, v2

    .line 161
    check-cast v10, Lt31/o;

    .line 162
    .line 163
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v4

    .line 171
    if-nez v2, :cond_5

    .line 172
    .line 173
    if-ne v4, v3, :cond_6

    .line 174
    .line 175
    :cond_5
    new-instance v14, Lwc/a;

    .line 176
    .line 177
    const/16 v20, 0x0

    .line 178
    .line 179
    const/16 v21, 0x1c

    .line 180
    .line 181
    const/4 v15, 0x1

    .line 182
    const-class v17, Lt31/n;

    .line 183
    .line 184
    const-string v18, "onEvent"

    .line 185
    .line 186
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/newrequest/NewRequestViewEvent;)V"

    .line 187
    .line 188
    move-object/from16 v16, v1

    .line 189
    .line 190
    invoke-direct/range {v14 .. v21}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    move-object v4, v14

    .line 197
    :cond_6
    check-cast v4, Lhy0/g;

    .line 198
    .line 199
    move-object v11, v4

    .line 200
    check-cast v11, Lay0/k;

    .line 201
    .line 202
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 203
    .line 204
    const/4 v14, 0x0

    .line 205
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 206
    .line 207
    invoke-virtual/range {v7 .. v14}, Lb41/b;->d(Lz70/d;Lay0/k;Lt31/o;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 208
    .line 209
    .line 210
    goto :goto_1

    .line 211
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 212
    .line 213
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 214
    .line 215
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    throw v0

    .line 219
    :cond_8
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 220
    .line 221
    .line 222
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 223
    .line 224
    return-object v0

    .line 225
    :pswitch_0
    move-object/from16 v1, p1

    .line 226
    .line 227
    check-cast v1, Ll2/o;

    .line 228
    .line 229
    move-object/from16 v2, p2

    .line 230
    .line 231
    check-cast v2, Ljava/lang/Integer;

    .line 232
    .line 233
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 234
    .line 235
    .line 236
    move-result v2

    .line 237
    and-int/lit8 v3, v2, 0x3

    .line 238
    .line 239
    const/4 v4, 0x2

    .line 240
    const/4 v5, 0x1

    .line 241
    const/4 v6, 0x0

    .line 242
    if-eq v3, v4, :cond_9

    .line 243
    .line 244
    move v3, v5

    .line 245
    goto :goto_2

    .line 246
    :cond_9
    move v3, v6

    .line 247
    :goto_2
    and-int/2addr v2, v5

    .line 248
    move-object v13, v1

    .line 249
    check-cast v13, Ll2/t;

    .line 250
    .line 251
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 252
    .line 253
    .line 254
    move-result v1

    .line 255
    if-eqz v1, :cond_11

    .line 256
    .line 257
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 258
    .line 259
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v1

    .line 263
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 268
    .line 269
    if-nez v1, :cond_a

    .line 270
    .line 271
    if-ne v2, v3, :cond_b

    .line 272
    .line 273
    :cond_a
    new-instance v2, Ly21/c;

    .line 274
    .line 275
    const/4 v1, 0x6

    .line 276
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    :cond_b
    move-object/from16 v20, v2

    .line 283
    .line 284
    check-cast v20, Lay0/a;

    .line 285
    .line 286
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    if-eqz v1, :cond_10

    .line 291
    .line 292
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 293
    .line 294
    .line 295
    move-result-object v17

    .line 296
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 297
    .line 298
    .line 299
    move-result-object v19

    .line 300
    const v2, -0x6040e0aa

    .line 301
    .line 302
    .line 303
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 304
    .line 305
    .line 306
    const-class v2, Lq31/h;

    .line 307
    .line 308
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 309
    .line 310
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 311
    .line 312
    .line 313
    move-result-object v14

    .line 314
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 315
    .line 316
    .line 317
    move-result-object v15

    .line 318
    const/16 v16, 0x0

    .line 319
    .line 320
    const/16 v18, 0x0

    .line 321
    .line 322
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 323
    .line 324
    .line 325
    move-result-object v1

    .line 326
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 327
    .line 328
    .line 329
    check-cast v1, Lq31/h;

    .line 330
    .line 331
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 332
    .line 333
    .line 334
    move-result v2

    .line 335
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v4

    .line 339
    if-nez v2, :cond_c

    .line 340
    .line 341
    if-ne v4, v3, :cond_d

    .line 342
    .line 343
    :cond_c
    new-instance v4, Lw81/c;

    .line 344
    .line 345
    const/16 v2, 0x1b

    .line 346
    .line 347
    invoke-direct {v4, v1, v2}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 351
    .line 352
    .line 353
    :cond_d
    check-cast v4, Lay0/k;

    .line 354
    .line 355
    const/4 v2, 0x0

    .line 356
    invoke-static {v1, v2, v4, v13, v6}, Ljp/ba;->a(Ljava/lang/Object;Landroidx/lifecycle/x;Lay0/k;Ll2/o;I)V

    .line 357
    .line 358
    .line 359
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 360
    .line 361
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 362
    .line 363
    .line 364
    move-result-object v2

    .line 365
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 366
    .line 367
    iget-object v4, v4, Lg1/q;->c:Ljava/lang/Object;

    .line 368
    .line 369
    move-object v8, v4

    .line 370
    check-cast v8, Lz70/a;

    .line 371
    .line 372
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 373
    .line 374
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v2

    .line 378
    move-object v10, v2

    .line 379
    check-cast v10, Lq31/i;

    .line 380
    .line 381
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    move-result v2

    .line 385
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v4

    .line 389
    if-nez v2, :cond_e

    .line 390
    .line 391
    if-ne v4, v3, :cond_f

    .line 392
    .line 393
    :cond_e
    new-instance v14, Ly21/d;

    .line 394
    .line 395
    const/16 v20, 0x0

    .line 396
    .line 397
    const/16 v21, 0x0

    .line 398
    .line 399
    const/4 v15, 0x1

    .line 400
    const-class v17, Lq31/h;

    .line 401
    .line 402
    const-string v18, "onEvent"

    .line 403
    .line 404
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/appointmentschedule/AppointmentScheduleViewEvent;)V"

    .line 405
    .line 406
    move-object/from16 v16, v1

    .line 407
    .line 408
    invoke-direct/range {v14 .. v21}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    move-object v4, v14

    .line 415
    :cond_f
    check-cast v4, Lhy0/g;

    .line 416
    .line 417
    move-object v11, v4

    .line 418
    check-cast v11, Lay0/k;

    .line 419
    .line 420
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 421
    .line 422
    const/4 v14, 0x0

    .line 423
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 424
    .line 425
    invoke-virtual/range {v7 .. v14}, Lb41/b;->c(Lz70/a;Lay0/k;Lq31/i;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 426
    .line 427
    .line 428
    goto :goto_3

    .line 429
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 430
    .line 431
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 432
    .line 433
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 434
    .line 435
    .line 436
    throw v0

    .line 437
    :cond_11
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 438
    .line 439
    .line 440
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 441
    .line 442
    return-object v0

    .line 443
    :pswitch_1
    move-object/from16 v1, p1

    .line 444
    .line 445
    check-cast v1, Ll2/o;

    .line 446
    .line 447
    move-object/from16 v2, p2

    .line 448
    .line 449
    check-cast v2, Ljava/lang/Integer;

    .line 450
    .line 451
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 452
    .line 453
    .line 454
    move-result v2

    .line 455
    and-int/lit8 v3, v2, 0x3

    .line 456
    .line 457
    const/4 v4, 0x2

    .line 458
    const/4 v5, 0x1

    .line 459
    const/4 v6, 0x0

    .line 460
    if-eq v3, v4, :cond_12

    .line 461
    .line 462
    move v3, v5

    .line 463
    goto :goto_4

    .line 464
    :cond_12
    move v3, v6

    .line 465
    :goto_4
    and-int/2addr v2, v5

    .line 466
    move-object v13, v1

    .line 467
    check-cast v13, Ll2/t;

    .line 468
    .line 469
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 470
    .line 471
    .line 472
    move-result v1

    .line 473
    if-eqz v1, :cond_18

    .line 474
    .line 475
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 476
    .line 477
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    move-result v1

    .line 481
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move-result-object v2

    .line 485
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 486
    .line 487
    if-nez v1, :cond_13

    .line 488
    .line 489
    if-ne v2, v3, :cond_14

    .line 490
    .line 491
    :cond_13
    new-instance v2, Ly21/c;

    .line 492
    .line 493
    const/4 v1, 0x1

    .line 494
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 495
    .line 496
    .line 497
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 498
    .line 499
    .line 500
    :cond_14
    move-object/from16 v20, v2

    .line 501
    .line 502
    check-cast v20, Lay0/a;

    .line 503
    .line 504
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 505
    .line 506
    .line 507
    move-result-object v1

    .line 508
    if-eqz v1, :cond_17

    .line 509
    .line 510
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 511
    .line 512
    .line 513
    move-result-object v17

    .line 514
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 515
    .line 516
    .line 517
    move-result-object v19

    .line 518
    const v2, -0x6040e0aa

    .line 519
    .line 520
    .line 521
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 522
    .line 523
    .line 524
    const-class v2, Ls31/i;

    .line 525
    .line 526
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 527
    .line 528
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 529
    .line 530
    .line 531
    move-result-object v14

    .line 532
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 533
    .line 534
    .line 535
    move-result-object v15

    .line 536
    const/16 v16, 0x0

    .line 537
    .line 538
    const/16 v18, 0x0

    .line 539
    .line 540
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 541
    .line 542
    .line 543
    move-result-object v1

    .line 544
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 545
    .line 546
    .line 547
    check-cast v1, Ls31/i;

    .line 548
    .line 549
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 550
    .line 551
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 552
    .line 553
    .line 554
    move-result-object v2

    .line 555
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 556
    .line 557
    iget-object v4, v4, Lg1/q;->g:Ljava/lang/Object;

    .line 558
    .line 559
    move-object v8, v4

    .line 560
    check-cast v8, Lz70/b;

    .line 561
    .line 562
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 563
    .line 564
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 565
    .line 566
    .line 567
    move-result-object v2

    .line 568
    move-object v10, v2

    .line 569
    check-cast v10, Ls31/k;

    .line 570
    .line 571
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 572
    .line 573
    .line 574
    move-result v2

    .line 575
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 576
    .line 577
    .line 578
    move-result-object v4

    .line 579
    if-nez v2, :cond_15

    .line 580
    .line 581
    if-ne v4, v3, :cond_16

    .line 582
    .line 583
    :cond_15
    new-instance v14, Lwc/a;

    .line 584
    .line 585
    const/16 v20, 0x0

    .line 586
    .line 587
    const/16 v21, 0x1a

    .line 588
    .line 589
    const/4 v15, 0x1

    .line 590
    const-class v17, Ls31/i;

    .line 591
    .line 592
    const-string v18, "onEvent"

    .line 593
    .line 594
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/msl16summary/MSL16SummaryViewEvent;)V"

    .line 595
    .line 596
    move-object/from16 v16, v1

    .line 597
    .line 598
    invoke-direct/range {v14 .. v21}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 599
    .line 600
    .line 601
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 602
    .line 603
    .line 604
    move-object v4, v14

    .line 605
    :cond_16
    check-cast v4, Lhy0/g;

    .line 606
    .line 607
    move-object v11, v4

    .line 608
    check-cast v11, Lay0/k;

    .line 609
    .line 610
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 611
    .line 612
    const/4 v14, 0x0

    .line 613
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 614
    .line 615
    invoke-virtual/range {v7 .. v14}, Lb41/b;->b(Lz70/b;Lay0/k;Ls31/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 616
    .line 617
    .line 618
    goto :goto_5

    .line 619
    :cond_17
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 620
    .line 621
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 622
    .line 623
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 624
    .line 625
    .line 626
    throw v0

    .line 627
    :cond_18
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 628
    .line 629
    .line 630
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 631
    .line 632
    return-object v0

    .line 633
    :pswitch_2
    move-object/from16 v1, p1

    .line 634
    .line 635
    check-cast v1, Ll2/o;

    .line 636
    .line 637
    move-object/from16 v2, p2

    .line 638
    .line 639
    check-cast v2, Ljava/lang/Integer;

    .line 640
    .line 641
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 642
    .line 643
    .line 644
    move-result v2

    .line 645
    and-int/lit8 v3, v2, 0x3

    .line 646
    .line 647
    const/4 v4, 0x2

    .line 648
    const/4 v5, 0x1

    .line 649
    const/4 v6, 0x0

    .line 650
    if-eq v3, v4, :cond_19

    .line 651
    .line 652
    move v3, v5

    .line 653
    goto :goto_6

    .line 654
    :cond_19
    move v3, v6

    .line 655
    :goto_6
    and-int/2addr v2, v5

    .line 656
    move-object v11, v1

    .line 657
    check-cast v11, Ll2/t;

    .line 658
    .line 659
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 660
    .line 661
    .line 662
    move-result v1

    .line 663
    if-eqz v1, :cond_1d

    .line 664
    .line 665
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 666
    .line 667
    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 668
    .line 669
    .line 670
    move-result v1

    .line 671
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    move-result-object v2

    .line 675
    if-nez v1, :cond_1a

    .line 676
    .line 677
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 678
    .line 679
    if-ne v2, v1, :cond_1b

    .line 680
    .line 681
    :cond_1a
    new-instance v2, Ly21/c;

    .line 682
    .line 683
    const/16 v1, 0x8

    .line 684
    .line 685
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 686
    .line 687
    .line 688
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 689
    .line 690
    .line 691
    :cond_1b
    move-object/from16 v18, v2

    .line 692
    .line 693
    check-cast v18, Lay0/a;

    .line 694
    .line 695
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 696
    .line 697
    .line 698
    move-result-object v1

    .line 699
    if-eqz v1, :cond_1c

    .line 700
    .line 701
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 702
    .line 703
    .line 704
    move-result-object v15

    .line 705
    invoke-static {v11}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 706
    .line 707
    .line 708
    move-result-object v17

    .line 709
    const v2, -0x6040e0aa

    .line 710
    .line 711
    .line 712
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 713
    .line 714
    .line 715
    const-class v2, Lv31/b;

    .line 716
    .line 717
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 718
    .line 719
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 720
    .line 721
    .line 722
    move-result-object v12

    .line 723
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 724
    .line 725
    .line 726
    move-result-object v13

    .line 727
    const/4 v14, 0x0

    .line 728
    const/16 v16, 0x0

    .line 729
    .line 730
    invoke-static/range {v12 .. v18}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 731
    .line 732
    .line 733
    move-result-object v1

    .line 734
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 735
    .line 736
    .line 737
    check-cast v1, Lv31/b;

    .line 738
    .line 739
    iget-object v1, v1, Lq41/b;->e:Lyy0/l1;

    .line 740
    .line 741
    invoke-static {v1, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 742
    .line 743
    .line 744
    move-result-object v1

    .line 745
    iget-object v8, v0, Lz21/g;->f:Lay0/k;

    .line 746
    .line 747
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 748
    .line 749
    .line 750
    move-result-object v1

    .line 751
    move-object v9, v1

    .line 752
    check-cast v9, Lv31/c;

    .line 753
    .line 754
    iget-object v10, v0, Lz21/g;->g:Lay0/k;

    .line 755
    .line 756
    const/4 v12, 0x0

    .line 757
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 758
    .line 759
    invoke-virtual/range {v7 .. v12}, Lb41/b;->f(Lay0/k;Lv31/c;Lay0/k;Ll2/o;I)V

    .line 760
    .line 761
    .line 762
    goto :goto_7

    .line 763
    :cond_1c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 764
    .line 765
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 766
    .line 767
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 768
    .line 769
    .line 770
    throw v0

    .line 771
    :cond_1d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 772
    .line 773
    .line 774
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 775
    .line 776
    return-object v0

    .line 777
    :pswitch_3
    move-object/from16 v1, p1

    .line 778
    .line 779
    check-cast v1, Ll2/o;

    .line 780
    .line 781
    move-object/from16 v2, p2

    .line 782
    .line 783
    check-cast v2, Ljava/lang/Integer;

    .line 784
    .line 785
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 786
    .line 787
    .line 788
    move-result v2

    .line 789
    and-int/lit8 v3, v2, 0x3

    .line 790
    .line 791
    const/4 v4, 0x2

    .line 792
    const/4 v5, 0x1

    .line 793
    const/4 v6, 0x0

    .line 794
    if-eq v3, v4, :cond_1e

    .line 795
    .line 796
    move v3, v5

    .line 797
    goto :goto_8

    .line 798
    :cond_1e
    move v3, v6

    .line 799
    :goto_8
    and-int/2addr v2, v5

    .line 800
    move-object v13, v1

    .line 801
    check-cast v13, Ll2/t;

    .line 802
    .line 803
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 804
    .line 805
    .line 806
    move-result v1

    .line 807
    if-eqz v1, :cond_26

    .line 808
    .line 809
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 810
    .line 811
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 812
    .line 813
    .line 814
    move-result v1

    .line 815
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 816
    .line 817
    .line 818
    move-result-object v2

    .line 819
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 820
    .line 821
    if-nez v1, :cond_1f

    .line 822
    .line 823
    if-ne v2, v3, :cond_20

    .line 824
    .line 825
    :cond_1f
    new-instance v2, Ly21/c;

    .line 826
    .line 827
    const/4 v1, 0x0

    .line 828
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 829
    .line 830
    .line 831
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 832
    .line 833
    .line 834
    :cond_20
    move-object/from16 v20, v2

    .line 835
    .line 836
    check-cast v20, Lay0/a;

    .line 837
    .line 838
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 839
    .line 840
    .line 841
    move-result-object v1

    .line 842
    if-eqz v1, :cond_25

    .line 843
    .line 844
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 845
    .line 846
    .line 847
    move-result-object v17

    .line 848
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 849
    .line 850
    .line 851
    move-result-object v19

    .line 852
    const v2, -0x6040e0aa

    .line 853
    .line 854
    .line 855
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 856
    .line 857
    .line 858
    const-class v2, Lr31/i;

    .line 859
    .line 860
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 861
    .line 862
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 863
    .line 864
    .line 865
    move-result-object v14

    .line 866
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 867
    .line 868
    .line 869
    move-result-object v15

    .line 870
    const/16 v16, 0x0

    .line 871
    .line 872
    const/16 v18, 0x0

    .line 873
    .line 874
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 875
    .line 876
    .line 877
    move-result-object v1

    .line 878
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 879
    .line 880
    .line 881
    check-cast v1, Lr31/i;

    .line 882
    .line 883
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 884
    .line 885
    .line 886
    move-result v2

    .line 887
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 888
    .line 889
    .line 890
    move-result-object v4

    .line 891
    if-nez v2, :cond_21

    .line 892
    .line 893
    if-ne v4, v3, :cond_22

    .line 894
    .line 895
    :cond_21
    new-instance v4, Lw81/c;

    .line 896
    .line 897
    const/16 v2, 0x1a

    .line 898
    .line 899
    invoke-direct {v4, v1, v2}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 900
    .line 901
    .line 902
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 903
    .line 904
    .line 905
    :cond_22
    check-cast v4, Lay0/k;

    .line 906
    .line 907
    const/4 v2, 0x0

    .line 908
    invoke-static {v1, v2, v4, v13, v6}, Ljp/ba;->a(Ljava/lang/Object;Landroidx/lifecycle/x;Lay0/k;Ll2/o;I)V

    .line 909
    .line 910
    .line 911
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 912
    .line 913
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 914
    .line 915
    .line 916
    move-result-object v2

    .line 917
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 918
    .line 919
    iget-object v4, v4, Lg1/q;->e:Ljava/lang/Object;

    .line 920
    .line 921
    move-object v8, v4

    .line 922
    check-cast v8, Lz70/a;

    .line 923
    .line 924
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 925
    .line 926
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 927
    .line 928
    .line 929
    move-result-object v2

    .line 930
    move-object v10, v2

    .line 931
    check-cast v10, Lr31/j;

    .line 932
    .line 933
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 934
    .line 935
    .line 936
    move-result v2

    .line 937
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 938
    .line 939
    .line 940
    move-result-object v4

    .line 941
    if-nez v2, :cond_23

    .line 942
    .line 943
    if-ne v4, v3, :cond_24

    .line 944
    .line 945
    :cond_23
    new-instance v14, Ly21/d;

    .line 946
    .line 947
    const/16 v20, 0x0

    .line 948
    .line 949
    const/16 v21, 0x3

    .line 950
    .line 951
    const/4 v15, 0x1

    .line 952
    const-class v17, Lr31/i;

    .line 953
    .line 954
    const-string v18, "onEvent"

    .line 955
    .line 956
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/licenseplate/LicensePlateViewEvent;)V"

    .line 957
    .line 958
    move-object/from16 v16, v1

    .line 959
    .line 960
    invoke-direct/range {v14 .. v21}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 961
    .line 962
    .line 963
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 964
    .line 965
    .line 966
    move-object v4, v14

    .line 967
    :cond_24
    check-cast v4, Lhy0/g;

    .line 968
    .line 969
    move-object v11, v4

    .line 970
    check-cast v11, Lay0/k;

    .line 971
    .line 972
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 973
    .line 974
    const/4 v14, 0x0

    .line 975
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 976
    .line 977
    invoke-virtual/range {v7 .. v14}, Lb41/b;->a(Lz70/a;Lay0/k;Lr31/j;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 978
    .line 979
    .line 980
    goto :goto_9

    .line 981
    :cond_25
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 982
    .line 983
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 984
    .line 985
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 986
    .line 987
    .line 988
    throw v0

    .line 989
    :cond_26
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 990
    .line 991
    .line 992
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 993
    .line 994
    return-object v0

    .line 995
    :pswitch_4
    move-object/from16 v1, p1

    .line 996
    .line 997
    check-cast v1, Ll2/o;

    .line 998
    .line 999
    move-object/from16 v2, p2

    .line 1000
    .line 1001
    check-cast v2, Ljava/lang/Integer;

    .line 1002
    .line 1003
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1004
    .line 1005
    .line 1006
    move-result v2

    .line 1007
    and-int/lit8 v3, v2, 0x3

    .line 1008
    .line 1009
    const/4 v4, 0x2

    .line 1010
    const/4 v5, 0x1

    .line 1011
    const/4 v6, 0x0

    .line 1012
    if-eq v3, v4, :cond_27

    .line 1013
    .line 1014
    move v3, v5

    .line 1015
    goto :goto_a

    .line 1016
    :cond_27
    move v3, v6

    .line 1017
    :goto_a
    and-int/2addr v2, v5

    .line 1018
    move-object v13, v1

    .line 1019
    check-cast v13, Ll2/t;

    .line 1020
    .line 1021
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1022
    .line 1023
    .line 1024
    move-result v1

    .line 1025
    if-eqz v1, :cond_2d

    .line 1026
    .line 1027
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 1028
    .line 1029
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1030
    .line 1031
    .line 1032
    move-result v1

    .line 1033
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1034
    .line 1035
    .line 1036
    move-result-object v2

    .line 1037
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 1038
    .line 1039
    if-nez v1, :cond_28

    .line 1040
    .line 1041
    if-ne v2, v3, :cond_29

    .line 1042
    .line 1043
    :cond_28
    new-instance v2, Ly21/c;

    .line 1044
    .line 1045
    const/4 v1, 0x4

    .line 1046
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 1047
    .line 1048
    .line 1049
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1050
    .line 1051
    .line 1052
    :cond_29
    move-object/from16 v20, v2

    .line 1053
    .line 1054
    check-cast v20, Lay0/a;

    .line 1055
    .line 1056
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v1

    .line 1060
    if-eqz v1, :cond_2c

    .line 1061
    .line 1062
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v17

    .line 1066
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v19

    .line 1070
    const v2, -0x6040e0aa

    .line 1071
    .line 1072
    .line 1073
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 1074
    .line 1075
    .line 1076
    const-class v2, Ly31/e;

    .line 1077
    .line 1078
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1079
    .line 1080
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1081
    .line 1082
    .line 1083
    move-result-object v14

    .line 1084
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 1085
    .line 1086
    .line 1087
    move-result-object v15

    .line 1088
    const/16 v16, 0x0

    .line 1089
    .line 1090
    const/16 v18, 0x0

    .line 1091
    .line 1092
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v1

    .line 1096
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 1097
    .line 1098
    .line 1099
    check-cast v1, Ly31/e;

    .line 1100
    .line 1101
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 1102
    .line 1103
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 1104
    .line 1105
    .line 1106
    move-result-object v2

    .line 1107
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 1108
    .line 1109
    iget-object v4, v4, Lg1/q;->j:Ljava/lang/Object;

    .line 1110
    .line 1111
    move-object v8, v4

    .line 1112
    check-cast v8, Lz70/c;

    .line 1113
    .line 1114
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 1115
    .line 1116
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1117
    .line 1118
    .line 1119
    move-result-object v2

    .line 1120
    move-object v10, v2

    .line 1121
    check-cast v10, Ly31/g;

    .line 1122
    .line 1123
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1124
    .line 1125
    .line 1126
    move-result v2

    .line 1127
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v4

    .line 1131
    if-nez v2, :cond_2a

    .line 1132
    .line 1133
    if-ne v4, v3, :cond_2b

    .line 1134
    .line 1135
    :cond_2a
    new-instance v14, Lwc/a;

    .line 1136
    .line 1137
    const/16 v20, 0x0

    .line 1138
    .line 1139
    const/16 v21, 0x1b

    .line 1140
    .line 1141
    const/4 v15, 0x1

    .line 1142
    const-class v17, Ly31/e;

    .line 1143
    .line 1144
    const-string v18, "onEvent"

    .line 1145
    .line 1146
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/sbosummary/SBOSummaryViewEvent;)V"

    .line 1147
    .line 1148
    move-object/from16 v16, v1

    .line 1149
    .line 1150
    invoke-direct/range {v14 .. v21}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1151
    .line 1152
    .line 1153
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1154
    .line 1155
    .line 1156
    move-object v4, v14

    .line 1157
    :cond_2b
    check-cast v4, Lhy0/g;

    .line 1158
    .line 1159
    move-object v11, v4

    .line 1160
    check-cast v11, Lay0/k;

    .line 1161
    .line 1162
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 1163
    .line 1164
    const/4 v14, 0x0

    .line 1165
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 1166
    .line 1167
    invoke-virtual/range {v7 .. v14}, Lb41/b;->j(Lz70/c;Lay0/k;Ly31/g;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 1168
    .line 1169
    .line 1170
    goto :goto_b

    .line 1171
    :cond_2c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1172
    .line 1173
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 1174
    .line 1175
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1176
    .line 1177
    .line 1178
    throw v0

    .line 1179
    :cond_2d
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1180
    .line 1181
    .line 1182
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1183
    .line 1184
    return-object v0

    .line 1185
    :pswitch_5
    move-object/from16 v1, p1

    .line 1186
    .line 1187
    check-cast v1, Ll2/o;

    .line 1188
    .line 1189
    move-object/from16 v2, p2

    .line 1190
    .line 1191
    check-cast v2, Ljava/lang/Integer;

    .line 1192
    .line 1193
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1194
    .line 1195
    .line 1196
    move-result v2

    .line 1197
    and-int/lit8 v3, v2, 0x3

    .line 1198
    .line 1199
    const/4 v4, 0x2

    .line 1200
    const/4 v5, 0x1

    .line 1201
    const/4 v6, 0x0

    .line 1202
    if-eq v3, v4, :cond_2e

    .line 1203
    .line 1204
    move v3, v5

    .line 1205
    goto :goto_c

    .line 1206
    :cond_2e
    move v3, v6

    .line 1207
    :goto_c
    and-int/2addr v2, v5

    .line 1208
    move-object v13, v1

    .line 1209
    check-cast v13, Ll2/t;

    .line 1210
    .line 1211
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1212
    .line 1213
    .line 1214
    move-result v1

    .line 1215
    if-eqz v1, :cond_36

    .line 1216
    .line 1217
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 1218
    .line 1219
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1220
    .line 1221
    .line 1222
    move-result v1

    .line 1223
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v2

    .line 1227
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 1228
    .line 1229
    if-nez v1, :cond_2f

    .line 1230
    .line 1231
    if-ne v2, v3, :cond_30

    .line 1232
    .line 1233
    :cond_2f
    new-instance v2, Ly21/c;

    .line 1234
    .line 1235
    const/4 v1, 0x2

    .line 1236
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 1237
    .line 1238
    .line 1239
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1240
    .line 1241
    .line 1242
    :cond_30
    move-object/from16 v20, v2

    .line 1243
    .line 1244
    check-cast v20, Lay0/a;

    .line 1245
    .line 1246
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 1247
    .line 1248
    .line 1249
    move-result-object v1

    .line 1250
    if-eqz v1, :cond_35

    .line 1251
    .line 1252
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 1253
    .line 1254
    .line 1255
    move-result-object v17

    .line 1256
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v19

    .line 1260
    const v2, -0x6040e0aa

    .line 1261
    .line 1262
    .line 1263
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 1264
    .line 1265
    .line 1266
    const-class v2, Lu31/h;

    .line 1267
    .line 1268
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1269
    .line 1270
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1271
    .line 1272
    .line 1273
    move-result-object v14

    .line 1274
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v15

    .line 1278
    const/16 v16, 0x0

    .line 1279
    .line 1280
    const/16 v18, 0x0

    .line 1281
    .line 1282
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v1

    .line 1286
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 1287
    .line 1288
    .line 1289
    check-cast v1, Lu31/h;

    .line 1290
    .line 1291
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1292
    .line 1293
    .line 1294
    move-result v2

    .line 1295
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v4

    .line 1299
    if-nez v2, :cond_31

    .line 1300
    .line 1301
    if-ne v4, v3, :cond_32

    .line 1302
    .line 1303
    :cond_31
    new-instance v4, Lu31/f;

    .line 1304
    .line 1305
    const/4 v2, 0x1

    .line 1306
    invoke-direct {v4, v1, v2}, Lu31/f;-><init>(Lu31/h;I)V

    .line 1307
    .line 1308
    .line 1309
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1310
    .line 1311
    .line 1312
    :cond_32
    check-cast v4, Lay0/k;

    .line 1313
    .line 1314
    const/4 v2, 0x0

    .line 1315
    invoke-static {v1, v2, v4, v13, v6}, Ljp/ba;->a(Ljava/lang/Object;Landroidx/lifecycle/x;Lay0/k;Ll2/o;I)V

    .line 1316
    .line 1317
    .line 1318
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 1319
    .line 1320
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 1321
    .line 1322
    .line 1323
    move-result-object v2

    .line 1324
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 1325
    .line 1326
    iget-object v4, v4, Lg1/q;->d:Ljava/lang/Object;

    .line 1327
    .line 1328
    move-object v8, v4

    .line 1329
    check-cast v8, Lz70/c;

    .line 1330
    .line 1331
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 1332
    .line 1333
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1334
    .line 1335
    .line 1336
    move-result-object v2

    .line 1337
    move-object v10, v2

    .line 1338
    check-cast v10, Lu31/i;

    .line 1339
    .line 1340
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1341
    .line 1342
    .line 1343
    move-result v2

    .line 1344
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1345
    .line 1346
    .line 1347
    move-result-object v4

    .line 1348
    if-nez v2, :cond_33

    .line 1349
    .line 1350
    if-ne v4, v3, :cond_34

    .line 1351
    .line 1352
    :cond_33
    new-instance v14, Ly21/d;

    .line 1353
    .line 1354
    const/16 v20, 0x0

    .line 1355
    .line 1356
    const/16 v21, 0x2

    .line 1357
    .line 1358
    const/4 v15, 0x1

    .line 1359
    const-class v17, Lu31/h;

    .line 1360
    .line 1361
    const-string v18, "onEvent"

    .line 1362
    .line 1363
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/replacementmobility/ReplacementMobilityViewEvent;)V"

    .line 1364
    .line 1365
    move-object/from16 v16, v1

    .line 1366
    .line 1367
    invoke-direct/range {v14 .. v21}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1368
    .line 1369
    .line 1370
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1371
    .line 1372
    .line 1373
    move-object v4, v14

    .line 1374
    :cond_34
    check-cast v4, Lhy0/g;

    .line 1375
    .line 1376
    move-object v11, v4

    .line 1377
    check-cast v11, Lay0/k;

    .line 1378
    .line 1379
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 1380
    .line 1381
    const/4 v14, 0x0

    .line 1382
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 1383
    .line 1384
    invoke-virtual/range {v7 .. v14}, Lb41/b;->g(Lz70/c;Lay0/k;Lu31/i;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 1385
    .line 1386
    .line 1387
    goto :goto_d

    .line 1388
    :cond_35
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1389
    .line 1390
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 1391
    .line 1392
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1393
    .line 1394
    .line 1395
    throw v0

    .line 1396
    :cond_36
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1397
    .line 1398
    .line 1399
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1400
    .line 1401
    return-object v0

    .line 1402
    :pswitch_6
    move-object/from16 v1, p1

    .line 1403
    .line 1404
    check-cast v1, Ll2/o;

    .line 1405
    .line 1406
    move-object/from16 v2, p2

    .line 1407
    .line 1408
    check-cast v2, Ljava/lang/Integer;

    .line 1409
    .line 1410
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1411
    .line 1412
    .line 1413
    move-result v2

    .line 1414
    and-int/lit8 v3, v2, 0x3

    .line 1415
    .line 1416
    const/4 v4, 0x2

    .line 1417
    const/4 v5, 0x1

    .line 1418
    const/4 v6, 0x0

    .line 1419
    if-eq v3, v4, :cond_37

    .line 1420
    .line 1421
    move v3, v5

    .line 1422
    goto :goto_e

    .line 1423
    :cond_37
    move v3, v6

    .line 1424
    :goto_e
    and-int/2addr v2, v5

    .line 1425
    move-object v13, v1

    .line 1426
    check-cast v13, Ll2/t;

    .line 1427
    .line 1428
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1429
    .line 1430
    .line 1431
    move-result v1

    .line 1432
    if-eqz v1, :cond_3d

    .line 1433
    .line 1434
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 1435
    .line 1436
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1437
    .line 1438
    .line 1439
    move-result v1

    .line 1440
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v2

    .line 1444
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 1445
    .line 1446
    if-nez v1, :cond_38

    .line 1447
    .line 1448
    if-ne v2, v3, :cond_39

    .line 1449
    .line 1450
    :cond_38
    new-instance v2, Ly21/c;

    .line 1451
    .line 1452
    const/4 v1, 0x7

    .line 1453
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 1454
    .line 1455
    .line 1456
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1457
    .line 1458
    .line 1459
    :cond_39
    move-object/from16 v20, v2

    .line 1460
    .line 1461
    check-cast v20, Lay0/a;

    .line 1462
    .line 1463
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 1464
    .line 1465
    .line 1466
    move-result-object v1

    .line 1467
    if-eqz v1, :cond_3c

    .line 1468
    .line 1469
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 1470
    .line 1471
    .line 1472
    move-result-object v17

    .line 1473
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 1474
    .line 1475
    .line 1476
    move-result-object v19

    .line 1477
    const v2, -0x6040e0aa

    .line 1478
    .line 1479
    .line 1480
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 1481
    .line 1482
    .line 1483
    const-class v2, Lx31/n;

    .line 1484
    .line 1485
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1486
    .line 1487
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1488
    .line 1489
    .line 1490
    move-result-object v14

    .line 1491
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 1492
    .line 1493
    .line 1494
    move-result-object v15

    .line 1495
    const/16 v16, 0x0

    .line 1496
    .line 1497
    const/16 v18, 0x0

    .line 1498
    .line 1499
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 1500
    .line 1501
    .line 1502
    move-result-object v1

    .line 1503
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 1504
    .line 1505
    .line 1506
    check-cast v1, Lx31/n;

    .line 1507
    .line 1508
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 1509
    .line 1510
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 1511
    .line 1512
    .line 1513
    move-result-object v2

    .line 1514
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 1515
    .line 1516
    iget-object v4, v4, Lg1/q;->h:Ljava/lang/Object;

    .line 1517
    .line 1518
    move-object v8, v4

    .line 1519
    check-cast v8, Lz70/b;

    .line 1520
    .line 1521
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 1522
    .line 1523
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1524
    .line 1525
    .line 1526
    move-result-object v2

    .line 1527
    move-object v10, v2

    .line 1528
    check-cast v10, Lx31/o;

    .line 1529
    .line 1530
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1531
    .line 1532
    .line 1533
    move-result v2

    .line 1534
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1535
    .line 1536
    .line 1537
    move-result-object v4

    .line 1538
    if-nez v2, :cond_3a

    .line 1539
    .line 1540
    if-ne v4, v3, :cond_3b

    .line 1541
    .line 1542
    :cond_3a
    new-instance v14, Lwc/a;

    .line 1543
    .line 1544
    const/16 v20, 0x0

    .line 1545
    .line 1546
    const/16 v21, 0x1d

    .line 1547
    .line 1548
    const/4 v15, 0x1

    .line 1549
    const-class v17, Lx31/n;

    .line 1550
    .line 1551
    const-string v18, "onEvent"

    .line 1552
    .line 1553
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/sbonewrequest/SBONewRequestViewEvent;)V"

    .line 1554
    .line 1555
    move-object/from16 v16, v1

    .line 1556
    .line 1557
    invoke-direct/range {v14 .. v21}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1558
    .line 1559
    .line 1560
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1561
    .line 1562
    .line 1563
    move-object v4, v14

    .line 1564
    :cond_3b
    check-cast v4, Lhy0/g;

    .line 1565
    .line 1566
    move-object v11, v4

    .line 1567
    check-cast v11, Lay0/k;

    .line 1568
    .line 1569
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 1570
    .line 1571
    const/4 v14, 0x0

    .line 1572
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 1573
    .line 1574
    invoke-virtual/range {v7 .. v14}, Lb41/b;->i(Lz70/b;Lay0/k;Lx31/o;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 1575
    .line 1576
    .line 1577
    goto :goto_f

    .line 1578
    :cond_3c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1579
    .line 1580
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 1581
    .line 1582
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1583
    .line 1584
    .line 1585
    throw v0

    .line 1586
    :cond_3d
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1587
    .line 1588
    .line 1589
    :goto_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1590
    .line 1591
    return-object v0

    .line 1592
    :pswitch_7
    move-object/from16 v1, p1

    .line 1593
    .line 1594
    check-cast v1, Ll2/o;

    .line 1595
    .line 1596
    move-object/from16 v2, p2

    .line 1597
    .line 1598
    check-cast v2, Ljava/lang/Integer;

    .line 1599
    .line 1600
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1601
    .line 1602
    .line 1603
    move-result v2

    .line 1604
    and-int/lit8 v3, v2, 0x3

    .line 1605
    .line 1606
    const/4 v4, 0x2

    .line 1607
    const/4 v5, 0x1

    .line 1608
    const/4 v6, 0x0

    .line 1609
    if-eq v3, v4, :cond_3e

    .line 1610
    .line 1611
    move v3, v5

    .line 1612
    goto :goto_10

    .line 1613
    :cond_3e
    move v3, v6

    .line 1614
    :goto_10
    and-int/2addr v2, v5

    .line 1615
    move-object v13, v1

    .line 1616
    check-cast v13, Ll2/t;

    .line 1617
    .line 1618
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1619
    .line 1620
    .line 1621
    move-result v1

    .line 1622
    if-eqz v1, :cond_44

    .line 1623
    .line 1624
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 1625
    .line 1626
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1627
    .line 1628
    .line 1629
    move-result v1

    .line 1630
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v2

    .line 1634
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 1635
    .line 1636
    if-nez v1, :cond_3f

    .line 1637
    .line 1638
    if-ne v2, v3, :cond_40

    .line 1639
    .line 1640
    :cond_3f
    new-instance v2, Ly21/c;

    .line 1641
    .line 1642
    const/4 v1, 0x5

    .line 1643
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 1644
    .line 1645
    .line 1646
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1647
    .line 1648
    .line 1649
    :cond_40
    move-object/from16 v20, v2

    .line 1650
    .line 1651
    check-cast v20, Lay0/a;

    .line 1652
    .line 1653
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 1654
    .line 1655
    .line 1656
    move-result-object v1

    .line 1657
    if-eqz v1, :cond_43

    .line 1658
    .line 1659
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 1660
    .line 1661
    .line 1662
    move-result-object v17

    .line 1663
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 1664
    .line 1665
    .line 1666
    move-result-object v19

    .line 1667
    const v2, -0x6040e0aa

    .line 1668
    .line 1669
    .line 1670
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 1671
    .line 1672
    .line 1673
    const-class v2, Lz31/e;

    .line 1674
    .line 1675
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1676
    .line 1677
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1678
    .line 1679
    .line 1680
    move-result-object v14

    .line 1681
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 1682
    .line 1683
    .line 1684
    move-result-object v15

    .line 1685
    const/16 v16, 0x0

    .line 1686
    .line 1687
    const/16 v18, 0x0

    .line 1688
    .line 1689
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 1690
    .line 1691
    .line 1692
    move-result-object v1

    .line 1693
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 1694
    .line 1695
    .line 1696
    check-cast v1, Lz31/e;

    .line 1697
    .line 1698
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 1699
    .line 1700
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 1701
    .line 1702
    .line 1703
    move-result-object v2

    .line 1704
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 1705
    .line 1706
    iget-object v4, v4, Lg1/q;->f:Ljava/lang/Object;

    .line 1707
    .line 1708
    move-object v8, v4

    .line 1709
    check-cast v8, Lz70/a;

    .line 1710
    .line 1711
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 1712
    .line 1713
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1714
    .line 1715
    .line 1716
    move-result-object v2

    .line 1717
    move-object v10, v2

    .line 1718
    check-cast v10, Lz31/g;

    .line 1719
    .line 1720
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1721
    .line 1722
    .line 1723
    move-result v2

    .line 1724
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1725
    .line 1726
    .line 1727
    move-result-object v4

    .line 1728
    if-nez v2, :cond_41

    .line 1729
    .line 1730
    if-ne v4, v3, :cond_42

    .line 1731
    .line 1732
    :cond_41
    new-instance v14, Lwc/a;

    .line 1733
    .line 1734
    const/16 v20, 0x0

    .line 1735
    .line 1736
    const/16 v21, 0x19

    .line 1737
    .line 1738
    const/4 v15, 0x1

    .line 1739
    const-class v17, Lz31/e;

    .line 1740
    .line 1741
    const-string v18, "onEvent"

    .line 1742
    .line 1743
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/summary/SummaryViewEvent;)V"

    .line 1744
    .line 1745
    move-object/from16 v16, v1

    .line 1746
    .line 1747
    invoke-direct/range {v14 .. v21}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1748
    .line 1749
    .line 1750
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1751
    .line 1752
    .line 1753
    move-object v4, v14

    .line 1754
    :cond_42
    check-cast v4, Lhy0/g;

    .line 1755
    .line 1756
    move-object v11, v4

    .line 1757
    check-cast v11, Lay0/k;

    .line 1758
    .line 1759
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 1760
    .line 1761
    const/4 v14, 0x0

    .line 1762
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 1763
    .line 1764
    invoke-virtual/range {v7 .. v14}, Lb41/b;->e(Lz70/a;Lay0/k;Lz31/g;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 1765
    .line 1766
    .line 1767
    goto :goto_11

    .line 1768
    :cond_43
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1769
    .line 1770
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 1771
    .line 1772
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1773
    .line 1774
    .line 1775
    throw v0

    .line 1776
    :cond_44
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1777
    .line 1778
    .line 1779
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1780
    .line 1781
    return-object v0

    .line 1782
    :pswitch_8
    move-object/from16 v1, p1

    .line 1783
    .line 1784
    check-cast v1, Ll2/o;

    .line 1785
    .line 1786
    move-object/from16 v2, p2

    .line 1787
    .line 1788
    check-cast v2, Ljava/lang/Integer;

    .line 1789
    .line 1790
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1791
    .line 1792
    .line 1793
    move-result v2

    .line 1794
    and-int/lit8 v3, v2, 0x3

    .line 1795
    .line 1796
    const/4 v4, 0x2

    .line 1797
    const/4 v5, 0x1

    .line 1798
    const/4 v6, 0x0

    .line 1799
    if-eq v3, v4, :cond_45

    .line 1800
    .line 1801
    move v3, v5

    .line 1802
    goto :goto_12

    .line 1803
    :cond_45
    move v3, v6

    .line 1804
    :goto_12
    and-int/2addr v2, v5

    .line 1805
    move-object v13, v1

    .line 1806
    check-cast v13, Ll2/t;

    .line 1807
    .line 1808
    invoke-virtual {v13, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1809
    .line 1810
    .line 1811
    move-result v1

    .line 1812
    if-eqz v1, :cond_4b

    .line 1813
    .line 1814
    iget-object v0, v0, Ly21/b;->e:Lz21/g;

    .line 1815
    .line 1816
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1817
    .line 1818
    .line 1819
    move-result v1

    .line 1820
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1821
    .line 1822
    .line 1823
    move-result-object v2

    .line 1824
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 1825
    .line 1826
    if-nez v1, :cond_46

    .line 1827
    .line 1828
    if-ne v2, v3, :cond_47

    .line 1829
    .line 1830
    :cond_46
    new-instance v2, Ly21/c;

    .line 1831
    .line 1832
    const/16 v1, 0x9

    .line 1833
    .line 1834
    invoke-direct {v2, v0, v1}, Ly21/c;-><init>(Lz21/g;I)V

    .line 1835
    .line 1836
    .line 1837
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1838
    .line 1839
    .line 1840
    :cond_47
    move-object/from16 v20, v2

    .line 1841
    .line 1842
    check-cast v20, Lay0/a;

    .line 1843
    .line 1844
    invoke-static {v13}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 1845
    .line 1846
    .line 1847
    move-result-object v1

    .line 1848
    if-eqz v1, :cond_4a

    .line 1849
    .line 1850
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 1851
    .line 1852
    .line 1853
    move-result-object v17

    .line 1854
    invoke-static {v13}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 1855
    .line 1856
    .line 1857
    move-result-object v19

    .line 1858
    const v2, -0x6040e0aa

    .line 1859
    .line 1860
    .line 1861
    invoke-virtual {v13, v2}, Ll2/t;->Y(I)V

    .line 1862
    .line 1863
    .line 1864
    const-class v2, Lw31/g;

    .line 1865
    .line 1866
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1867
    .line 1868
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1869
    .line 1870
    .line 1871
    move-result-object v14

    .line 1872
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 1873
    .line 1874
    .line 1875
    move-result-object v15

    .line 1876
    const/16 v16, 0x0

    .line 1877
    .line 1878
    const/16 v18, 0x0

    .line 1879
    .line 1880
    invoke-static/range {v14 .. v20}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 1881
    .line 1882
    .line 1883
    move-result-object v1

    .line 1884
    invoke-virtual {v13, v6}, Ll2/t;->q(Z)V

    .line 1885
    .line 1886
    .line 1887
    check-cast v1, Lw31/g;

    .line 1888
    .line 1889
    iget-object v2, v1, Lq41/b;->e:Lyy0/l1;

    .line 1890
    .line 1891
    invoke-static {v2, v13}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 1892
    .line 1893
    .line 1894
    move-result-object v2

    .line 1895
    iget-object v4, v0, Lz21/g;->e:Lg1/q;

    .line 1896
    .line 1897
    iget-object v4, v4, Lg1/q;->i:Ljava/lang/Object;

    .line 1898
    .line 1899
    move-object v8, v4

    .line 1900
    check-cast v8, Lz70/b;

    .line 1901
    .line 1902
    iget-object v9, v0, Lz21/g;->f:Lay0/k;

    .line 1903
    .line 1904
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1905
    .line 1906
    .line 1907
    move-result-object v2

    .line 1908
    move-object v10, v2

    .line 1909
    check-cast v10, Lw31/h;

    .line 1910
    .line 1911
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1912
    .line 1913
    .line 1914
    move-result v2

    .line 1915
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 1916
    .line 1917
    .line 1918
    move-result-object v4

    .line 1919
    if-nez v2, :cond_48

    .line 1920
    .line 1921
    if-ne v4, v3, :cond_49

    .line 1922
    .line 1923
    :cond_48
    new-instance v14, Ly21/d;

    .line 1924
    .line 1925
    const/16 v20, 0x0

    .line 1926
    .line 1927
    const/16 v21, 0x1

    .line 1928
    .line 1929
    const/4 v15, 0x1

    .line 1930
    const-class v17, Lw31/g;

    .line 1931
    .line 1932
    const-string v18, "onEvent"

    .line 1933
    .line 1934
    const-string v19, "onEvent(Ltechnology/cariad/appointmentbooking/base/ui/screens/sboappointmentschedule/SBOAppointmentScheduleViewEvent;)V"

    .line 1935
    .line 1936
    move-object/from16 v16, v1

    .line 1937
    .line 1938
    invoke-direct/range {v14 .. v21}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1939
    .line 1940
    .line 1941
    invoke-virtual {v13, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1942
    .line 1943
    .line 1944
    move-object v4, v14

    .line 1945
    :cond_49
    check-cast v4, Lhy0/g;

    .line 1946
    .line 1947
    move-object v11, v4

    .line 1948
    check-cast v11, Lay0/k;

    .line 1949
    .line 1950
    iget-object v12, v0, Lz21/g;->g:Lay0/k;

    .line 1951
    .line 1952
    const/4 v14, 0x0

    .line 1953
    sget-object v7, Lb41/b;->a:Lb41/b;

    .line 1954
    .line 1955
    invoke-virtual/range {v7 .. v14}, Lb41/b;->h(Lz70/b;Lay0/k;Lw31/h;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 1956
    .line 1957
    .line 1958
    goto :goto_13

    .line 1959
    :cond_4a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1960
    .line 1961
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 1962
    .line 1963
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1964
    .line 1965
    .line 1966
    throw v0

    .line 1967
    :cond_4b
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1968
    .line 1969
    .line 1970
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1971
    .line 1972
    return-object v0

    .line 1973
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
