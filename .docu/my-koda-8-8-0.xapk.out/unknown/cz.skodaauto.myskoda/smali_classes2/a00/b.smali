.class public final synthetic La00/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, La00/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, La00/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    iget v1, v1, La00/b;->d:I

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast v0, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {v0, v1}, Lb50/f;->a(Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object v0

    .line 30
    :pswitch_0
    check-cast v0, Lk21/a;

    .line 31
    .line 32
    move-object/from16 v1, p2

    .line 33
    .line 34
    check-cast v1, Lg21/a;

    .line 35
    .line 36
    const-string v2, "$this$single"

    .line 37
    .line 38
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v2, "it"

    .line 42
    .line 43
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    new-instance v1, La30/d;

    .line 47
    .line 48
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 49
    .line 50
    const-class v3, Lxl0/f;

    .line 51
    .line 52
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    const/4 v4, 0x0

    .line 57
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    check-cast v3, Lxl0/f;

    .line 62
    .line 63
    const-class v5, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 64
    .line 65
    const-string v6, "null"

    .line 66
    .line 67
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    const-class v6, Lti0/a;

    .line 72
    .line 73
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    check-cast v0, Lti0/a;

    .line 82
    .line 83
    invoke-direct {v1, v3, v0}, La30/d;-><init>(Lxl0/f;Lti0/a;)V

    .line 84
    .line 85
    .line 86
    return-object v1

    .line 87
    :pswitch_1
    check-cast v0, Lk21/a;

    .line 88
    .line 89
    move-object/from16 v1, p2

    .line 90
    .line 91
    check-cast v1, Lg21/a;

    .line 92
    .line 93
    const-string v2, "$this$single"

    .line 94
    .line 95
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    const-string v2, "it"

    .line 99
    .line 100
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    new-instance v1, La20/b;

    .line 104
    .line 105
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 106
    .line 107
    const-class v3, Lxl0/f;

    .line 108
    .line 109
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    const/4 v4, 0x0

    .line 114
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    check-cast v3, Lxl0/f;

    .line 119
    .line 120
    const-class v5, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi;

    .line 121
    .line 122
    const-string v6, "null"

    .line 123
    .line 124
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    const-class v6, Lti0/a;

    .line 129
    .line 130
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Lti0/a;

    .line 139
    .line 140
    invoke-direct {v1, v3, v0}, La20/b;-><init>(Lxl0/f;Lti0/a;)V

    .line 141
    .line 142
    .line 143
    return-object v1

    .line 144
    :pswitch_2
    check-cast v0, Ll2/o;

    .line 145
    .line 146
    move-object/from16 v1, p2

    .line 147
    .line 148
    check-cast v1, Ljava/lang/Integer;

    .line 149
    .line 150
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    const/4 v1, 0x1

    .line 154
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    invoke-static {v0, v1}, Ljp/z1;->f(Ll2/o;I)V

    .line 159
    .line 160
    .line 161
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    return-object v0

    .line 164
    :pswitch_3
    check-cast v0, Ll2/o;

    .line 165
    .line 166
    move-object/from16 v1, p2

    .line 167
    .line 168
    check-cast v1, Ljava/lang/Integer;

    .line 169
    .line 170
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 171
    .line 172
    .line 173
    const/4 v1, 0x1

    .line 174
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    invoke-static {v0, v1}, Ljp/z1;->d(Ll2/o;I)V

    .line 179
    .line 180
    .line 181
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 182
    .line 183
    return-object v0

    .line 184
    :pswitch_4
    check-cast v0, Laz0/w;

    .line 185
    .line 186
    move-object/from16 v1, p2

    .line 187
    .line 188
    check-cast v1, Lpx0/e;

    .line 189
    .line 190
    instance-of v2, v1, Lvy0/a2;

    .line 191
    .line 192
    if-eqz v2, :cond_0

    .line 193
    .line 194
    check-cast v1, Lvy0/a2;

    .line 195
    .line 196
    iget-object v2, v0, Laz0/w;->a:Lpx0/g;

    .line 197
    .line 198
    invoke-interface {v1, v2}, Lvy0/a2;->updateThreadContext(Lpx0/g;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v2

    .line 202
    iget-object v3, v0, Laz0/w;->b:[Ljava/lang/Object;

    .line 203
    .line 204
    iget v4, v0, Laz0/w;->d:I

    .line 205
    .line 206
    aput-object v2, v3, v4

    .line 207
    .line 208
    iget-object v2, v0, Laz0/w;->c:[Lvy0/a2;

    .line 209
    .line 210
    add-int/lit8 v3, v4, 0x1

    .line 211
    .line 212
    iput v3, v0, Laz0/w;->d:I

    .line 213
    .line 214
    aput-object v1, v2, v4

    .line 215
    .line 216
    :cond_0
    return-object v0

    .line 217
    :pswitch_5
    check-cast v0, Lvy0/a2;

    .line 218
    .line 219
    move-object/from16 v1, p2

    .line 220
    .line 221
    check-cast v1, Lpx0/e;

    .line 222
    .line 223
    if-eqz v0, :cond_1

    .line 224
    .line 225
    goto :goto_0

    .line 226
    :cond_1
    instance-of v0, v1, Lvy0/a2;

    .line 227
    .line 228
    if-eqz v0, :cond_2

    .line 229
    .line 230
    move-object v0, v1

    .line 231
    check-cast v0, Lvy0/a2;

    .line 232
    .line 233
    goto :goto_0

    .line 234
    :cond_2
    const/4 v0, 0x0

    .line 235
    :goto_0
    return-object v0

    .line 236
    :pswitch_6
    move-object/from16 v1, p2

    .line 237
    .line 238
    check-cast v1, Lpx0/e;

    .line 239
    .line 240
    instance-of v2, v1, Lvy0/a2;

    .line 241
    .line 242
    if-eqz v2, :cond_6

    .line 243
    .line 244
    instance-of v2, v0, Ljava/lang/Integer;

    .line 245
    .line 246
    if-eqz v2, :cond_3

    .line 247
    .line 248
    check-cast v0, Ljava/lang/Integer;

    .line 249
    .line 250
    goto :goto_1

    .line 251
    :cond_3
    const/4 v0, 0x0

    .line 252
    :goto_1
    const/4 v2, 0x1

    .line 253
    if-eqz v0, :cond_4

    .line 254
    .line 255
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 256
    .line 257
    .line 258
    move-result v0

    .line 259
    goto :goto_2

    .line 260
    :cond_4
    move v0, v2

    .line 261
    :goto_2
    if-nez v0, :cond_5

    .line 262
    .line 263
    move-object v0, v1

    .line 264
    goto :goto_3

    .line 265
    :cond_5
    add-int/2addr v0, v2

    .line 266
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    :cond_6
    :goto_3
    return-object v0

    .line 271
    :pswitch_7
    check-cast v0, Lk21/a;

    .line 272
    .line 273
    move-object/from16 v1, p2

    .line 274
    .line 275
    check-cast v1, Lg21/a;

    .line 276
    .line 277
    const-string v2, "$this$single"

    .line 278
    .line 279
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    const-string v2, "it"

    .line 283
    .line 284
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    new-instance v1, Lzp0/e;

    .line 288
    .line 289
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 290
    .line 291
    const-class v3, Lxl0/f;

    .line 292
    .line 293
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    const/4 v4, 0x0

    .line 298
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v3

    .line 302
    check-cast v3, Lxl0/f;

    .line 303
    .line 304
    const-class v5, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 305
    .line 306
    const-string v6, "null"

    .line 307
    .line 308
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 309
    .line 310
    .line 311
    move-result-object v5

    .line 312
    const-class v6, Lti0/a;

    .line 313
    .line 314
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 315
    .line 316
    .line 317
    move-result-object v2

    .line 318
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v0

    .line 322
    check-cast v0, Lti0/a;

    .line 323
    .line 324
    invoke-direct {v1, v3, v0}, Lzp0/e;-><init>(Lxl0/f;Lti0/a;)V

    .line 325
    .line 326
    .line 327
    return-object v1

    .line 328
    :pswitch_8
    check-cast v0, Ll2/o;

    .line 329
    .line 330
    move-object/from16 v1, p2

    .line 331
    .line 332
    check-cast v1, Ljava/lang/Integer;

    .line 333
    .line 334
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 335
    .line 336
    .line 337
    const/4 v1, 0x1

    .line 338
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 339
    .line 340
    .line 341
    move-result v1

    .line 342
    invoke-static {v0, v1}, Lal/a;->a(Ll2/o;I)V

    .line 343
    .line 344
    .line 345
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 346
    .line 347
    return-object v0

    .line 348
    :pswitch_9
    check-cast v0, Ll2/o;

    .line 349
    .line 350
    move-object/from16 v1, p2

    .line 351
    .line 352
    check-cast v1, Ljava/lang/Integer;

    .line 353
    .line 354
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 355
    .line 356
    .line 357
    move-result v1

    .line 358
    and-int/lit8 v2, v1, 0x3

    .line 359
    .line 360
    const/4 v3, 0x2

    .line 361
    const/4 v4, 0x0

    .line 362
    const/4 v5, 0x1

    .line 363
    if-eq v2, v3, :cond_7

    .line 364
    .line 365
    move v2, v5

    .line 366
    goto :goto_4

    .line 367
    :cond_7
    move v2, v4

    .line 368
    :goto_4
    and-int/2addr v1, v5

    .line 369
    check-cast v0, Ll2/t;

    .line 370
    .line 371
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 372
    .line 373
    .line 374
    move-result v1

    .line 375
    if-eqz v1, :cond_8

    .line 376
    .line 377
    const/4 v1, 0x6

    .line 378
    invoke-static {v1, v4, v0, v5}, Ldk/b;->e(IILl2/o;Z)V

    .line 379
    .line 380
    .line 381
    goto :goto_5

    .line 382
    :cond_8
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 383
    .line 384
    .line 385
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 386
    .line 387
    return-object v0

    .line 388
    :pswitch_a
    check-cast v0, Ll2/o;

    .line 389
    .line 390
    move-object/from16 v1, p2

    .line 391
    .line 392
    check-cast v1, Ljava/lang/Integer;

    .line 393
    .line 394
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 395
    .line 396
    .line 397
    move-result v1

    .line 398
    and-int/lit8 v2, v1, 0x3

    .line 399
    .line 400
    const/4 v3, 0x2

    .line 401
    const/4 v4, 0x1

    .line 402
    if-eq v2, v3, :cond_9

    .line 403
    .line 404
    move v2, v4

    .line 405
    goto :goto_6

    .line 406
    :cond_9
    const/4 v2, 0x0

    .line 407
    :goto_6
    and-int/2addr v1, v4

    .line 408
    move-object v6, v0

    .line 409
    check-cast v6, Ll2/t;

    .line 410
    .line 411
    invoke-virtual {v6, v1, v2}, Ll2/t;->O(IZ)Z

    .line 412
    .line 413
    .line 414
    move-result v0

    .line 415
    if-eqz v0, :cond_a

    .line 416
    .line 417
    invoke-static {v6}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 418
    .line 419
    .line 420
    move-result-object v5

    .line 421
    const/4 v7, 0x6

    .line 422
    const/4 v8, 0x2

    .line 423
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 424
    .line 425
    const/4 v4, 0x0

    .line 426
    invoke-static/range {v3 .. v8}, Ljp/nd;->a(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 427
    .line 428
    .line 429
    goto :goto_7

    .line 430
    :cond_a
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 431
    .line 432
    .line 433
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 434
    .line 435
    return-object v0

    .line 436
    :pswitch_b
    check-cast v0, Ll2/o;

    .line 437
    .line 438
    move-object/from16 v1, p2

    .line 439
    .line 440
    check-cast v1, Ljava/lang/Integer;

    .line 441
    .line 442
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 443
    .line 444
    .line 445
    move-result v1

    .line 446
    and-int/lit8 v2, v1, 0x3

    .line 447
    .line 448
    const/4 v3, 0x2

    .line 449
    const/4 v4, 0x0

    .line 450
    const/4 v5, 0x1

    .line 451
    if-eq v2, v3, :cond_b

    .line 452
    .line 453
    move v2, v5

    .line 454
    goto :goto_8

    .line 455
    :cond_b
    move v2, v4

    .line 456
    :goto_8
    and-int/2addr v1, v5

    .line 457
    check-cast v0, Ll2/t;

    .line 458
    .line 459
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 460
    .line 461
    .line 462
    move-result v1

    .line 463
    if-eqz v1, :cond_c

    .line 464
    .line 465
    const/4 v1, 0x6

    .line 466
    invoke-static {v1, v4, v0, v5}, Ldk/b;->e(IILl2/o;Z)V

    .line 467
    .line 468
    .line 469
    goto :goto_9

    .line 470
    :cond_c
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 471
    .line 472
    .line 473
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 474
    .line 475
    return-object v0

    .line 476
    :pswitch_c
    check-cast v0, Ll2/o;

    .line 477
    .line 478
    move-object/from16 v1, p2

    .line 479
    .line 480
    check-cast v1, Ljava/lang/Integer;

    .line 481
    .line 482
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 483
    .line 484
    .line 485
    move-result v1

    .line 486
    and-int/lit8 v2, v1, 0x3

    .line 487
    .line 488
    const/4 v3, 0x2

    .line 489
    const/4 v4, 0x1

    .line 490
    if-eq v2, v3, :cond_d

    .line 491
    .line 492
    move v2, v4

    .line 493
    goto :goto_a

    .line 494
    :cond_d
    const/4 v2, 0x0

    .line 495
    :goto_a
    and-int/2addr v1, v4

    .line 496
    move-object v6, v0

    .line 497
    check-cast v6, Ll2/t;

    .line 498
    .line 499
    invoke-virtual {v6, v1, v2}, Ll2/t;->O(IZ)Z

    .line 500
    .line 501
    .line 502
    move-result v0

    .line 503
    if-eqz v0, :cond_e

    .line 504
    .line 505
    invoke-static {v6}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 506
    .line 507
    .line 508
    move-result-object v5

    .line 509
    const/4 v7, 0x6

    .line 510
    const/4 v8, 0x2

    .line 511
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 512
    .line 513
    const/4 v4, 0x0

    .line 514
    invoke-static/range {v3 .. v8}, Ljp/nd;->a(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 515
    .line 516
    .line 517
    goto :goto_b

    .line 518
    :cond_e
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 519
    .line 520
    .line 521
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 522
    .line 523
    return-object v0

    .line 524
    :pswitch_d
    check-cast v0, Ll2/o;

    .line 525
    .line 526
    move-object/from16 v1, p2

    .line 527
    .line 528
    check-cast v1, Ljava/lang/Integer;

    .line 529
    .line 530
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 531
    .line 532
    .line 533
    move-result v1

    .line 534
    and-int/lit8 v2, v1, 0x3

    .line 535
    .line 536
    const/4 v3, 0x2

    .line 537
    const/4 v4, 0x0

    .line 538
    const/4 v5, 0x1

    .line 539
    if-eq v2, v3, :cond_f

    .line 540
    .line 541
    move v2, v5

    .line 542
    goto :goto_c

    .line 543
    :cond_f
    move v2, v4

    .line 544
    :goto_c
    and-int/2addr v1, v5

    .line 545
    check-cast v0, Ll2/t;

    .line 546
    .line 547
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 548
    .line 549
    .line 550
    move-result v1

    .line 551
    if-eqz v1, :cond_10

    .line 552
    .line 553
    const/4 v1, 0x6

    .line 554
    invoke-static {v1, v4, v0, v5}, Ldk/b;->e(IILl2/o;Z)V

    .line 555
    .line 556
    .line 557
    goto :goto_d

    .line 558
    :cond_10
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 559
    .line 560
    .line 561
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 562
    .line 563
    return-object v0

    .line 564
    :pswitch_e
    check-cast v0, Ll2/o;

    .line 565
    .line 566
    move-object/from16 v1, p2

    .line 567
    .line 568
    check-cast v1, Ljava/lang/Integer;

    .line 569
    .line 570
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 571
    .line 572
    .line 573
    move-result v1

    .line 574
    and-int/lit8 v2, v1, 0x3

    .line 575
    .line 576
    const/4 v3, 0x2

    .line 577
    const/4 v4, 0x1

    .line 578
    if-eq v2, v3, :cond_11

    .line 579
    .line 580
    move v2, v4

    .line 581
    goto :goto_e

    .line 582
    :cond_11
    const/4 v2, 0x0

    .line 583
    :goto_e
    and-int/2addr v1, v4

    .line 584
    move-object v6, v0

    .line 585
    check-cast v6, Ll2/t;

    .line 586
    .line 587
    invoke-virtual {v6, v1, v2}, Ll2/t;->O(IZ)Z

    .line 588
    .line 589
    .line 590
    move-result v0

    .line 591
    if-eqz v0, :cond_12

    .line 592
    .line 593
    invoke-static {v6}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 594
    .line 595
    .line 596
    move-result-object v5

    .line 597
    const/4 v7, 0x6

    .line 598
    const/4 v8, 0x2

    .line 599
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 600
    .line 601
    const/4 v4, 0x0

    .line 602
    invoke-static/range {v3 .. v8}, Ljp/nd;->a(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 603
    .line 604
    .line 605
    goto :goto_f

    .line 606
    :cond_12
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 607
    .line 608
    .line 609
    :goto_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 610
    .line 611
    return-object v0

    .line 612
    :pswitch_f
    check-cast v0, Ll2/o;

    .line 613
    .line 614
    move-object/from16 v1, p2

    .line 615
    .line 616
    check-cast v1, Ljava/lang/Integer;

    .line 617
    .line 618
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 619
    .line 620
    .line 621
    const/4 v1, 0x1

    .line 622
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 623
    .line 624
    .line 625
    move-result v1

    .line 626
    invoke-static {v0, v1}, Lak/a;->p(Ll2/o;I)V

    .line 627
    .line 628
    .line 629
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 630
    .line 631
    return-object v0

    .line 632
    :pswitch_10
    check-cast v0, Ll2/o;

    .line 633
    .line 634
    move-object/from16 v1, p2

    .line 635
    .line 636
    check-cast v1, Ljava/lang/Integer;

    .line 637
    .line 638
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 639
    .line 640
    .line 641
    const/4 v1, 0x1

    .line 642
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 643
    .line 644
    .line 645
    move-result v1

    .line 646
    invoke-static {v0, v1}, Lak/a;->j(Ll2/o;I)V

    .line 647
    .line 648
    .line 649
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 650
    .line 651
    return-object v0

    .line 652
    :pswitch_11
    check-cast v0, Ll2/o;

    .line 653
    .line 654
    move-object/from16 v1, p2

    .line 655
    .line 656
    check-cast v1, Ljava/lang/Integer;

    .line 657
    .line 658
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 659
    .line 660
    .line 661
    move-result v1

    .line 662
    and-int/lit8 v2, v1, 0x3

    .line 663
    .line 664
    const/4 v3, 0x2

    .line 665
    const/4 v4, 0x0

    .line 666
    const/4 v5, 0x1

    .line 667
    if-eq v2, v3, :cond_13

    .line 668
    .line 669
    move v2, v5

    .line 670
    goto :goto_10

    .line 671
    :cond_13
    move v2, v4

    .line 672
    :goto_10
    and-int/2addr v1, v5

    .line 673
    check-cast v0, Ll2/t;

    .line 674
    .line 675
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 676
    .line 677
    .line 678
    move-result v1

    .line 679
    if-eqz v1, :cond_14

    .line 680
    .line 681
    invoke-static {v0, v4}, Lak/a;->p(Ll2/o;I)V

    .line 682
    .line 683
    .line 684
    goto :goto_11

    .line 685
    :cond_14
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 686
    .line 687
    .line 688
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 689
    .line 690
    return-object v0

    .line 691
    :pswitch_12
    check-cast v0, Ll2/o;

    .line 692
    .line 693
    move-object/from16 v1, p2

    .line 694
    .line 695
    check-cast v1, Ljava/lang/Integer;

    .line 696
    .line 697
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 698
    .line 699
    .line 700
    const/4 v1, 0x1

    .line 701
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 702
    .line 703
    .line 704
    move-result v1

    .line 705
    invoke-static {v0, v1}, Laj0/a;->f(Ll2/o;I)V

    .line 706
    .line 707
    .line 708
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 709
    .line 710
    return-object v0

    .line 711
    :pswitch_13
    check-cast v0, Ll2/o;

    .line 712
    .line 713
    move-object/from16 v1, p2

    .line 714
    .line 715
    check-cast v1, Ljava/lang/Integer;

    .line 716
    .line 717
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 718
    .line 719
    .line 720
    const/4 v1, 0x1

    .line 721
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 722
    .line 723
    .line 724
    move-result v1

    .line 725
    invoke-static {v0, v1}, Laj0/a;->f(Ll2/o;I)V

    .line 726
    .line 727
    .line 728
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 729
    .line 730
    return-object v0

    .line 731
    :pswitch_14
    check-cast v0, Ll2/o;

    .line 732
    .line 733
    move-object/from16 v1, p2

    .line 734
    .line 735
    check-cast v1, Ljava/lang/Integer;

    .line 736
    .line 737
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 738
    .line 739
    .line 740
    move-result v1

    .line 741
    and-int/lit8 v2, v1, 0x3

    .line 742
    .line 743
    const/4 v3, 0x1

    .line 744
    const/4 v4, 0x2

    .line 745
    if-eq v2, v4, :cond_15

    .line 746
    .line 747
    move v2, v3

    .line 748
    goto :goto_12

    .line 749
    :cond_15
    const/4 v2, 0x0

    .line 750
    :goto_12
    and-int/2addr v1, v3

    .line 751
    move-object v9, v0

    .line 752
    check-cast v9, Ll2/t;

    .line 753
    .line 754
    invoke-virtual {v9, v1, v2}, Ll2/t;->O(IZ)Z

    .line 755
    .line 756
    .line 757
    move-result v0

    .line 758
    if-eqz v0, :cond_19

    .line 759
    .line 760
    new-instance v5, Lzi0/b;

    .line 761
    .line 762
    invoke-direct {v5, v4}, Lzi0/b;-><init>(I)V

    .line 763
    .line 764
    .line 765
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 766
    .line 767
    .line 768
    move-result-object v0

    .line 769
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 770
    .line 771
    if-ne v0, v1, :cond_16

    .line 772
    .line 773
    new-instance v0, Lz81/g;

    .line 774
    .line 775
    const/4 v2, 0x2

    .line 776
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 777
    .line 778
    .line 779
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 780
    .line 781
    .line 782
    :cond_16
    move-object v6, v0

    .line 783
    check-cast v6, Lay0/a;

    .line 784
    .line 785
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v0

    .line 789
    if-ne v0, v1, :cond_17

    .line 790
    .line 791
    new-instance v0, Lz81/g;

    .line 792
    .line 793
    const/4 v2, 0x2

    .line 794
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 795
    .line 796
    .line 797
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 798
    .line 799
    .line 800
    :cond_17
    move-object v7, v0

    .line 801
    check-cast v7, Lay0/a;

    .line 802
    .line 803
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 804
    .line 805
    .line 806
    move-result-object v0

    .line 807
    if-ne v0, v1, :cond_18

    .line 808
    .line 809
    new-instance v0, La00/a;

    .line 810
    .line 811
    const/16 v1, 0x11

    .line 812
    .line 813
    invoke-direct {v0, v1}, La00/a;-><init>(I)V

    .line 814
    .line 815
    .line 816
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 817
    .line 818
    .line 819
    :cond_18
    move-object v8, v0

    .line 820
    check-cast v8, Lay0/k;

    .line 821
    .line 822
    const/16 v10, 0xdb0

    .line 823
    .line 824
    invoke-static/range {v5 .. v10}, Laj0/a;->c(Lzi0/b;Lay0/a;Lay0/a;Lay0/k;Ll2/o;I)V

    .line 825
    .line 826
    .line 827
    goto :goto_13

    .line 828
    :cond_19
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 829
    .line 830
    .line 831
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 832
    .line 833
    return-object v0

    .line 834
    :pswitch_15
    check-cast v0, Ll2/o;

    .line 835
    .line 836
    move-object/from16 v1, p2

    .line 837
    .line 838
    check-cast v1, Ljava/lang/Integer;

    .line 839
    .line 840
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 841
    .line 842
    .line 843
    const/4 v1, 0x1

    .line 844
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 845
    .line 846
    .line 847
    move-result v1

    .line 848
    invoke-static {v0, v1}, Laj0/a;->a(Ll2/o;I)V

    .line 849
    .line 850
    .line 851
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 852
    .line 853
    return-object v0

    .line 854
    :pswitch_16
    check-cast v0, Ll2/o;

    .line 855
    .line 856
    move-object/from16 v1, p2

    .line 857
    .line 858
    check-cast v1, Ljava/lang/Integer;

    .line 859
    .line 860
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 861
    .line 862
    .line 863
    const/4 v1, 0x1

    .line 864
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 865
    .line 866
    .line 867
    move-result v1

    .line 868
    invoke-static {v0, v1}, Laj0/a;->b(Ll2/o;I)V

    .line 869
    .line 870
    .line 871
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 872
    .line 873
    return-object v0

    .line 874
    :pswitch_17
    check-cast v0, Ll2/o;

    .line 875
    .line 876
    move-object/from16 v1, p2

    .line 877
    .line 878
    check-cast v1, Ljava/lang/Integer;

    .line 879
    .line 880
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 881
    .line 882
    .line 883
    const/4 v1, 0x1

    .line 884
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 885
    .line 886
    .line 887
    move-result v1

    .line 888
    invoke-static {v0, v1}, Laj0/a;->b(Ll2/o;I)V

    .line 889
    .line 890
    .line 891
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 892
    .line 893
    return-object v0

    .line 894
    :pswitch_18
    check-cast v0, Lk21/a;

    .line 895
    .line 896
    move-object/from16 v1, p2

    .line 897
    .line 898
    check-cast v1, Lg21/a;

    .line 899
    .line 900
    const-string v2, "$this$factory"

    .line 901
    .line 902
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 903
    .line 904
    .line 905
    const-string v2, "it"

    .line 906
    .line 907
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 908
    .line 909
    .line 910
    invoke-static {v0}, Llp/va;->a(Lk21/a;)Landroid/content/Context;

    .line 911
    .line 912
    .line 913
    move-result-object v0

    .line 914
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 915
    .line 916
    .line 917
    move-result-object v0

    .line 918
    return-object v0

    .line 919
    :pswitch_19
    check-cast v0, Lu2/b;

    .line 920
    .line 921
    move-object/from16 v0, p2

    .line 922
    .line 923
    check-cast v0, Lz9/y;

    .line 924
    .line 925
    iget-object v1, v0, Lz9/y;->b:Lca/g;

    .line 926
    .line 927
    iget-object v2, v1, Lca/g;->m:Ljava/util/LinkedHashMap;

    .line 928
    .line 929
    iget-object v3, v1, Lca/g;->f:Lmx0/l;

    .line 930
    .line 931
    iget-object v4, v1, Lca/g;->l:Ljava/util/LinkedHashMap;

    .line 932
    .line 933
    new-instance v5, Ljava/util/ArrayList;

    .line 934
    .line 935
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 936
    .line 937
    .line 938
    const/4 v6, 0x0

    .line 939
    new-array v7, v6, [Llx0/l;

    .line 940
    .line 941
    invoke-static {v7, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    move-result-object v7

    .line 945
    check-cast v7, [Llx0/l;

    .line 946
    .line 947
    invoke-static {v7}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 948
    .line 949
    .line 950
    move-result-object v7

    .line 951
    iget-object v1, v1, Lca/g;->s:Lz9/k0;

    .line 952
    .line 953
    iget-object v1, v1, Lz9/k0;->a:Ljava/util/LinkedHashMap;

    .line 954
    .line 955
    invoke-static {v1}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 956
    .line 957
    .line 958
    move-result-object v1

    .line 959
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 960
    .line 961
    .line 962
    move-result-object v1

    .line 963
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 964
    .line 965
    .line 966
    move-result-object v1

    .line 967
    :goto_14
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 968
    .line 969
    .line 970
    move-result v8

    .line 971
    if-eqz v8, :cond_1a

    .line 972
    .line 973
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 974
    .line 975
    .line 976
    move-result-object v8

    .line 977
    check-cast v8, Ljava/util/Map$Entry;

    .line 978
    .line 979
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 980
    .line 981
    .line 982
    move-result-object v9

    .line 983
    check-cast v9, Ljava/lang/String;

    .line 984
    .line 985
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 986
    .line 987
    .line 988
    move-result-object v8

    .line 989
    check-cast v8, Lz9/j0;

    .line 990
    .line 991
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 992
    .line 993
    .line 994
    goto :goto_14

    .line 995
    :cond_1a
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 996
    .line 997
    .line 998
    move-result v1

    .line 999
    if-nez v1, :cond_1b

    .line 1000
    .line 1001
    new-array v1, v6, [Llx0/l;

    .line 1002
    .line 1003
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v1

    .line 1007
    check-cast v1, [Llx0/l;

    .line 1008
    .line 1009
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1010
    .line 1011
    .line 1012
    move-result-object v1

    .line 1013
    const-string v8, "android-support-nav:controller:navigatorState:names"

    .line 1014
    .line 1015
    invoke-static {v7, v8, v5}, Lkp/v;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/util/List;)V

    .line 1016
    .line 1017
    .line 1018
    const-string v5, "android-support-nav:controller:navigatorState"

    .line 1019
    .line 1020
    invoke-static {v1, v5, v7}, Lkp/v;->d(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1021
    .line 1022
    .line 1023
    goto :goto_15

    .line 1024
    :cond_1b
    const/4 v1, 0x0

    .line 1025
    :goto_15
    invoke-virtual {v3}, Lmx0/l;->isEmpty()Z

    .line 1026
    .line 1027
    .line 1028
    move-result v5

    .line 1029
    const-string v7, "nav-entry-state:saved-state"

    .line 1030
    .line 1031
    const-string v8, "nav-entry-state:args"

    .line 1032
    .line 1033
    const-string v9, "nav-entry-state:destination-id"

    .line 1034
    .line 1035
    const-string v10, "nav-entry-state:id"

    .line 1036
    .line 1037
    if-nez v5, :cond_1f

    .line 1038
    .line 1039
    if-nez v1, :cond_1c

    .line 1040
    .line 1041
    new-array v1, v6, [Llx0/l;

    .line 1042
    .line 1043
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1044
    .line 1045
    .line 1046
    move-result-object v1

    .line 1047
    check-cast v1, [Llx0/l;

    .line 1048
    .line 1049
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1050
    .line 1051
    .line 1052
    move-result-object v1

    .line 1053
    :cond_1c
    new-instance v5, Ljava/util/ArrayList;

    .line 1054
    .line 1055
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 1056
    .line 1057
    .line 1058
    invoke-virtual {v3}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v3

    .line 1062
    :goto_16
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1063
    .line 1064
    .line 1065
    move-result v11

    .line 1066
    if-eqz v11, :cond_1e

    .line 1067
    .line 1068
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v11

    .line 1072
    check-cast v11, Lz9/k;

    .line 1073
    .line 1074
    const-string v12, "entry"

    .line 1075
    .line 1076
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1077
    .line 1078
    .line 1079
    iget-object v12, v11, Lz9/k;->e:Lz9/u;

    .line 1080
    .line 1081
    iget-object v12, v12, Lz9/u;->e:Lca/j;

    .line 1082
    .line 1083
    iget v12, v12, Lca/j;->a:I

    .line 1084
    .line 1085
    iget-object v13, v11, Lz9/k;->i:Ljava/lang/String;

    .line 1086
    .line 1087
    iget-object v11, v11, Lz9/k;->k:Lca/c;

    .line 1088
    .line 1089
    invoke-virtual {v11}, Lca/c;->a()Landroid/os/Bundle;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v14

    .line 1093
    new-array v15, v6, [Llx0/l;

    .line 1094
    .line 1095
    invoke-static {v15, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v15

    .line 1099
    check-cast v15, [Llx0/l;

    .line 1100
    .line 1101
    invoke-static {v15}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v15

    .line 1105
    iget-object v11, v11, Lca/c;->h:Lra/e;

    .line 1106
    .line 1107
    invoke-virtual {v11, v15}, Lra/e;->c(Landroid/os/Bundle;)V

    .line 1108
    .line 1109
    .line 1110
    new-array v11, v6, [Llx0/l;

    .line 1111
    .line 1112
    invoke-static {v11, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v11

    .line 1116
    check-cast v11, [Llx0/l;

    .line 1117
    .line 1118
    invoke-static {v11}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1119
    .line 1120
    .line 1121
    move-result-object v11

    .line 1122
    invoke-static {v10, v13, v11}, Lkp/v;->e(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1123
    .line 1124
    .line 1125
    invoke-virtual {v11, v9, v12}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 1126
    .line 1127
    .line 1128
    if-nez v14, :cond_1d

    .line 1129
    .line 1130
    new-array v12, v6, [Llx0/l;

    .line 1131
    .line 1132
    invoke-static {v12, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v12

    .line 1136
    check-cast v12, [Llx0/l;

    .line 1137
    .line 1138
    invoke-static {v12}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1139
    .line 1140
    .line 1141
    move-result-object v14

    .line 1142
    :cond_1d
    invoke-static {v11, v8, v14}, Lkp/v;->d(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1143
    .line 1144
    .line 1145
    invoke-static {v11, v7, v15}, Lkp/v;->d(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1146
    .line 1147
    .line 1148
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1149
    .line 1150
    .line 1151
    goto :goto_16

    .line 1152
    :cond_1e
    const-string v3, "android-support-nav:controller:backStack"

    .line 1153
    .line 1154
    invoke-virtual {v1, v3, v5}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 1155
    .line 1156
    .line 1157
    :cond_1f
    invoke-interface {v4}, Ljava/util/Map;->isEmpty()Z

    .line 1158
    .line 1159
    .line 1160
    move-result v3

    .line 1161
    if-nez v3, :cond_23

    .line 1162
    .line 1163
    if-nez v1, :cond_20

    .line 1164
    .line 1165
    new-array v1, v6, [Llx0/l;

    .line 1166
    .line 1167
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v1

    .line 1171
    check-cast v1, [Llx0/l;

    .line 1172
    .line 1173
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1174
    .line 1175
    .line 1176
    move-result-object v1

    .line 1177
    :cond_20
    invoke-interface {v4}, Ljava/util/Map;->size()I

    .line 1178
    .line 1179
    .line 1180
    move-result v3

    .line 1181
    new-array v3, v3, [I

    .line 1182
    .line 1183
    new-instance v5, Ljava/util/ArrayList;

    .line 1184
    .line 1185
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 1186
    .line 1187
    .line 1188
    invoke-virtual {v4}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v4

    .line 1192
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v4

    .line 1196
    move v11, v6

    .line 1197
    :goto_17
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1198
    .line 1199
    .line 1200
    move-result v12

    .line 1201
    if-eqz v12, :cond_22

    .line 1202
    .line 1203
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v12

    .line 1207
    check-cast v12, Ljava/util/Map$Entry;

    .line 1208
    .line 1209
    invoke-interface {v12}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v13

    .line 1213
    check-cast v13, Ljava/lang/Number;

    .line 1214
    .line 1215
    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    .line 1216
    .line 1217
    .line 1218
    move-result v13

    .line 1219
    invoke-interface {v12}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1220
    .line 1221
    .line 1222
    move-result-object v12

    .line 1223
    check-cast v12, Ljava/lang/String;

    .line 1224
    .line 1225
    add-int/lit8 v14, v11, 0x1

    .line 1226
    .line 1227
    aput v13, v3, v11

    .line 1228
    .line 1229
    if-nez v12, :cond_21

    .line 1230
    .line 1231
    const-string v12, ""

    .line 1232
    .line 1233
    :cond_21
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1234
    .line 1235
    .line 1236
    move v11, v14

    .line 1237
    goto :goto_17

    .line 1238
    :cond_22
    const-string v4, "android-support-nav:controller:backStackDestIds"

    .line 1239
    .line 1240
    invoke-virtual {v1, v4, v3}, Landroid/os/BaseBundle;->putIntArray(Ljava/lang/String;[I)V

    .line 1241
    .line 1242
    .line 1243
    const-string v3, "android-support-nav:controller:backStackIds"

    .line 1244
    .line 1245
    invoke-static {v1, v3, v5}, Lkp/v;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/util/List;)V

    .line 1246
    .line 1247
    .line 1248
    :cond_23
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    .line 1249
    .line 1250
    .line 1251
    move-result v3

    .line 1252
    if-nez v3, :cond_28

    .line 1253
    .line 1254
    if-nez v1, :cond_24

    .line 1255
    .line 1256
    new-array v1, v6, [Llx0/l;

    .line 1257
    .line 1258
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v1

    .line 1262
    check-cast v1, [Llx0/l;

    .line 1263
    .line 1264
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v1

    .line 1268
    :cond_24
    new-instance v3, Ljava/util/ArrayList;

    .line 1269
    .line 1270
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 1271
    .line 1272
    .line 1273
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v2

    .line 1277
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1278
    .line 1279
    .line 1280
    move-result-object v2

    .line 1281
    :goto_18
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1282
    .line 1283
    .line 1284
    move-result v4

    .line 1285
    if-eqz v4, :cond_27

    .line 1286
    .line 1287
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1288
    .line 1289
    .line 1290
    move-result-object v4

    .line 1291
    check-cast v4, Ljava/util/Map$Entry;

    .line 1292
    .line 1293
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1294
    .line 1295
    .line 1296
    move-result-object v5

    .line 1297
    check-cast v5, Ljava/lang/String;

    .line 1298
    .line 1299
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v4

    .line 1303
    check-cast v4, Lmx0/l;

    .line 1304
    .line 1305
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1306
    .line 1307
    .line 1308
    new-instance v11, Ljava/util/ArrayList;

    .line 1309
    .line 1310
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 1311
    .line 1312
    .line 1313
    invoke-virtual {v4}, Ljava/util/AbstractList;->iterator()Ljava/util/Iterator;

    .line 1314
    .line 1315
    .line 1316
    move-result-object v4

    .line 1317
    :goto_19
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1318
    .line 1319
    .line 1320
    move-result v12

    .line 1321
    if-eqz v12, :cond_26

    .line 1322
    .line 1323
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1324
    .line 1325
    .line 1326
    move-result-object v12

    .line 1327
    check-cast v12, Lz9/l;

    .line 1328
    .line 1329
    iget-object v12, v12, Lz9/l;->a:Lio/o;

    .line 1330
    .line 1331
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1332
    .line 1333
    .line 1334
    new-array v13, v6, [Llx0/l;

    .line 1335
    .line 1336
    invoke-static {v13, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1337
    .line 1338
    .line 1339
    move-result-object v13

    .line 1340
    check-cast v13, [Llx0/l;

    .line 1341
    .line 1342
    invoke-static {v13}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1343
    .line 1344
    .line 1345
    move-result-object v13

    .line 1346
    iget-object v14, v12, Lio/o;->e:Ljava/lang/Object;

    .line 1347
    .line 1348
    check-cast v14, Ljava/lang/String;

    .line 1349
    .line 1350
    invoke-static {v10, v14, v13}, Lkp/v;->e(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1351
    .line 1352
    .line 1353
    iget v14, v12, Lio/o;->d:I

    .line 1354
    .line 1355
    invoke-virtual {v13, v9, v14}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 1356
    .line 1357
    .line 1358
    iget-object v14, v12, Lio/o;->f:Ljava/lang/Object;

    .line 1359
    .line 1360
    check-cast v14, Landroid/os/Bundle;

    .line 1361
    .line 1362
    if-nez v14, :cond_25

    .line 1363
    .line 1364
    new-array v14, v6, [Llx0/l;

    .line 1365
    .line 1366
    invoke-static {v14, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1367
    .line 1368
    .line 1369
    move-result-object v14

    .line 1370
    check-cast v14, [Llx0/l;

    .line 1371
    .line 1372
    invoke-static {v14}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v14

    .line 1376
    :cond_25
    invoke-static {v13, v8, v14}, Lkp/v;->d(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1377
    .line 1378
    .line 1379
    iget-object v12, v12, Lio/o;->g:Ljava/lang/Object;

    .line 1380
    .line 1381
    check-cast v12, Landroid/os/Bundle;

    .line 1382
    .line 1383
    invoke-static {v13, v7, v12}, Lkp/v;->d(Landroid/os/Bundle;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1384
    .line 1385
    .line 1386
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1387
    .line 1388
    .line 1389
    goto :goto_19

    .line 1390
    :cond_26
    new-instance v4, Ljava/lang/StringBuilder;

    .line 1391
    .line 1392
    const-string v12, "android-support-nav:controller:backStackStates:"

    .line 1393
    .line 1394
    invoke-direct {v4, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1395
    .line 1396
    .line 1397
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1398
    .line 1399
    .line 1400
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1401
    .line 1402
    .line 1403
    move-result-object v4

    .line 1404
    const-string v5, "key"

    .line 1405
    .line 1406
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1407
    .line 1408
    .line 1409
    invoke-virtual {v1, v4, v11}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 1410
    .line 1411
    .line 1412
    goto/16 :goto_18

    .line 1413
    .line 1414
    :cond_27
    const-string v2, "android-support-nav:controller:backStackStates"

    .line 1415
    .line 1416
    invoke-static {v1, v2, v3}, Lkp/v;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/util/List;)V

    .line 1417
    .line 1418
    .line 1419
    :cond_28
    iget-boolean v2, v0, Lz9/y;->e:Z

    .line 1420
    .line 1421
    if-eqz v2, :cond_2a

    .line 1422
    .line 1423
    if-nez v1, :cond_29

    .line 1424
    .line 1425
    new-array v1, v6, [Llx0/l;

    .line 1426
    .line 1427
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v1

    .line 1431
    check-cast v1, [Llx0/l;

    .line 1432
    .line 1433
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 1434
    .line 1435
    .line 1436
    move-result-object v1

    .line 1437
    :cond_29
    const-string v2, "android-support-nav:controller:deepLinkHandled"

    .line 1438
    .line 1439
    iget-boolean v0, v0, Lz9/y;->e:Z

    .line 1440
    .line 1441
    invoke-virtual {v1, v2, v0}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 1442
    .line 1443
    .line 1444
    :cond_2a
    return-object v1

    .line 1445
    :pswitch_1a
    check-cast v0, Ll2/o;

    .line 1446
    .line 1447
    move-object/from16 v1, p2

    .line 1448
    .line 1449
    check-cast v1, Ljava/lang/Integer;

    .line 1450
    .line 1451
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1452
    .line 1453
    .line 1454
    const/4 v1, 0x1

    .line 1455
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1456
    .line 1457
    .line 1458
    move-result v1

    .line 1459
    invoke-static {v0, v1}, La71/b;->l(Ll2/o;I)V

    .line 1460
    .line 1461
    .line 1462
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1463
    .line 1464
    return-object v0

    .line 1465
    :pswitch_1b
    check-cast v0, Ll2/o;

    .line 1466
    .line 1467
    move-object/from16 v1, p2

    .line 1468
    .line 1469
    check-cast v1, Ljava/lang/Integer;

    .line 1470
    .line 1471
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1472
    .line 1473
    .line 1474
    move-result v1

    .line 1475
    and-int/lit8 v2, v1, 0x3

    .line 1476
    .line 1477
    const/4 v3, 0x2

    .line 1478
    const/4 v4, 0x1

    .line 1479
    if-eq v2, v3, :cond_2b

    .line 1480
    .line 1481
    move v2, v4

    .line 1482
    goto :goto_1a

    .line 1483
    :cond_2b
    const/4 v2, 0x0

    .line 1484
    :goto_1a
    and-int/2addr v1, v4

    .line 1485
    check-cast v0, Ll2/t;

    .line 1486
    .line 1487
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1488
    .line 1489
    .line 1490
    move-result v1

    .line 1491
    if-eqz v1, :cond_2c

    .line 1492
    .line 1493
    goto :goto_1b

    .line 1494
    :cond_2c
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 1495
    .line 1496
    .line 1497
    :goto_1b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1498
    .line 1499
    return-object v0

    .line 1500
    :pswitch_1c
    check-cast v0, Lk21/a;

    .line 1501
    .line 1502
    move-object/from16 v1, p2

    .line 1503
    .line 1504
    check-cast v1, Lg21/a;

    .line 1505
    .line 1506
    const-string v2, "$this$viewModel"

    .line 1507
    .line 1508
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1509
    .line 1510
    .line 1511
    const-string v2, "it"

    .line 1512
    .line 1513
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1514
    .line 1515
    .line 1516
    new-instance v3, Lc00/k1;

    .line 1517
    .line 1518
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1519
    .line 1520
    const-class v2, Ltr0/b;

    .line 1521
    .line 1522
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1523
    .line 1524
    .line 1525
    move-result-object v2

    .line 1526
    const/4 v4, 0x0

    .line 1527
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1528
    .line 1529
    .line 1530
    move-result-object v2

    .line 1531
    check-cast v2, Ltr0/b;

    .line 1532
    .line 1533
    const-class v5, Lb00/h;

    .line 1534
    .line 1535
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1536
    .line 1537
    .line 1538
    move-result-object v5

    .line 1539
    invoke-virtual {v0, v5, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1540
    .line 1541
    .line 1542
    move-result-object v5

    .line 1543
    check-cast v5, Lb00/h;

    .line 1544
    .line 1545
    const-class v6, Lij0/a;

    .line 1546
    .line 1547
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1548
    .line 1549
    .line 1550
    move-result-object v6

    .line 1551
    invoke-virtual {v0, v6, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v6

    .line 1555
    check-cast v6, Lij0/a;

    .line 1556
    .line 1557
    const-class v7, Lkf0/v;

    .line 1558
    .line 1559
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1560
    .line 1561
    .line 1562
    move-result-object v7

    .line 1563
    invoke-virtual {v0, v7, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1564
    .line 1565
    .line 1566
    move-result-object v7

    .line 1567
    check-cast v7, Lkf0/v;

    .line 1568
    .line 1569
    const-class v8, Llb0/p;

    .line 1570
    .line 1571
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v8

    .line 1575
    invoke-virtual {v0, v8, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1576
    .line 1577
    .line 1578
    move-result-object v8

    .line 1579
    check-cast v8, Llb0/p;

    .line 1580
    .line 1581
    const-class v9, Llb0/b;

    .line 1582
    .line 1583
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1584
    .line 1585
    .line 1586
    move-result-object v9

    .line 1587
    invoke-virtual {v0, v9, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v9

    .line 1591
    check-cast v9, Llb0/b;

    .line 1592
    .line 1593
    const-class v10, Lrq0/f;

    .line 1594
    .line 1595
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1596
    .line 1597
    .line 1598
    move-result-object v10

    .line 1599
    invoke-virtual {v0, v10, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1600
    .line 1601
    .line 1602
    move-result-object v10

    .line 1603
    check-cast v10, Lrq0/f;

    .line 1604
    .line 1605
    const-class v11, Lrq0/d;

    .line 1606
    .line 1607
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1608
    .line 1609
    .line 1610
    move-result-object v11

    .line 1611
    invoke-virtual {v0, v11, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1612
    .line 1613
    .line 1614
    move-result-object v11

    .line 1615
    check-cast v11, Lrq0/d;

    .line 1616
    .line 1617
    const-class v12, Llb0/g0;

    .line 1618
    .line 1619
    invoke-virtual {v1, v12}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1620
    .line 1621
    .line 1622
    move-result-object v12

    .line 1623
    invoke-virtual {v0, v12, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1624
    .line 1625
    .line 1626
    move-result-object v12

    .line 1627
    check-cast v12, Llb0/g0;

    .line 1628
    .line 1629
    const-class v13, Llb0/o0;

    .line 1630
    .line 1631
    invoke-virtual {v1, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1632
    .line 1633
    .line 1634
    move-result-object v13

    .line 1635
    invoke-virtual {v0, v13, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1636
    .line 1637
    .line 1638
    move-result-object v13

    .line 1639
    check-cast v13, Llb0/o0;

    .line 1640
    .line 1641
    const-class v14, Llb0/m0;

    .line 1642
    .line 1643
    invoke-virtual {v1, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1644
    .line 1645
    .line 1646
    move-result-object v14

    .line 1647
    invoke-virtual {v0, v14, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1648
    .line 1649
    .line 1650
    move-result-object v14

    .line 1651
    check-cast v14, Llb0/m0;

    .line 1652
    .line 1653
    const-class v15, Llb0/r0;

    .line 1654
    .line 1655
    invoke-virtual {v1, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1656
    .line 1657
    .line 1658
    move-result-object v15

    .line 1659
    invoke-virtual {v0, v15, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1660
    .line 1661
    .line 1662
    move-result-object v15

    .line 1663
    check-cast v15, Llb0/r0;

    .line 1664
    .line 1665
    move-object/from16 p0, v2

    .line 1666
    .line 1667
    const-class v2, Llb0/g;

    .line 1668
    .line 1669
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1670
    .line 1671
    .line 1672
    move-result-object v2

    .line 1673
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1674
    .line 1675
    .line 1676
    move-result-object v2

    .line 1677
    move-object/from16 v16, v2

    .line 1678
    .line 1679
    check-cast v16, Llb0/g;

    .line 1680
    .line 1681
    const-class v2, Llb0/i;

    .line 1682
    .line 1683
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1684
    .line 1685
    .line 1686
    move-result-object v2

    .line 1687
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1688
    .line 1689
    .line 1690
    move-result-object v2

    .line 1691
    move-object/from16 v17, v2

    .line 1692
    .line 1693
    check-cast v17, Llb0/i;

    .line 1694
    .line 1695
    const-class v2, Ljn0/c;

    .line 1696
    .line 1697
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1698
    .line 1699
    .line 1700
    move-result-object v2

    .line 1701
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1702
    .line 1703
    .line 1704
    move-result-object v2

    .line 1705
    move-object/from16 v18, v2

    .line 1706
    .line 1707
    check-cast v18, Ljn0/c;

    .line 1708
    .line 1709
    const-class v2, Lyt0/b;

    .line 1710
    .line 1711
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1712
    .line 1713
    .line 1714
    move-result-object v2

    .line 1715
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1716
    .line 1717
    .line 1718
    move-result-object v2

    .line 1719
    move-object/from16 v19, v2

    .line 1720
    .line 1721
    check-cast v19, Lyt0/b;

    .line 1722
    .line 1723
    const-class v2, Lcs0/n;

    .line 1724
    .line 1725
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1726
    .line 1727
    .line 1728
    move-result-object v2

    .line 1729
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1730
    .line 1731
    .line 1732
    move-result-object v2

    .line 1733
    move-object/from16 v20, v2

    .line 1734
    .line 1735
    check-cast v20, Lcs0/n;

    .line 1736
    .line 1737
    const-class v2, Llb0/e0;

    .line 1738
    .line 1739
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1740
    .line 1741
    .line 1742
    move-result-object v2

    .line 1743
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1744
    .line 1745
    .line 1746
    move-result-object v2

    .line 1747
    move-object/from16 v21, v2

    .line 1748
    .line 1749
    check-cast v21, Llb0/e0;

    .line 1750
    .line 1751
    const-class v2, Lqf0/g;

    .line 1752
    .line 1753
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1754
    .line 1755
    .line 1756
    move-result-object v2

    .line 1757
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1758
    .line 1759
    .line 1760
    move-result-object v2

    .line 1761
    move-object/from16 v22, v2

    .line 1762
    .line 1763
    check-cast v22, Lqf0/g;

    .line 1764
    .line 1765
    const-class v2, Lko0/f;

    .line 1766
    .line 1767
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1768
    .line 1769
    .line 1770
    move-result-object v2

    .line 1771
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1772
    .line 1773
    .line 1774
    move-result-object v2

    .line 1775
    move-object/from16 v23, v2

    .line 1776
    .line 1777
    check-cast v23, Lko0/f;

    .line 1778
    .line 1779
    const-class v2, Llb0/c0;

    .line 1780
    .line 1781
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1782
    .line 1783
    .line 1784
    move-result-object v1

    .line 1785
    invoke-virtual {v0, v1, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1786
    .line 1787
    .line 1788
    move-result-object v0

    .line 1789
    move-object/from16 v24, v0

    .line 1790
    .line 1791
    check-cast v24, Llb0/c0;

    .line 1792
    .line 1793
    move-object/from16 v4, p0

    .line 1794
    .line 1795
    invoke-direct/range {v3 .. v24}, Lc00/k1;-><init>(Ltr0/b;Lb00/h;Lij0/a;Lkf0/v;Llb0/p;Llb0/b;Lrq0/f;Lrq0/d;Llb0/g0;Llb0/o0;Llb0/m0;Llb0/r0;Llb0/g;Llb0/i;Ljn0/c;Lyt0/b;Lcs0/n;Llb0/e0;Lqf0/g;Lko0/f;Llb0/c0;)V

    .line 1796
    .line 1797
    .line 1798
    return-object v3

    .line 1799
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
