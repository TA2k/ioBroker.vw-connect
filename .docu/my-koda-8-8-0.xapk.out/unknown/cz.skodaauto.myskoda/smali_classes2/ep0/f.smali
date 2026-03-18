.class public final Lep0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;Lh21/b;)V
    .locals 0

    const/16 p1, 0x17

    iput p1, p0, Lep0/f;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lep0/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lep0/f;->d:I

    iput-object p1, p0, Lep0/f;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lep0/f;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object p0, p0, Lep0/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    invoke-static {}, Luu/a;->a()Luu/g;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast p0, Lyp0/d;

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lyp0/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    return-object v0

    .line 21
    :pswitch_0
    invoke-static {}, Luu/a;->a()Luu/g;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast p0, Lyk0/o;

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lyk0/o;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    return-object v0

    .line 31
    :pswitch_1
    check-cast p0, Lh21/b;

    .line 32
    .line 33
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iget-object v0, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Li21/b;

    .line 40
    .line 41
    iget-object v0, v0, Li21/b;->d:Lk21/a;

    .line 42
    .line 43
    const-class v1, Lyl/l;

    .line 44
    .line 45
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 46
    .line 47
    invoke-virtual {v3, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v0, v1, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_2
    check-cast p0, Ljava/lang/String;

    .line 57
    .line 58
    if-nez p0, :cond_0

    .line 59
    .line 60
    const-string p0, ""

    .line 61
    .line 62
    :cond_0
    return-object p0

    .line 63
    :pswitch_3
    check-cast p0, Ly10/e;

    .line 64
    .line 65
    iget-object p0, p0, Ly10/e;->c:Ljava/util/List;

    .line 66
    .line 67
    check-cast p0, Ljava/util/Collection;

    .line 68
    .line 69
    invoke-static {p0}, Ljp/k1;->g(Ljava/util/Collection;)Lgy0/j;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    iget p0, p0, Lgy0/h;->e:I

    .line 74
    .line 75
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    :pswitch_4
    check-cast p0, Lay0/k;

    .line 81
    .line 82
    sget-object v0, Lfh/b;->a:Lfh/b;

    .line 83
    .line 84
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    return-object v1

    .line 88
    :pswitch_5
    check-cast p0, Lvm0/c;

    .line 89
    .line 90
    iget-object p0, p0, Lvm0/c;->a:Lvm0/b;

    .line 91
    .line 92
    check-cast p0, Ltm0/a;

    .line 93
    .line 94
    iget-object p0, p0, Ltm0/a;->a:Lwe0/a;

    .line 95
    .line 96
    check-cast p0, Lwe0/c;

    .line 97
    .line 98
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :pswitch_6
    check-cast p0, Lay0/a;

    .line 108
    .line 109
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    return-object v1

    .line 113
    :pswitch_7
    check-cast p0, Lry/q;

    .line 114
    .line 115
    iget-object p0, p0, Lry/q;->d:Lwe0/a;

    .line 116
    .line 117
    check-cast p0, Lwe0/c;

    .line 118
    .line 119
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    :pswitch_8
    check-cast p0, Lod0/i0;

    .line 129
    .line 130
    iget-object p0, p0, Lod0/i0;->f:Lwe0/a;

    .line 131
    .line 132
    check-cast p0, Lwe0/c;

    .line 133
    .line 134
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0

    .line 143
    :pswitch_9
    check-cast p0, Lqa0/e;

    .line 144
    .line 145
    iget-object p0, p0, Lqa0/e;->a:Lqa0/c;

    .line 146
    .line 147
    check-cast p0, Loa0/a;

    .line 148
    .line 149
    iget-object p0, p0, Loa0/a;->a:Lwe0/a;

    .line 150
    .line 151
    check-cast p0, Lwe0/c;

    .line 152
    .line 153
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    return-object p0

    .line 162
    :pswitch_a
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 163
    .line 164
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->access$getVin$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    const-string v0, "SetupRPATearDown(): onDispose() - stop RPA immediately for vin = "

    .line 169
    .line 170
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    return-object p0

    .line 175
    :pswitch_b
    check-cast p0, Landroid/view/View;

    .line 176
    .line 177
    new-instance v0, Ljava/lang/StringBuilder;

    .line 178
    .line 179
    const-string v1, "SetupDisplaySize(): onDispose view = "

    .line 180
    .line 181
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    return-object p0

    .line 192
    :pswitch_c
    check-cast p0, Lq10/f;

    .line 193
    .line 194
    check-cast p0, Lo10/t;

    .line 195
    .line 196
    iget-object p0, p0, Lo10/t;->d:Lwe0/a;

    .line 197
    .line 198
    check-cast p0, Lwe0/c;

    .line 199
    .line 200
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 201
    .line 202
    .line 203
    move-result p0

    .line 204
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    return-object p0

    .line 209
    :pswitch_d
    check-cast p0, Lsr/h;

    .line 210
    .line 211
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    const-string v0, "Failed while fetching Firebase Remote Config. Exception message: "

    .line 216
    .line 217
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    return-object p0

    .line 222
    :pswitch_e
    check-cast p0, Lx61/a;

    .line 223
    .line 224
    new-instance v0, Ljava/lang/StringBuilder;

    .line 225
    .line 226
    const-string v1, "RPAScreen(): onDispose rpaScreenViewModel = "

    .line 227
    .line 228
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 232
    .line 233
    .line 234
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    return-object p0

    .line 239
    :pswitch_f
    check-cast p0, Lm20/j;

    .line 240
    .line 241
    iget-object p0, p0, Lm20/j;->b:Lwe0/a;

    .line 242
    .line 243
    check-cast p0, Lwe0/c;

    .line 244
    .line 245
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 246
    .line 247
    .line 248
    move-result p0

    .line 249
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 250
    .line 251
    .line 252
    move-result-object p0

    .line 253
    return-object p0

    .line 254
    :pswitch_10
    check-cast p0, Lno0/f;

    .line 255
    .line 256
    iget-object p0, p0, Lno0/f;->b:Lno0/d;

    .line 257
    .line 258
    check-cast p0, Llo0/a;

    .line 259
    .line 260
    iget-object p0, p0, Llo0/a;->a:Lwe0/a;

    .line 261
    .line 262
    check-cast p0, Lwe0/c;

    .line 263
    .line 264
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 265
    .line 266
    .line 267
    move-result p0

    .line 268
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    return-object p0

    .line 273
    :pswitch_11
    check-cast p0, Ljz/s;

    .line 274
    .line 275
    iget-object p0, p0, Ljz/s;->d:Lwe0/a;

    .line 276
    .line 277
    check-cast p0, Lwe0/c;

    .line 278
    .line 279
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 280
    .line 281
    .line 282
    move-result p0

    .line 283
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    return-object p0

    .line 288
    :pswitch_12
    check-cast p0, Ljb0/e0;

    .line 289
    .line 290
    iget-object p0, p0, Ljb0/e0;->d:Lwe0/a;

    .line 291
    .line 292
    check-cast p0, Lwe0/c;

    .line 293
    .line 294
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 295
    .line 296
    .line 297
    move-result p0

    .line 298
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    return-object p0

    .line 303
    :pswitch_13
    check-cast p0, Ll2/o1;

    .line 304
    .line 305
    iget-object p0, p0, Ll2/o1;->a:Ljava/util/ArrayList;

    .line 306
    .line 307
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 308
    .line 309
    .line 310
    move-result v0

    .line 311
    new-instance v1, Landroidx/collection/q0;

    .line 312
    .line 313
    invoke-direct {v1, v0}, Landroidx/collection/q0;-><init>(I)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 317
    .line 318
    .line 319
    move-result v0

    .line 320
    const/4 v3, 0x0

    .line 321
    move v4, v3

    .line 322
    :goto_0
    if-ge v4, v0, :cond_7

    .line 323
    .line 324
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v5

    .line 328
    check-cast v5, Ll2/u0;

    .line 329
    .line 330
    iget-object v6, v5, Ll2/u0;->b:Ljava/lang/Object;

    .line 331
    .line 332
    iget v7, v5, Ll2/u0;->a:I

    .line 333
    .line 334
    if-eqz v6, :cond_1

    .line 335
    .line 336
    new-instance v6, Ll2/t0;

    .line 337
    .line 338
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 339
    .line 340
    .line 341
    move-result-object v7

    .line 342
    iget-object v8, v5, Ll2/u0;->b:Ljava/lang/Object;

    .line 343
    .line 344
    invoke-direct {v6, v7, v8}, Ll2/t0;-><init>(Ljava/lang/Integer;Ljava/lang/Object;)V

    .line 345
    .line 346
    .line 347
    goto :goto_1

    .line 348
    :cond_1
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 349
    .line 350
    .line 351
    move-result-object v6

    .line 352
    :goto_1
    invoke-virtual {v1, v6}, Landroidx/collection/q0;->f(Ljava/lang/Object;)I

    .line 353
    .line 354
    .line 355
    move-result v7

    .line 356
    if-gez v7, :cond_2

    .line 357
    .line 358
    const/4 v8, 0x1

    .line 359
    goto :goto_2

    .line 360
    :cond_2
    move v8, v3

    .line 361
    :goto_2
    if-eqz v8, :cond_3

    .line 362
    .line 363
    move-object v9, v2

    .line 364
    goto :goto_3

    .line 365
    :cond_3
    iget-object v9, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 366
    .line 367
    aget-object v9, v9, v7

    .line 368
    .line 369
    :goto_3
    if-nez v9, :cond_4

    .line 370
    .line 371
    goto :goto_4

    .line 372
    :cond_4
    instance-of v10, v9, Landroidx/collection/l0;

    .line 373
    .line 374
    if-eqz v10, :cond_5

    .line 375
    .line 376
    check-cast v9, Landroidx/collection/l0;

    .line 377
    .line 378
    invoke-virtual {v9, v5}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 379
    .line 380
    .line 381
    move-object v5, v9

    .line 382
    goto :goto_4

    .line 383
    :cond_5
    sget-object v10, Landroidx/collection/w0;->a:[Ljava/lang/Object;

    .line 384
    .line 385
    new-instance v10, Landroidx/collection/l0;

    .line 386
    .line 387
    const/4 v11, 0x2

    .line 388
    invoke-direct {v10, v11}, Landroidx/collection/l0;-><init>(I)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v10, v9}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v10, v5}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 395
    .line 396
    .line 397
    move-object v5, v10

    .line 398
    :goto_4
    if-eqz v8, :cond_6

    .line 399
    .line 400
    not-int v7, v7

    .line 401
    iget-object v8, v1, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 402
    .line 403
    aput-object v6, v8, v7

    .line 404
    .line 405
    iget-object v6, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 406
    .line 407
    aput-object v5, v6, v7

    .line 408
    .line 409
    goto :goto_5

    .line 410
    :cond_6
    iget-object v6, v1, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 411
    .line 412
    aput-object v5, v6, v7

    .line 413
    .line 414
    :goto_5
    add-int/lit8 v4, v4, 0x1

    .line 415
    .line 416
    goto :goto_0

    .line 417
    :cond_7
    new-instance p0, Ln2/a;

    .line 418
    .line 419
    invoke-direct {p0, v1}, Ln2/a;-><init>(Landroidx/collection/q0;)V

    .line 420
    .line 421
    .line 422
    return-object p0

    .line 423
    :pswitch_14
    check-cast p0, Lym/g;

    .line 424
    .line 425
    sget v0, Lkv0/i;->a:F

    .line 426
    .line 427
    invoke-virtual {p0}, Lym/g;->getValue()Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object p0

    .line 431
    check-cast p0, Ljava/lang/Number;

    .line 432
    .line 433
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 434
    .line 435
    .line 436
    move-result p0

    .line 437
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 438
    .line 439
    .line 440
    move-result-object p0

    .line 441
    return-object p0

    .line 442
    :pswitch_15
    check-cast p0, Lkf0/z;

    .line 443
    .line 444
    iget-object p0, p0, Lkf0/z;->b:Lif0/f0;

    .line 445
    .line 446
    iget-object p0, p0, Lif0/f0;->h:Lwe0/a;

    .line 447
    .line 448
    check-cast p0, Lwe0/c;

    .line 449
    .line 450
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 451
    .line 452
    .line 453
    move-result p0

    .line 454
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 455
    .line 456
    .line 457
    move-result-object p0

    .line 458
    return-object p0

    .line 459
    :pswitch_16
    check-cast p0, Li70/c0;

    .line 460
    .line 461
    iget-object p0, p0, Li70/c0;->a:Lwe0/a;

    .line 462
    .line 463
    check-cast p0, Lwe0/c;

    .line 464
    .line 465
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 466
    .line 467
    .line 468
    move-result p0

    .line 469
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 470
    .line 471
    .line 472
    move-result-object p0

    .line 473
    return-object p0

    .line 474
    :pswitch_17
    check-cast p0, Lh2/t8;

    .line 475
    .line 476
    iget-object p0, p0, Lh2/t8;->i:Lh2/zb;

    .line 477
    .line 478
    iget-wide v0, p0, Lh2/zb;->a:J

    .line 479
    .line 480
    iget-wide v2, p0, Lh2/zb;->b:J

    .line 481
    .line 482
    sget-object p0, Lc1/z;->c:Lc1/s;

    .line 483
    .line 484
    const/4 v4, 0x0

    .line 485
    invoke-virtual {p0, v4}, Lc1/s;->b(F)F

    .line 486
    .line 487
    .line 488
    move-result p0

    .line 489
    invoke-static {v0, v1, v2, v3, p0}, Le3/j0;->q(JJF)J

    .line 490
    .line 491
    .line 492
    move-result-wide v0

    .line 493
    new-instance p0, Le3/s;

    .line 494
    .line 495
    invoke-direct {p0, v0, v1}, Le3/s;-><init>(J)V

    .line 496
    .line 497
    .line 498
    return-object p0

    .line 499
    :pswitch_18
    check-cast p0, Lcp0/l;

    .line 500
    .line 501
    iget-object p0, p0, Lcp0/l;->b:Lwe0/a;

    .line 502
    .line 503
    check-cast p0, Lwe0/c;

    .line 504
    .line 505
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 506
    .line 507
    .line 508
    move-result p0

    .line 509
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 510
    .line 511
    .line 512
    move-result-object p0

    .line 513
    return-object p0

    .line 514
    nop

    .line 515
    :pswitch_data_0
    .packed-switch 0x0
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
