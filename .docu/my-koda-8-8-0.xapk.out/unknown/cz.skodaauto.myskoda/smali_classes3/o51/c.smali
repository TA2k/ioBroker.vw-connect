.class public final synthetic Lo51/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lo51/c;->d:I

    iput-object p2, p0, Lo51/c;->e:Ljava/lang/Object;

    iput-object p3, p0, Lo51/c;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lt1/k1;Lg4/e;Lw3/r0;)V
    .locals 0

    .line 2
    const/16 p1, 0x17

    iput p1, p0, Lo51/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lo51/c;->e:Ljava/lang/Object;

    iput-object p3, p0, Lo51/c;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 15

    .line 1
    iget v0, p0, Lo51/c;->d:I

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const/4 v2, 0x0

    .line 5
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v4, p0, Lo51/c;->f:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object p0, p0, Lo51/c;->e:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast p0, Llx0/l;

    .line 15
    .line 16
    check-cast v4, Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->g(Llx0/l;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p0, Lt71/f;

    .line 24
    .line 25
    check-cast v4, Lkotlin/jvm/internal/f0;

    .line 26
    .line 27
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->B(Lt71/f;Lkotlin/jvm/internal/f0;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 33
    .line 34
    check-cast v4, Lk71/c;

    .line 35
    .line 36
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->h(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lk71/c;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_2
    check-cast p0, Lorg/altbeacon/beacon/Region;

    .line 42
    .line 43
    check-cast v4, Lt41/b;

    .line 44
    .line 45
    new-instance v0, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string v1, "removeRegionForRangingBeacons(): Region = "

    .line 48
    .line 49
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p0, " ("

    .line 56
    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, ") lost"

    .line 64
    .line 65
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_3
    check-cast p0, Lorg/altbeacon/beacon/Beacon;

    .line 74
    .line 75
    check-cast v4, Lt41/a0;

    .line 76
    .line 77
    new-instance v0, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    const-string v1, "updateBeaconSignal(): The signal of "

    .line 80
    .line 81
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string p0, " changed to "

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string p0, "."

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0

    .line 105
    :pswitch_4
    check-cast p0, Lay0/k;

    .line 106
    .line 107
    check-cast v4, Ls10/i;

    .line 108
    .line 109
    iget-wide v0, v4, Ls10/i;->a:J

    .line 110
    .line 111
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    return-object v3

    .line 119
    :pswitch_5
    check-cast p0, Lg4/e;

    .line 120
    .line 121
    check-cast v4, Lw3/r0;

    .line 122
    .line 123
    iget-object p0, p0, Lg4/e;->a:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Lg4/n;

    .line 126
    .line 127
    instance-of v0, p0, Lg4/m;

    .line 128
    .line 129
    if-eqz v0, :cond_1

    .line 130
    .line 131
    move-object v0, p0

    .line 132
    check-cast v0, Lg4/m;

    .line 133
    .line 134
    iget-object v0, v0, Lg4/m;->c:Lxf0/x1;

    .line 135
    .line 136
    if-eqz v0, :cond_0

    .line 137
    .line 138
    iget-object p0, v0, Lxf0/x1;->a:Lay0/k;

    .line 139
    .line 140
    iget-object v0, v0, Lxf0/x1;->b:Lxf0/w1;

    .line 141
    .line 142
    iget-object v0, v0, Lxf0/w1;->b:Ljava/lang/String;

    .line 143
    .line 144
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    goto :goto_0

    .line 148
    :cond_0
    :try_start_0
    check-cast p0, Lg4/m;

    .line 149
    .line 150
    iget-object p0, p0, Lg4/m;->a:Ljava/lang/String;

    .line 151
    .line 152
    invoke-virtual {v4, p0}, Lw3/r0;->a(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 153
    .line 154
    .line 155
    goto :goto_0

    .line 156
    :cond_1
    instance-of v0, p0, Lg4/l;

    .line 157
    .line 158
    if-eqz v0, :cond_2

    .line 159
    .line 160
    check-cast p0, Lg4/l;

    .line 161
    .line 162
    iget-object p0, p0, Lg4/l;->c:Lxf0/x1;

    .line 163
    .line 164
    if-eqz p0, :cond_2

    .line 165
    .line 166
    iget-object v0, p0, Lxf0/x1;->a:Lay0/k;

    .line 167
    .line 168
    iget-object p0, p0, Lxf0/x1;->b:Lxf0/w1;

    .line 169
    .line 170
    iget-object p0, p0, Lxf0/w1;->b:Ljava/lang/String;

    .line 171
    .line 172
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    :catch_0
    :cond_2
    :goto_0
    return-object v3

    .line 176
    :pswitch_6
    check-cast p0, Lt1/k1;

    .line 177
    .line 178
    check-cast v4, Lg4/g;

    .line 179
    .line 180
    if-eqz p0, :cond_6

    .line 181
    .line 182
    iget-object v0, p0, Lt1/k1;->c:Lv2/o;

    .line 183
    .line 184
    invoke-virtual {v0}, Lv2/o;->isEmpty()Z

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    if-eqz v1, :cond_3

    .line 189
    .line 190
    iget-object v0, p0, Lt1/k1;->b:Lg4/g;

    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_3
    new-instance v1, Lt1/t0;

    .line 194
    .line 195
    iget-object v3, p0, Lt1/k1;->b:Lg4/g;

    .line 196
    .line 197
    invoke-direct {v1, v3}, Lt1/t0;-><init>(Lg4/g;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v0}, Lv2/o;->size()I

    .line 201
    .line 202
    .line 203
    move-result v3

    .line 204
    :goto_1
    if-ge v2, v3, :cond_4

    .line 205
    .line 206
    invoke-virtual {v0, v2}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v5

    .line 210
    check-cast v5, Lay0/k;

    .line 211
    .line 212
    invoke-interface {v5, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    add-int/lit8 v2, v2, 0x1

    .line 216
    .line 217
    goto :goto_1

    .line 218
    :cond_4
    iget-object v0, v1, Lt1/t0;->b:Lg4/g;

    .line 219
    .line 220
    :goto_2
    iput-object v0, p0, Lt1/k1;->b:Lg4/g;

    .line 221
    .line 222
    if-nez v0, :cond_5

    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_5
    move-object v4, v0

    .line 226
    :cond_6
    :goto_3
    return-object v4

    .line 227
    :pswitch_7
    check-cast p0, Ll4/v;

    .line 228
    .line 229
    check-cast v4, Ll2/b1;

    .line 230
    .line 231
    iget-wide v0, p0, Ll4/v;->b:J

    .line 232
    .line 233
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    check-cast v2, Ll4/v;

    .line 238
    .line 239
    iget-wide v5, v2, Ll4/v;->b:J

    .line 240
    .line 241
    invoke-static {v0, v1, v5, v6}, Lg4/o0;->b(JJ)Z

    .line 242
    .line 243
    .line 244
    move-result v0

    .line 245
    if-eqz v0, :cond_7

    .line 246
    .line 247
    iget-object v0, p0, Ll4/v;->c:Lg4/o0;

    .line 248
    .line 249
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    check-cast v1, Ll4/v;

    .line 254
    .line 255
    iget-object v1, v1, Ll4/v;->c:Lg4/o0;

    .line 256
    .line 257
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v0

    .line 261
    if-nez v0, :cond_8

    .line 262
    .line 263
    :cond_7
    invoke-interface {v4, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    :cond_8
    return-object v3

    .line 267
    :pswitch_8
    check-cast p0, Lrm0/c;

    .line 268
    .line 269
    check-cast v4, Lay0/a;

    .line 270
    .line 271
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    check-cast v0, Lrm0/b;

    .line 276
    .line 277
    sget-object v1, Lrm0/a;->d:Lrm0/a;

    .line 278
    .line 279
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 280
    .line 281
    .line 282
    new-instance v0, Lrm0/b;

    .line 283
    .line 284
    invoke-direct {v0, v2, v1, v2, v2}, Lrm0/b;-><init>(ZLrm0/a;ZI)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 288
    .line 289
    .line 290
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    return-object v3

    .line 294
    :pswitch_9
    check-cast p0, Lay0/k;

    .line 295
    .line 296
    check-cast v4, Lr60/r;

    .line 297
    .line 298
    iget-boolean v0, v4, Lr60/r;->a:Z

    .line 299
    .line 300
    xor-int/lit8 v0, v0, 0x1

    .line 301
    .line 302
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    return-object v3

    .line 310
    :pswitch_a
    check-cast p0, Ls10/e;

    .line 311
    .line 312
    check-cast v4, Lcn0/c;

    .line 313
    .line 314
    iget-object v0, p0, Ls10/e;->l:Lij0/a;

    .line 315
    .line 316
    iget-object v1, v4, Lcn0/c;->e:Lcn0/a;

    .line 317
    .line 318
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 319
    .line 320
    .line 321
    move-result v1

    .line 322
    const/16 v4, 0x1c

    .line 323
    .line 324
    const v5, 0x7f120f45

    .line 325
    .line 326
    .line 327
    if-eq v1, v4, :cond_a

    .line 328
    .line 329
    const/16 v4, 0x1e

    .line 330
    .line 331
    if-eq v1, v4, :cond_9

    .line 332
    .line 333
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    check-cast v0, Ls10/b;

    .line 338
    .line 339
    goto :goto_4

    .line 340
    :cond_9
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 341
    .line 342
    .line 343
    move-result-object v1

    .line 344
    move-object v6, v1

    .line 345
    check-cast v6, Ls10/b;

    .line 346
    .line 347
    new-array v1, v2, [Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v0, Ljj0/f;

    .line 350
    .line 351
    invoke-virtual {v0, v5, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v8

    .line 355
    const/4 v13, 0x0

    .line 356
    const/16 v14, 0xbd

    .line 357
    .line 358
    const/4 v7, 0x0

    .line 359
    const/4 v9, 0x0

    .line 360
    const/4 v10, 0x0

    .line 361
    const/4 v11, 0x0

    .line 362
    const/4 v12, 0x0

    .line 363
    invoke-static/range {v6 .. v14}, Ls10/b;->a(Ls10/b;Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZI)Ls10/b;

    .line 364
    .line 365
    .line 366
    move-result-object v0

    .line 367
    goto :goto_4

    .line 368
    :cond_a
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    move-object v6, v1

    .line 373
    check-cast v6, Ls10/b;

    .line 374
    .line 375
    new-array v1, v2, [Ljava/lang/Object;

    .line 376
    .line 377
    check-cast v0, Ljj0/f;

    .line 378
    .line 379
    invoke-virtual {v0, v5, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v10

    .line 383
    const/4 v13, 0x0

    .line 384
    const/16 v14, 0xd7

    .line 385
    .line 386
    const/4 v7, 0x0

    .line 387
    const/4 v8, 0x0

    .line 388
    const/4 v9, 0x0

    .line 389
    const/4 v11, 0x0

    .line 390
    const/4 v12, 0x1

    .line 391
    invoke-static/range {v6 .. v14}, Ls10/b;->a(Ls10/b;Lql0/g;Ljava/lang/String;ILjava/lang/String;IZZI)Ls10/b;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    :goto_4
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 396
    .line 397
    .line 398
    return-object v3

    .line 399
    :pswitch_b
    check-cast p0, Ljava/lang/String;

    .line 400
    .line 401
    check-cast v4, Lne0/s;

    .line 402
    .line 403
    invoke-static {p0}, Lto0/h;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 404
    .line 405
    .line 406
    move-result-object p0

    .line 407
    new-instance v0, Ljava/lang/StringBuilder;

    .line 408
    .line 409
    const-string v1, "Connector detail of `"

    .line 410
    .line 411
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 415
    .line 416
    .line 417
    const-string p0, "` = "

    .line 418
    .line 419
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 420
    .line 421
    .line 422
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 423
    .line 424
    .line 425
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 426
    .line 427
    .line 428
    move-result-object p0

    .line 429
    return-object p0

    .line 430
    :pswitch_c
    check-cast p0, Lay0/k;

    .line 431
    .line 432
    check-cast v4, Lpk0/a;

    .line 433
    .line 434
    invoke-interface {p0, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    return-object v3

    .line 438
    :pswitch_d
    check-cast p0, Lay0/k;

    .line 439
    .line 440
    check-cast v4, Lqg/k;

    .line 441
    .line 442
    new-instance v0, Lqg/d;

    .line 443
    .line 444
    iget-object v1, v4, Lqg/k;->b:Lqg/h;

    .line 445
    .line 446
    iget-object v1, v1, Lqg/h;->e:Ljava/lang/String;

    .line 447
    .line 448
    invoke-direct {v0, v1}, Lqg/d;-><init>(Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    return-object v3

    .line 455
    :pswitch_e
    check-cast p0, Lay0/k;

    .line 456
    .line 457
    check-cast v4, Lq00/a;

    .line 458
    .line 459
    iget-object v0, v4, Lq00/a;->c:Ljava/lang/String;

    .line 460
    .line 461
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    return-object v3

    .line 465
    :pswitch_f
    check-cast p0, Ljava/lang/String;

    .line 466
    .line 467
    check-cast v4, Lqz0/f;

    .line 468
    .line 469
    sget-object v0, Lsz0/c;->c:Lsz0/c;

    .line 470
    .line 471
    new-array v1, v2, [Lsz0/g;

    .line 472
    .line 473
    new-instance v3, Lqz0/e;

    .line 474
    .line 475
    invoke-direct {v3, v4, v2}, Lqz0/e;-><init>(Lqz0/f;I)V

    .line 476
    .line 477
    .line 478
    invoke-static {p0, v0, v1, v3}, Lkp/x8;->d(Ljava/lang/String;Lkp/y8;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 479
    .line 480
    .line 481
    move-result-object p0

    .line 482
    return-object p0

    .line 483
    :pswitch_10
    check-cast p0, Lay0/k;

    .line 484
    .line 485
    check-cast v4, Llc/l;

    .line 486
    .line 487
    new-instance v0, Lpg/h;

    .line 488
    .line 489
    iget-object v1, v4, Llc/l;->i:Lk/a;

    .line 490
    .line 491
    invoke-virtual {v1}, Lk/a;->b()Llc/b;

    .line 492
    .line 493
    .line 494
    move-result-object v1

    .line 495
    invoke-direct {v0, v1}, Lpg/h;-><init>(Llc/b;)V

    .line 496
    .line 497
    .line 498
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    return-object v3

    .line 502
    :pswitch_11
    check-cast p0, Ljava/lang/String;

    .line 503
    .line 504
    check-cast v4, Lq51/e;

    .line 505
    .line 506
    new-instance v0, Ljava/lang/StringBuilder;

    .line 507
    .line 508
    const-string v1, "fileNameForKey(): Failed to generate file name for key = "

    .line 509
    .line 510
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 511
    .line 512
    .line 513
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 514
    .line 515
    .line 516
    const-string p0, " / accessibility = "

    .line 517
    .line 518
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 519
    .line 520
    .line 521
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 522
    .line 523
    .line 524
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 525
    .line 526
    .line 527
    move-result-object p0

    .line 528
    return-object p0

    .line 529
    :pswitch_12
    check-cast p0, Ljava/lang/Throwable;

    .line 530
    .line 531
    check-cast v4, Ljava/lang/String;

    .line 532
    .line 533
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 534
    .line 535
    .line 536
    move-result-object p0

    .line 537
    const-string v0, ": "

    .line 538
    .line 539
    invoke-static {p0, v0, v4}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 540
    .line 541
    .line 542
    move-result-object p0

    .line 543
    return-object p0

    .line 544
    :pswitch_13
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 545
    .line 546
    check-cast v4, Lay0/a;

    .line 547
    .line 548
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->d(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Lay0/a;)Llx0/b0;

    .line 549
    .line 550
    .line 551
    move-result-object p0

    .line 552
    return-object p0

    .line 553
    :pswitch_14
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 554
    .line 555
    check-cast v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;

    .line 556
    .line 557
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/P2CMessage;)Llx0/b0;

    .line 558
    .line 559
    .line 560
    move-result-object p0

    .line 561
    return-object p0

    .line 562
    :pswitch_15
    check-cast p0, Lx61/a;

    .line 563
    .line 564
    check-cast v4, Ll2/t2;

    .line 565
    .line 566
    invoke-static {p0, v4}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->c(Lx61/a;Ll2/t2;)Llx0/b0;

    .line 567
    .line 568
    .line 569
    move-result-object p0

    .line 570
    return-object p0

    .line 571
    :pswitch_16
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 572
    .line 573
    check-cast v4, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;

    .line 574
    .line 575
    invoke-static {p0, v4}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->g(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 576
    .line 577
    .line 578
    move-result-object p0

    .line 579
    return-object p0

    .line 580
    :pswitch_17
    check-cast p0, [B

    .line 581
    .line 582
    check-cast v4, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;

    .line 583
    .line 584
    invoke-static {p0, v4}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->i([BLtechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 585
    .line 586
    .line 587
    move-result-object p0

    .line 588
    return-object p0

    .line 589
    :pswitch_18
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 590
    .line 591
    check-cast v4, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;

    .line 592
    .line 593
    invoke-static {p0, v4}, Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;->f(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;Ltechnology/cariad/cat/genx/services/ble/BLEMessageHandler;)Ljava/lang/String;

    .line 594
    .line 595
    .line 596
    move-result-object p0

    .line 597
    return-object p0

    .line 598
    :pswitch_19
    check-cast p0, Ll2/h0;

    .line 599
    .line 600
    check-cast v4, Lp1/v;

    .line 601
    .line 602
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    move-result-object p0

    .line 606
    check-cast p0, Lp1/l;

    .line 607
    .line 608
    new-instance v0, Lbb/g0;

    .line 609
    .line 610
    iget-object v1, v4, Lp1/v;->d:Lh8/o;

    .line 611
    .line 612
    iget-object v1, v1, Lh8/o;->f:Ljava/lang/Object;

    .line 613
    .line 614
    check-cast v1, Lo1/g0;

    .line 615
    .line 616
    invoke-virtual {v1}, Lo1/g0;->getValue()Ljava/lang/Object;

    .line 617
    .line 618
    .line 619
    move-result-object v1

    .line 620
    check-cast v1, Lgy0/j;

    .line 621
    .line 622
    invoke-direct {v0, v1, p0}, Lbb/g0;-><init>(Lgy0/j;Lo1/y;)V

    .line 623
    .line 624
    .line 625
    new-instance v1, Lp1/m;

    .line 626
    .line 627
    invoke-direct {v1, v4, p0, v0}, Lp1/m;-><init>(Lp1/v;Lp1/l;Lbb/g0;)V

    .line 628
    .line 629
    .line 630
    return-object v1

    .line 631
    :pswitch_1a
    check-cast p0, Ljava/util/ArrayList;

    .line 632
    .line 633
    check-cast v4, Low0/f0;

    .line 634
    .line 635
    iget-object v0, v4, Low0/f0;->h:Ljava/lang/String;

    .line 636
    .line 637
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 638
    .line 639
    .line 640
    move-result p0

    .line 641
    if-eqz p0, :cond_b

    .line 642
    .line 643
    goto :goto_5

    .line 644
    :cond_b
    iget-object p0, v4, Low0/f0;->j:Low0/b0;

    .line 645
    .line 646
    iget-object p0, p0, Low0/b0;->d:Ljava/lang/String;

    .line 647
    .line 648
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 649
    .line 650
    .line 651
    move-result p0

    .line 652
    add-int/lit8 p0, p0, 0x3

    .line 653
    .line 654
    const/16 v3, 0x2f

    .line 655
    .line 656
    invoke-static {v0, v3, p0, v1}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 657
    .line 658
    .line 659
    move-result p0

    .line 660
    const/4 v1, -0x1

    .line 661
    if-ne p0, v1, :cond_c

    .line 662
    .line 663
    :goto_5
    const-string p0, ""

    .line 664
    .line 665
    goto :goto_6

    .line 666
    :cond_c
    const/4 v3, 0x2

    .line 667
    new-array v3, v3, [C

    .line 668
    .line 669
    fill-array-data v3, :array_0

    .line 670
    .line 671
    .line 672
    invoke-static {v0, v3, p0, v2}, Lly0/p;->L(Ljava/lang/CharSequence;[CIZ)I

    .line 673
    .line 674
    .line 675
    move-result v2

    .line 676
    const-string v3, "substring(...)"

    .line 677
    .line 678
    if-ne v2, v1, :cond_d

    .line 679
    .line 680
    invoke-virtual {v0, p0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 681
    .line 682
    .line 683
    move-result-object p0

    .line 684
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 685
    .line 686
    .line 687
    goto :goto_6

    .line 688
    :cond_d
    invoke-virtual {v0, p0, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 689
    .line 690
    .line 691
    move-result-object p0

    .line 692
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 693
    .line 694
    .line 695
    :goto_6
    return-object p0

    .line 696
    :pswitch_1b
    check-cast p0, Landroid/app/Activity;

    .line 697
    .line 698
    check-cast v4, Lnt0/k;

    .line 699
    .line 700
    if-eqz p0, :cond_e

    .line 701
    .line 702
    invoke-virtual {p0, v1}, Landroid/app/Activity;->setRequestedOrientation(I)V

    .line 703
    .line 704
    .line 705
    :cond_e
    iget-object p0, v4, Lnt0/k;->i:Ltr0/b;

    .line 706
    .line 707
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    return-object v3

    .line 711
    :pswitch_1c
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 712
    .line 713
    check-cast v4, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;

    .line 714
    .line 715
    invoke-static {p0, v4}, Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;->k(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/services/bl3/BL3MessageHandler;)Ljava/lang/String;

    .line 716
    .line 717
    .line 718
    move-result-object p0

    .line 719
    return-object p0

    .line 720
    nop

    .line 721
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

    .line 722
    .line 723
    .line 724
    .line 725
    .line 726
    .line 727
    .line 728
    .line 729
    .line 730
    .line 731
    .line 732
    .line 733
    .line 734
    .line 735
    .line 736
    .line 737
    .line 738
    .line 739
    .line 740
    .line 741
    .line 742
    .line 743
    .line 744
    .line 745
    .line 746
    .line 747
    .line 748
    .line 749
    .line 750
    .line 751
    .line 752
    .line 753
    .line 754
    .line 755
    .line 756
    .line 757
    .line 758
    .line 759
    .line 760
    .line 761
    .line 762
    .line 763
    .line 764
    .line 765
    .line 766
    .line 767
    .line 768
    .line 769
    .line 770
    .line 771
    .line 772
    .line 773
    .line 774
    .line 775
    .line 776
    .line 777
    .line 778
    .line 779
    .line 780
    .line 781
    .line 782
    .line 783
    :array_0
    .array-data 2
        0x3fs
        0x23s
    .end array-data
.end method
