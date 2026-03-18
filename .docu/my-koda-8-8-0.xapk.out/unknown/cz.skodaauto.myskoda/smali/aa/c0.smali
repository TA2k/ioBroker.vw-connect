.class public final synthetic Laa/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Laa/c0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Laa/c0;->e:Lay0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Laa/c0;->d:I

    .line 2
    .line 3
    const-wide v1, 0xffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    const/16 v3, 0x20

    .line 9
    .line 10
    const-string v4, "it"

    .line 11
    .line 12
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    iget-object p0, p0, Laa/c0;->e:Lay0/k;

    .line 15
    .line 16
    packed-switch v0, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    check-cast p1, Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    return-object v5

    .line 28
    :pswitch_0
    check-cast p1, Lh2/sa;

    .line 29
    .line 30
    new-instance v0, Lh2/ra;

    .line 31
    .line 32
    invoke-direct {v0, p1, p0}, Lh2/ra;-><init>(Lh2/sa;Lay0/k;)V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_1
    check-cast p1, Lh2/r9;

    .line 37
    .line 38
    iget-wide v0, p1, Lh2/r9;->a:J

    .line 39
    .line 40
    invoke-static {v0, v1}, Lh2/r9;->b(J)F

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget-wide v1, p1, Lh2/r9;->a:J

    .line 45
    .line 46
    invoke-static {v1, v2}, Lh2/r9;->a(J)F

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    new-instance v1, Lgy0/e;

    .line 51
    .line 52
    invoke-direct {v1, v0, p1}, Lgy0/e;-><init>(FF)V

    .line 53
    .line 54
    .line 55
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    return-object v5

    .line 59
    :pswitch_2
    check-cast p1, Ljava/lang/String;

    .line 60
    .line 61
    const-string v0, "input"

    .line 62
    .line 63
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    new-instance v0, Lt31/c;

    .line 67
    .line 68
    new-instance v1, Ll4/v;

    .line 69
    .line 70
    const-wide/16 v2, 0x0

    .line 71
    .line 72
    const/4 v4, 0x6

    .line 73
    invoke-direct {v1, v2, v3, p1, v4}, Ll4/v;-><init>(JLjava/lang/String;I)V

    .line 74
    .line 75
    .line 76
    invoke-direct {v0, v1}, Lt31/c;-><init>(Ll4/v;)V

    .line 77
    .line 78
    .line 79
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    return-object v5

    .line 83
    :pswitch_3
    check-cast p1, Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    sget-object p1, Lic/h;->a:Lic/h;

    .line 89
    .line 90
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    return-object v5

    .line 94
    :pswitch_4
    check-cast p1, Ld3/b;

    .line 95
    .line 96
    iget-wide v6, p1, Ld3/b;->a:J

    .line 97
    .line 98
    invoke-static {v6, v7}, Ld3/b;->e(J)F

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    invoke-static {v6, v7}, Ld3/b;->f(J)F

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    invoke-static {p1}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 107
    .line 108
    .line 109
    move-result p1

    .line 110
    int-to-long v6, p1

    .line 111
    invoke-static {v0}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    int-to-long v8, p1

    .line 116
    shl-long v3, v6, v3

    .line 117
    .line 118
    and-long v0, v8, v1

    .line 119
    .line 120
    or-long/2addr v0, v3

    .line 121
    new-instance p1, Lpw/g;

    .line 122
    .line 123
    invoke-direct {p1, v0, v1}, Lpw/g;-><init>(J)V

    .line 124
    .line 125
    .line 126
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    return-object v5

    .line 130
    :pswitch_5
    check-cast p1, Ld3/b;

    .line 131
    .line 132
    iget-wide v6, p1, Ld3/b;->a:J

    .line 133
    .line 134
    invoke-static {v6, v7}, Ld3/b;->e(J)F

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    invoke-static {v6, v7}, Ld3/b;->f(J)F

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    invoke-static {p1}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    int-to-long v6, p1

    .line 147
    invoke-static {v0}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    int-to-long v8, p1

    .line 152
    shl-long v3, v6, v3

    .line 153
    .line 154
    and-long v0, v8, v1

    .line 155
    .line 156
    or-long/2addr v0, v3

    .line 157
    new-instance p1, Lpw/g;

    .line 158
    .line 159
    invoke-direct {p1, v0, v1}, Lpw/g;-><init>(J)V

    .line 160
    .line 161
    .line 162
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    return-object v5

    .line 166
    :pswitch_6
    check-cast p1, Ljava/lang/String;

    .line 167
    .line 168
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    new-instance v0, Lac/o;

    .line 172
    .line 173
    invoke-direct {v0, p1}, Lac/o;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    return-object v5

    .line 180
    :pswitch_7
    check-cast p1, Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    new-instance v0, Lac/t;

    .line 186
    .line 187
    invoke-direct {v0, p1}, Lac/t;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    return-object v5

    .line 194
    :pswitch_8
    check-cast p1, Ljava/lang/String;

    .line 195
    .line 196
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    new-instance v0, Lac/v;

    .line 200
    .line 201
    invoke-direct {v0, p1}, Lac/v;-><init>(Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    return-object v5

    .line 208
    :pswitch_9
    check-cast p1, Ljava/lang/String;

    .line 209
    .line 210
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    new-instance v0, Lac/u;

    .line 214
    .line 215
    invoke-direct {v0, p1}, Lac/u;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    return-object v5

    .line 222
    :pswitch_a
    check-cast p1, Ljava/lang/String;

    .line 223
    .line 224
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    new-instance v0, Lac/m;

    .line 228
    .line 229
    invoke-direct {v0, p1}, Lac/m;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    return-object v5

    .line 236
    :pswitch_b
    check-cast p1, Ljava/lang/String;

    .line 237
    .line 238
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    new-instance v0, Lac/s;

    .line 242
    .line 243
    invoke-direct {v0, p1}, Lac/s;-><init>(Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    return-object v5

    .line 250
    :pswitch_c
    check-cast p1, Ljava/lang/String;

    .line 251
    .line 252
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    new-instance v0, Lac/n;

    .line 256
    .line 257
    invoke-direct {v0, p1}, Lac/n;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    return-object v5

    .line 264
    :pswitch_d
    check-cast p1, Ljava/lang/String;

    .line 265
    .line 266
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    new-instance v0, Lac/r;

    .line 270
    .line 271
    invoke-direct {v0, p1}, Lac/r;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    return-object v5

    .line 278
    :pswitch_e
    check-cast p1, Ljava/lang/String;

    .line 279
    .line 280
    const-string v0, "newText"

    .line 281
    .line 282
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    new-instance v0, Lr31/b;

    .line 286
    .line 287
    invoke-direct {v0, p1}, Lr31/b;-><init>(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    return-object v5

    .line 294
    :pswitch_f
    check-cast p1, Ljava/util/List;

    .line 295
    .line 296
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    new-instance v0, Lrh/o;

    .line 300
    .line 301
    invoke-direct {v0, p1}, Lrh/o;-><init>(Ljava/util/List;)V

    .line 302
    .line 303
    .line 304
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    return-object v5

    .line 308
    :pswitch_10
    check-cast p1, Ljava/lang/String;

    .line 309
    .line 310
    const-string v0, "newValue"

    .line 311
    .line 312
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 316
    .line 317
    .line 318
    move-result v0

    .line 319
    const/16 v1, 0x24

    .line 320
    .line 321
    if-gt v0, v1, :cond_0

    .line 322
    .line 323
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    :cond_0
    return-object v5

    .line 327
    :pswitch_11
    check-cast p1, Lp31/g;

    .line 328
    .line 329
    const-string v0, "time"

    .line 330
    .line 331
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 332
    .line 333
    .line 334
    new-instance v0, Lq31/e;

    .line 335
    .line 336
    invoke-direct {v0, p1}, Lq31/e;-><init>(Lp31/g;)V

    .line 337
    .line 338
    .line 339
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    return-object v5

    .line 343
    :pswitch_12
    check-cast p1, Ljava/lang/Long;

    .line 344
    .line 345
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 346
    .line 347
    .line 348
    move-result-wide v0

    .line 349
    new-instance p1, Lq31/b;

    .line 350
    .line 351
    invoke-direct {p1, v0, v1}, Lq31/b;-><init>(J)V

    .line 352
    .line 353
    .line 354
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    return-object v5

    .line 358
    :pswitch_13
    check-cast p1, Ljava/lang/Boolean;

    .line 359
    .line 360
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 361
    .line 362
    .line 363
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    return-object v5

    .line 367
    :pswitch_14
    check-cast p1, Ljava/lang/Long;

    .line 368
    .line 369
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 370
    .line 371
    .line 372
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    return-object p0

    .line 377
    :pswitch_15
    check-cast p1, Ljava/lang/String;

    .line 378
    .line 379
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    new-instance v0, Lnh/l;

    .line 383
    .line 384
    invoke-direct {v0, p1}, Lnh/l;-><init>(Ljava/lang/String;)V

    .line 385
    .line 386
    .line 387
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    return-object v5

    .line 391
    :pswitch_16
    check-cast p1, Ljava/lang/String;

    .line 392
    .line 393
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    new-instance v0, Llh/d;

    .line 397
    .line 398
    invoke-direct {v0, p1}, Llh/d;-><init>(Ljava/lang/String;)V

    .line 399
    .line 400
    .line 401
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    return-object v5

    .line 405
    :pswitch_17
    check-cast p1, Ljava/lang/String;

    .line 406
    .line 407
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    new-instance v0, Lph/c;

    .line 411
    .line 412
    invoke-direct {v0, p1}, Lph/c;-><init>(Ljava/lang/String;)V

    .line 413
    .line 414
    .line 415
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    return-object v5

    .line 419
    :pswitch_18
    check-cast p1, Ljava/lang/Boolean;

    .line 420
    .line 421
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 422
    .line 423
    .line 424
    sget-object p1, Lph/b;->a:Lph/b;

    .line 425
    .line 426
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    return-object v5

    .line 430
    :pswitch_19
    check-cast p1, Ljava/lang/Boolean;

    .line 431
    .line 432
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 433
    .line 434
    .line 435
    move-result p1

    .line 436
    new-instance v0, Lfh/c;

    .line 437
    .line 438
    invoke-direct {v0, p1}, Lfh/c;-><init>(Z)V

    .line 439
    .line 440
    .line 441
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    return-object v5

    .line 445
    :pswitch_1a
    check-cast p1, Ljava/lang/String;

    .line 446
    .line 447
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    return-object v5

    .line 454
    :pswitch_1b
    check-cast p1, Ljava/lang/String;

    .line 455
    .line 456
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    return-object v5

    .line 463
    :pswitch_1c
    check-cast p1, Lb1/t;

    .line 464
    .line 465
    invoke-virtual {p1}, Lb1/t;->a()Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    move-result-object v0

    .line 469
    check-cast v0, Lz9/k;

    .line 470
    .line 471
    iget-object v0, v0, Lz9/k;->e:Lz9/u;

    .line 472
    .line 473
    const-string v1, "null cannot be cast to non-null type androidx.navigation.compose.ComposeNavigator.Destination"

    .line 474
    .line 475
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 476
    .line 477
    .line 478
    check-cast v0, Laa/h;

    .line 479
    .line 480
    sget v1, Lz9/u;->h:I

    .line 481
    .line 482
    invoke-static {v0}, Ljp/q0;->d(Lz9/u;)Lky0/j;

    .line 483
    .line 484
    .line 485
    move-result-object v0

    .line 486
    invoke-interface {v0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 491
    .line 492
    .line 493
    move-result v1

    .line 494
    if-eqz v1, :cond_1

    .line 495
    .line 496
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v1

    .line 500
    check-cast v1, Lz9/u;

    .line 501
    .line 502
    goto :goto_0

    .line 503
    :cond_1
    if-eqz p0, :cond_2

    .line 504
    .line 505
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object p0

    .line 509
    check-cast p0, Lb1/f1;

    .line 510
    .line 511
    goto :goto_1

    .line 512
    :cond_2
    const/4 p0, 0x0

    .line 513
    :goto_1
    return-object p0

    .line 514
    nop

    .line 515
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
