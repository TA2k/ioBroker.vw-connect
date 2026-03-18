.class public final synthetic Laj0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Laj0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laj0/c;->e:Lay0/a;

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
    .locals 3

    .line 1
    iget v0, p0, Laj0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld4/l;

    .line 7
    .line 8
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 9
    .line 10
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    move-object v0, p0

    .line 15
    check-cast v0, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    :goto_0
    check-cast p0, Ljava/lang/Float;

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    if-eqz p0, :cond_1

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move p0, v0

    .line 40
    :goto_1
    new-instance v1, Lgy0/e;

    .line 41
    .line 42
    const/high16 v2, 0x3f800000    # 1.0f

    .line 43
    .line 44
    invoke-direct {v1, v0, v2}, Lgy0/e;-><init>(FF)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Ld4/h;

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    invoke-direct {v0, p0, v1, v2}, Ld4/h;-><init>(FLgy0/e;I)V

    .line 51
    .line 52
    .line 53
    invoke-static {p1, v0}, Ld4/x;->h(Ld4/l;Ld4/h;)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_0
    check-cast p1, Ld4/l;

    .line 60
    .line 61
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 62
    .line 63
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    move-object v0, p0

    .line 68
    check-cast v0, Ljava/lang/Number;

    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-nez v0, :cond_2

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_2
    const/4 p0, 0x0

    .line 82
    :goto_2
    check-cast p0, Ljava/lang/Float;

    .line 83
    .line 84
    const/4 v0, 0x0

    .line 85
    if-eqz p0, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    goto :goto_3

    .line 92
    :cond_3
    move p0, v0

    .line 93
    :goto_3
    new-instance v1, Lgy0/e;

    .line 94
    .line 95
    const/high16 v2, 0x3f800000    # 1.0f

    .line 96
    .line 97
    invoke-direct {v1, v0, v2}, Lgy0/e;-><init>(FF)V

    .line 98
    .line 99
    .line 100
    new-instance v0, Ld4/h;

    .line 101
    .line 102
    const/4 v2, 0x0

    .line 103
    invoke-direct {v0, p0, v1, v2}, Ld4/h;-><init>(FLgy0/e;I)V

    .line 104
    .line 105
    .line 106
    invoke-static {p1, v0}, Ld4/x;->h(Ld4/l;Ld4/h;)V

    .line 107
    .line 108
    .line 109
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    return-object p0

    .line 112
    :pswitch_1
    check-cast p1, Ld3/b;

    .line 113
    .line 114
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 115
    .line 116
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_2
    check-cast p1, Ljava/lang/Throwable;

    .line 123
    .line 124
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 125
    .line 126
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_3
    check-cast p1, Le3/k0;

    .line 133
    .line 134
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 135
    .line 136
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    check-cast p0, Ljava/lang/Number;

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 147
    .line 148
    .line 149
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_4
    check-cast p1, Lql0/f;

    .line 153
    .line 154
    const-string v0, "it"

    .line 155
    .line 156
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 160
    .line 161
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_5
    check-cast p1, Lp3/t;

    .line 168
    .line 169
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 170
    .line 171
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 175
    .line 176
    return-object p0

    .line 177
    :pswitch_6
    check-cast p1, Lql0/f;

    .line 178
    .line 179
    const-string v0, "it"

    .line 180
    .line 181
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 185
    .line 186
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object p0

    .line 192
    :pswitch_7
    check-cast p1, Lql0/f;

    .line 193
    .line 194
    const-string v0, "it"

    .line 195
    .line 196
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 200
    .line 201
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 205
    .line 206
    return-object p0

    .line 207
    :pswitch_8
    check-cast p1, Lql0/f;

    .line 208
    .line 209
    const-string v0, "it"

    .line 210
    .line 211
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 215
    .line 216
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    return-object p0

    .line 222
    :pswitch_9
    check-cast p1, Lt4/c;

    .line 223
    .line 224
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 225
    .line 226
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    check-cast p0, Ld3/b;

    .line 231
    .line 232
    return-object p0

    .line 233
    :pswitch_a
    check-cast p1, Ljava/lang/Boolean;

    .line 234
    .line 235
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 236
    .line 237
    .line 238
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 239
    .line 240
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 244
    .line 245
    return-object p0

    .line 246
    :pswitch_b
    check-cast p1, Lql0/f;

    .line 247
    .line 248
    const-string v0, "it"

    .line 249
    .line 250
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 254
    .line 255
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 259
    .line 260
    return-object p0

    .line 261
    :pswitch_c
    check-cast p1, Lql0/f;

    .line 262
    .line 263
    const-string v0, "it"

    .line 264
    .line 265
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 269
    .line 270
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 274
    .line 275
    return-object p0

    .line 276
    :pswitch_d
    check-cast p1, Lql0/f;

    .line 277
    .line 278
    const-string v0, "it"

    .line 279
    .line 280
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 284
    .line 285
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 289
    .line 290
    return-object p0

    .line 291
    :pswitch_e
    check-cast p1, Lql0/f;

    .line 292
    .line 293
    const-string v0, "it"

    .line 294
    .line 295
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 299
    .line 300
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 304
    .line 305
    return-object p0

    .line 306
    :pswitch_f
    check-cast p1, Ljava/lang/Boolean;

    .line 307
    .line 308
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 309
    .line 310
    .line 311
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 312
    .line 313
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 317
    .line 318
    return-object p0

    .line 319
    :pswitch_10
    check-cast p1, Lql0/f;

    .line 320
    .line 321
    const-string v0, "it"

    .line 322
    .line 323
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 327
    .line 328
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 332
    .line 333
    return-object p0

    .line 334
    :pswitch_11
    check-cast p1, Ljava/lang/Boolean;

    .line 335
    .line 336
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 337
    .line 338
    .line 339
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 340
    .line 341
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 345
    .line 346
    return-object p0

    .line 347
    :pswitch_12
    check-cast p1, Ljava/lang/Boolean;

    .line 348
    .line 349
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 350
    .line 351
    .line 352
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 353
    .line 354
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 358
    .line 359
    return-object p0

    .line 360
    :pswitch_13
    check-cast p1, Lql0/f;

    .line 361
    .line 362
    const-string v0, "it"

    .line 363
    .line 364
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 368
    .line 369
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 373
    .line 374
    return-object p0

    .line 375
    :pswitch_14
    check-cast p1, Lql0/f;

    .line 376
    .line 377
    const-string v0, "it"

    .line 378
    .line 379
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 383
    .line 384
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 388
    .line 389
    return-object p0

    .line 390
    :pswitch_15
    check-cast p1, Lql0/f;

    .line 391
    .line 392
    const-string v0, "it"

    .line 393
    .line 394
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 398
    .line 399
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 403
    .line 404
    return-object p0

    .line 405
    :pswitch_16
    check-cast p1, Lql0/f;

    .line 406
    .line 407
    const-string v0, "it"

    .line 408
    .line 409
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 410
    .line 411
    .line 412
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 413
    .line 414
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 418
    .line 419
    return-object p0

    .line 420
    :pswitch_17
    check-cast p1, Lql0/f;

    .line 421
    .line 422
    const-string v0, "it"

    .line 423
    .line 424
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 425
    .line 426
    .line 427
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 428
    .line 429
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 433
    .line 434
    return-object p0

    .line 435
    :pswitch_18
    check-cast p1, Lql0/f;

    .line 436
    .line 437
    const-string v0, "it"

    .line 438
    .line 439
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 440
    .line 441
    .line 442
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 443
    .line 444
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 448
    .line 449
    return-object p0

    .line 450
    :pswitch_19
    check-cast p1, Lql0/f;

    .line 451
    .line 452
    const-string v0, "it"

    .line 453
    .line 454
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 455
    .line 456
    .line 457
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 458
    .line 459
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 463
    .line 464
    return-object p0

    .line 465
    :pswitch_1a
    check-cast p1, Lql0/f;

    .line 466
    .line 467
    const-string v0, "it"

    .line 468
    .line 469
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 473
    .line 474
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 475
    .line 476
    .line 477
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 478
    .line 479
    return-object p0

    .line 480
    :pswitch_1b
    check-cast p1, Lql0/f;

    .line 481
    .line 482
    const-string v0, "it"

    .line 483
    .line 484
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 488
    .line 489
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 493
    .line 494
    return-object p0

    .line 495
    :pswitch_1c
    check-cast p1, Lql0/f;

    .line 496
    .line 497
    const-string v0, "it"

    .line 498
    .line 499
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    iget-object p0, p0, Laj0/c;->e:Lay0/a;

    .line 503
    .line 504
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 508
    .line 509
    return-object p0

    .line 510
    nop

    .line 511
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
