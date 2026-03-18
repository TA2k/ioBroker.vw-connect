.class public final synthetic Lh50/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh50/q0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh50/q0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lh50/q0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lh50/q0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lij0/a;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    new-array v0, v0, [Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ljj0/f;

    .line 14
    .line 15
    const v1, 0x7f1201aa

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p0, Llz0/o;

    .line 24
    .line 25
    new-instance v0, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v1, "Unexpected end of input: yet to parse \'"

    .line 28
    .line 29
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Llz0/o;->a:Ljava/lang/String;

    .line 33
    .line 34
    const/16 v1, 0x27

    .line 35
    .line 36
    invoke-static {v0, p0, v1}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :pswitch_1
    check-cast p0, Llz0/g;

    .line 42
    .line 43
    new-instance v0, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v1, "Unexpected end of input: yet to parse "

    .line 46
    .line 47
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Llz0/g;->b()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_2
    check-cast p0, Lvg0/c;

    .line 63
    .line 64
    new-instance v0, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v1, "Destination "

    .line 67
    .line 68
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string p0, " cant be casted as Route"

    .line 75
    .line 76
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :pswitch_3
    check-cast p0, Lln/a;

    .line 85
    .line 86
    new-instance v0, Lcb/c;

    .line 87
    .line 88
    const/4 v1, 0x1

    .line 89
    invoke-direct {v0, p0, v1}, Lcb/c;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    return-object v0

    .line 93
    :pswitch_4
    check-cast p0, Llk0/i;

    .line 94
    .line 95
    iget-object p0, p0, Llk0/i;->a:Llk0/h;

    .line 96
    .line 97
    check-cast p0, Ljk0/a;

    .line 98
    .line 99
    iget-object p0, p0, Ljk0/a;->a:Lwe0/a;

    .line 100
    .line 101
    check-cast p0, Lwe0/c;

    .line 102
    .line 103
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :pswitch_5
    check-cast p0, Ljava/util/concurrent/Callable;

    .line 113
    .line 114
    invoke-interface {p0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_6
    check-cast p0, Ll2/y1;

    .line 120
    .line 121
    iget-object v1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 122
    .line 123
    monitor-enter v1

    .line 124
    :try_start_0
    invoke-virtual {p0}, Ll2/y1;->w()Lvy0/k;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    iget-object v2, p0, Ll2/y1;->u:Lyy0/c2;

    .line 129
    .line 130
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    check-cast v2, Ll2/w1;

    .line 135
    .line 136
    sget-object v3, Ll2/w1;->e:Ll2/w1;

    .line 137
    .line 138
    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 139
    .line 140
    .line 141
    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 142
    if-lez v2, :cond_1

    .line 143
    .line 144
    monitor-exit v1

    .line 145
    if-eqz v0, :cond_0

    .line 146
    .line 147
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    check-cast v0, Lvy0/l;

    .line 150
    .line 151
    invoke-virtual {v0, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 155
    .line 156
    return-object p0

    .line 157
    :cond_1
    :try_start_1
    const-string v0, "Recomposer shutdown; frame clock awaiter will never resume"

    .line 158
    .line 159
    iget-object p0, p0, Ll2/y1;->e:Ljava/lang/Throwable;

    .line 160
    .line 161
    invoke-static {v0, p0}, Lvy0/e0;->a(Ljava/lang/String;Ljava/lang/Throwable;)Ljava/util/concurrent/CancellationException;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 166
    :catchall_0
    move-exception v0

    .line 167
    move-object p0, v0

    .line 168
    monitor-exit v1

    .line 169
    throw p0

    .line 170
    :pswitch_7
    check-cast p0, Lky/u;

    .line 171
    .line 172
    iget-object p0, p0, Lky/u;->a:Ljava/lang/String;

    .line 173
    .line 174
    invoke-static {p0}, Lcz/skodaauto/myskoda/library/deeplink/model/Link;->toString-impl(Ljava/lang/String;)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    const-string v0, " is not valid"

    .line 179
    .line 180
    invoke-static {p0, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    return-object p0

    .line 185
    :pswitch_8
    check-cast p0, Lkj0/j;

    .line 186
    .line 187
    invoke-interface {p0}, Lkj0/j;->getName()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    invoke-interface {p0}, Lkj0/j;->getValue()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    const-string v1, "name="

    .line 196
    .line 197
    const-string v2, ", value="

    .line 198
    .line 199
    invoke-static {v1, v0, v2, p0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    return-object p0

    .line 204
    :pswitch_9
    check-cast p0, Lka0/c;

    .line 205
    .line 206
    iget-object p0, p0, Lka0/c;->a:Lka0/b;

    .line 207
    .line 208
    check-cast p0, Lia0/a;

    .line 209
    .line 210
    iget-object p0, p0, Lia0/a;->a:Lwe0/a;

    .line 211
    .line 212
    check-cast p0, Lwe0/c;

    .line 213
    .line 214
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 215
    .line 216
    .line 217
    move-result p0

    .line 218
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    return-object p0

    .line 223
    :pswitch_a
    check-cast p0, Lk01/p;

    .line 224
    .line 225
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 226
    .line 227
    .line 228
    :try_start_2
    iget-object v0, p0, Lk01/p;->z:Lk01/y;

    .line 229
    .line 230
    const/4 v1, 0x0

    .line 231
    const/4 v2, 0x2

    .line 232
    invoke-virtual {v0, v2, v1, v1}, Lk01/y;->h(IIZ)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 233
    .line 234
    .line 235
    goto :goto_0

    .line 236
    :catch_0
    move-exception v0

    .line 237
    sget-object v1, Lk01/b;->g:Lk01/b;

    .line 238
    .line 239
    invoke-virtual {p0, v1, v1, v0}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V

    .line 240
    .line 241
    .line 242
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    return-object p0

    .line 245
    :pswitch_b
    check-cast p0, Llj0/a;

    .line 246
    .line 247
    return-object p0

    .line 248
    :pswitch_c
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 249
    .line 250
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->d(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    return-object p0

    .line 255
    :pswitch_d
    check-cast p0, Ljava/lang/Boolean;

    .line 256
    .line 257
    new-instance v0, Ljava/lang/StringBuilder;

    .line 258
    .line 259
    const-string v1, "isSupportedByDevice="

    .line 260
    .line 261
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object p0

    .line 271
    return-object p0

    .line 272
    :pswitch_e
    check-cast p0, Li2/l0;

    .line 273
    .line 274
    invoke-interface {p0}, Li2/l0;->invoke()F

    .line 275
    .line 276
    .line 277
    move-result p0

    .line 278
    const/high16 v0, 0x3f800000    # 1.0f

    .line 279
    .line 280
    cmpl-float p0, p0, v0

    .line 281
    .line 282
    if-ltz p0, :cond_2

    .line 283
    .line 284
    goto :goto_1

    .line 285
    :cond_2
    const v0, 0x3e99999a    # 0.3f

    .line 286
    .line 287
    .line 288
    :goto_1
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    return-object p0

    .line 293
    :pswitch_f
    check-cast p0, Lt7/a1;

    .line 294
    .line 295
    iget v0, p0, Lt7/a1;->a:I

    .line 296
    .line 297
    iget p0, p0, Lt7/a1;->b:I

    .line 298
    .line 299
    const-string v1, "VideoPlayer: Resize: "

    .line 300
    .line 301
    const-string v2, "x"

    .line 302
    .line 303
    invoke-static {v1, v2, v0, p0}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object p0

    .line 307
    return-object p0

    .line 308
    :pswitch_10
    check-cast p0, Lyl/r;

    .line 309
    .line 310
    iget-object p0, p0, Lyl/r;->a:Lyl/o;

    .line 311
    .line 312
    iget-object p0, p0, Lyl/o;->e:Llx0/i;

    .line 313
    .line 314
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object p0

    .line 318
    check-cast p0, Lcm/g;

    .line 319
    .line 320
    return-object p0

    .line 321
    :pswitch_11
    check-cast p0, Lcz/myskoda/api/bff/v1/FuelPriceDto;

    .line 322
    .line 323
    new-instance v0, Lne0/c;

    .line 324
    .line 325
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 326
    .line 327
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelPriceDto;->getFuelType()Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object p0

    .line 331
    const-string v2, "Unknown fuel type: "

    .line 332
    .line 333
    invoke-static {v2, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object p0

    .line 337
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    const/4 v4, 0x0

    .line 341
    const/16 v5, 0x1e

    .line 342
    .line 343
    const/4 v2, 0x0

    .line 344
    const/4 v3, 0x0

    .line 345
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 346
    .line 347
    .line 348
    return-object v0

    .line 349
    :pswitch_12
    check-cast p0, Ltechnology/cariad/cat/genx/GenXError;

    .line 350
    .line 351
    new-instance v0, Ljava/lang/StringBuilder;

    .line 352
    .line 353
    const-string v1, "observeBleTransportStatusAndErrors(): vehicleErrors = "

    .line 354
    .line 355
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 359
    .line 360
    .line 361
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    move-result-object p0

    .line 365
    return-object p0

    .line 366
    :pswitch_13
    check-cast p0, Lg61/h;

    .line 367
    .line 368
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->f(Lg61/h;)Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object p0

    .line 372
    return-object p0

    .line 373
    :pswitch_14
    check-cast p0, Lh40/m3;

    .line 374
    .line 375
    iget-object p0, p0, Lh40/m3;->e:Ljava/util/List;

    .line 376
    .line 377
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 378
    .line 379
    .line 380
    move-result p0

    .line 381
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 382
    .line 383
    .line 384
    move-result-object p0

    .line 385
    return-object p0

    .line 386
    :pswitch_15
    check-cast p0, Li30/e;

    .line 387
    .line 388
    iget-object p0, p0, Li30/e;->a:Li30/d;

    .line 389
    .line 390
    check-cast p0, Lg30/a;

    .line 391
    .line 392
    iget-object p0, p0, Lg30/a;->a:Lwe0/a;

    .line 393
    .line 394
    check-cast p0, Lwe0/c;

    .line 395
    .line 396
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 397
    .line 398
    .line 399
    move-result p0

    .line 400
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 401
    .line 402
    .line 403
    move-result-object p0

    .line 404
    return-object p0

    .line 405
    :pswitch_16
    check-cast p0, Lhu/b1;

    .line 406
    .line 407
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 408
    .line 409
    .line 410
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 411
    .line 412
    .line 413
    move-result-object p0

    .line 414
    const-string v0, "randomUUID(...)"

    .line 415
    .line 416
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {p0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object p0

    .line 423
    const-string v0, "toString(...)"

    .line 424
    .line 425
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 426
    .line 427
    .line 428
    return-object p0

    .line 429
    :pswitch_17
    check-cast p0, Lkr0/b;

    .line 430
    .line 431
    new-instance v0, Ljava/lang/StringBuilder;

    .line 432
    .line 433
    const-string v1, "OpenTelemetry log event "

    .line 434
    .line 435
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 436
    .line 437
    .line 438
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 439
    .line 440
    .line 441
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 442
    .line 443
    .line 444
    move-result-object p0

    .line 445
    return-object p0

    .line 446
    :pswitch_18
    check-cast p0, Lyy0/q1;

    .line 447
    .line 448
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 449
    .line 450
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 451
    .line 452
    .line 453
    return-object v0

    .line 454
    :pswitch_19
    check-cast p0, Lhi0/a;

    .line 455
    .line 456
    new-instance v0, Lcx/b;

    .line 457
    .line 458
    new-instance v1, Lgr/k;

    .line 459
    .line 460
    const/4 v2, 0x4

    .line 461
    invoke-direct {v1, p0, v2}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 462
    .line 463
    .line 464
    invoke-direct {v0, v1}, Lcx/b;-><init>(Lgr/k;)V

    .line 465
    .line 466
    .line 467
    return-object v0

    .line 468
    :pswitch_1a
    check-cast p0, Landroid/content/IntentSender$SendIntentException;

    .line 469
    .line 470
    invoke-virtual {p0}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 471
    .line 472
    .line 473
    move-result-object p0

    .line 474
    const-string v0, "Can\'t show location settings dialog because "

    .line 475
    .line 476
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object p0

    .line 480
    return-object p0

    .line 481
    :pswitch_1b
    check-cast p0, Lg80/a;

    .line 482
    .line 483
    new-instance v0, Ldr0/a;

    .line 484
    .line 485
    iget-object p0, p0, Lg80/a;->b:Ljava/lang/String;

    .line 486
    .line 487
    invoke-direct {v0, p0}, Ldr0/a;-><init>(Ljava/lang/String;)V

    .line 488
    .line 489
    .line 490
    return-object v0

    .line 491
    :pswitch_1c
    check-cast p0, Lh50/s0;

    .line 492
    .line 493
    new-instance v0, Llj0/a;

    .line 494
    .line 495
    iget-object p0, p0, Lh50/s0;->t:Lij0/a;

    .line 496
    .line 497
    const v1, 0x7f12038c

    .line 498
    .line 499
    .line 500
    check-cast p0, Ljj0/f;

    .line 501
    .line 502
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    return-object v0

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
