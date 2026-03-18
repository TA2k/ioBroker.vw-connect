.class public final synthetic Li40/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Li40/e1;->d:I

    iput-object p1, p0, Li40/e1;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll4/g;Lb81/a;)V
    .locals 0

    .line 2
    const/16 p2, 0x1d

    iput p2, p0, Li40/e1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/e1;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Li40/e1;->d:I

    .line 6
    .line 7
    const/4 v3, 0x3

    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x1

    .line 10
    const/4 v6, 0x0

    .line 11
    iget-object v0, v0, Li40/e1;->e:Ljava/lang/Object;

    .line 12
    .line 13
    packed-switch v2, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    check-cast v0, Ll4/g;

    .line 17
    .line 18
    check-cast v1, Ll4/g;

    .line 19
    .line 20
    if-ne v0, v1, :cond_0

    .line 21
    .line 22
    const-string v0, " > "

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const-string v0, "   "

    .line 26
    .line 27
    :goto_0
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const-string v2, ", newCursorPosition="

    .line 32
    .line 33
    instance-of v3, v1, Ll4/a;

    .line 34
    .line 35
    const/16 v4, 0x29

    .line 36
    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    new-instance v3, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v5, "CommitTextCommand(text.length="

    .line 42
    .line 43
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    check-cast v1, Ll4/a;

    .line 47
    .line 48
    iget-object v5, v1, Ll4/a;->a:Lg4/g;

    .line 49
    .line 50
    iget-object v5, v5, Lg4/g;->e:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget v1, v1, Ll4/a;->b:I

    .line 63
    .line 64
    :goto_1
    invoke-static {v3, v1, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    goto/16 :goto_2

    .line 69
    .line 70
    :cond_1
    instance-of v3, v1, Ll4/t;

    .line 71
    .line 72
    if-eqz v3, :cond_2

    .line 73
    .line 74
    new-instance v3, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v5, "SetComposingTextCommand(text.length="

    .line 77
    .line 78
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    check-cast v1, Ll4/t;

    .line 82
    .line 83
    iget-object v5, v1, Ll4/t;->a:Lg4/g;

    .line 84
    .line 85
    iget-object v5, v5, Lg4/g;->e:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    iget v1, v1, Ll4/t;->b:I

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_2
    instance-of v2, v1, Ll4/s;

    .line 101
    .line 102
    if-eqz v2, :cond_3

    .line 103
    .line 104
    check-cast v1, Ll4/s;

    .line 105
    .line 106
    invoke-virtual {v1}, Ll4/s;->toString()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    goto :goto_2

    .line 111
    :cond_3
    instance-of v2, v1, Ll4/e;

    .line 112
    .line 113
    if-eqz v2, :cond_4

    .line 114
    .line 115
    check-cast v1, Ll4/e;

    .line 116
    .line 117
    invoke-virtual {v1}, Ll4/e;->toString()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    goto :goto_2

    .line 122
    :cond_4
    instance-of v2, v1, Ll4/f;

    .line 123
    .line 124
    if-eqz v2, :cond_5

    .line 125
    .line 126
    check-cast v1, Ll4/f;

    .line 127
    .line 128
    invoke-virtual {v1}, Ll4/f;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    goto :goto_2

    .line 133
    :cond_5
    instance-of v2, v1, Ll4/u;

    .line 134
    .line 135
    if-eqz v2, :cond_6

    .line 136
    .line 137
    check-cast v1, Ll4/u;

    .line 138
    .line 139
    invoke-virtual {v1}, Ll4/u;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    goto :goto_2

    .line 144
    :cond_6
    instance-of v2, v1, Ll4/h;

    .line 145
    .line 146
    if-eqz v2, :cond_7

    .line 147
    .line 148
    const-string v1, "FinishComposingTextCommand()"

    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_7
    instance-of v2, v1, Ll4/d;

    .line 152
    .line 153
    if-eqz v2, :cond_8

    .line 154
    .line 155
    const-string v1, "DeleteAllCommand()"

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_8
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 163
    .line 164
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    invoke-interface {v1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    if-nez v1, :cond_9

    .line 173
    .line 174
    const-string v1, "{anonymous EditCommand}"

    .line 175
    .line 176
    :cond_9
    const-string v2, "Unknown EditCommand: "

    .line 177
    .line 178
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    :goto_2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    return-object v0

    .line 190
    :pswitch_0
    check-cast v0, Landroidx/collection/r0;

    .line 191
    .line 192
    instance-of v2, v1, Lv2/u;

    .line 193
    .line 194
    if-eqz v2, :cond_a

    .line 195
    .line 196
    move-object v2, v1

    .line 197
    check-cast v2, Lv2/u;

    .line 198
    .line 199
    const/4 v3, 0x4

    .line 200
    invoke-virtual {v2, v3}, Lv2/u;->b(I)V

    .line 201
    .line 202
    .line 203
    :cond_a
    invoke-virtual {v0, v1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 207
    .line 208
    return-object v0

    .line 209
    :pswitch_1
    check-cast v0, Ll2/j1;

    .line 210
    .line 211
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 215
    .line 216
    return-object v0

    .line 217
    :pswitch_2
    check-cast v0, Ll2/h1;

    .line 218
    .line 219
    check-cast v1, Ljava/lang/Long;

    .line 220
    .line 221
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 222
    .line 223
    .line 224
    move-result-wide v1

    .line 225
    invoke-virtual {v0, v1, v2}, Ll2/h1;->c(J)V

    .line 226
    .line 227
    .line 228
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    return-object v0

    .line 231
    :pswitch_3
    check-cast v0, Ll2/g1;

    .line 232
    .line 233
    check-cast v1, Ljava/lang/Integer;

    .line 234
    .line 235
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 236
    .line 237
    .line 238
    move-result v1

    .line 239
    invoke-virtual {v0, v1}, Ll2/g1;->p(I)V

    .line 240
    .line 241
    .line 242
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    return-object v0

    .line 245
    :pswitch_4
    check-cast v0, Ll2/f1;

    .line 246
    .line 247
    check-cast v1, Ljava/lang/Float;

    .line 248
    .line 249
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 250
    .line 251
    .line 252
    move-result v1

    .line 253
    invoke-virtual {v0, v1}, Ll2/f1;->p(F)V

    .line 254
    .line 255
    .line 256
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 257
    .line 258
    return-object v0

    .line 259
    :pswitch_5
    check-cast v0, Ll2/y1;

    .line 260
    .line 261
    check-cast v1, Ljava/lang/Throwable;

    .line 262
    .line 263
    const-string v2, "Recomposer effect job completed"

    .line 264
    .line 265
    invoke-static {v2, v1}, Lvy0/e0;->a(Ljava/lang/String;Ljava/lang/Throwable;)Ljava/util/concurrent/CancellationException;

    .line 266
    .line 267
    .line 268
    move-result-object v2

    .line 269
    iget-object v3, v0, Ll2/y1;->c:Ljava/lang/Object;

    .line 270
    .line 271
    monitor-enter v3

    .line 272
    :try_start_0
    iget-object v5, v0, Ll2/y1;->d:Lvy0/i1;

    .line 273
    .line 274
    if-eqz v5, :cond_b

    .line 275
    .line 276
    iget-object v7, v0, Ll2/y1;->u:Lyy0/c2;

    .line 277
    .line 278
    sget-object v8, Ll2/w1;->e:Ll2/w1;

    .line 279
    .line 280
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 281
    .line 282
    .line 283
    invoke-virtual {v7, v4, v8}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    invoke-interface {v5, v2}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 287
    .line 288
    .line 289
    iput-object v4, v0, Ll2/y1;->r:Lvy0/l;

    .line 290
    .line 291
    new-instance v2, Ll2/v1;

    .line 292
    .line 293
    invoke-direct {v2, v6, v0, v1}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    invoke-interface {v5, v2}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 297
    .line 298
    .line 299
    goto :goto_3

    .line 300
    :catchall_0
    move-exception v0

    .line 301
    goto :goto_4

    .line 302
    :cond_b
    iput-object v2, v0, Ll2/y1;->e:Ljava/lang/Throwable;

    .line 303
    .line 304
    iget-object v0, v0, Ll2/y1;->u:Lyy0/c2;

    .line 305
    .line 306
    sget-object v1, Ll2/w1;->d:Ll2/w1;

    .line 307
    .line 308
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 309
    .line 310
    .line 311
    invoke-virtual {v0, v4, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 312
    .line 313
    .line 314
    :goto_3
    monitor-exit v3

    .line 315
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 316
    .line 317
    return-object v0

    .line 318
    :goto_4
    monitor-exit v3

    .line 319
    throw v0

    .line 320
    :pswitch_6
    check-cast v0, Ll2/a0;

    .line 321
    .line 322
    invoke-virtual {v0, v1}, Ll2/a0;->y(Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 326
    .line 327
    return-object v0

    .line 328
    :pswitch_7
    check-cast v0, Lss0/d0;

    .line 329
    .line 330
    check-cast v1, Lss0/x;

    .line 331
    .line 332
    const-string v2, "$this$mapData"

    .line 333
    .line 334
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    invoke-interface {v1}, Lss0/x;->getId()Lss0/d0;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result v0

    .line 345
    if-eqz v0, :cond_c

    .line 346
    .line 347
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 348
    .line 349
    return-object v0

    .line 350
    :cond_c
    const-string v0, "Failed requirement."

    .line 351
    .line 352
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 353
    .line 354
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    throw v1

    .line 358
    :pswitch_8
    check-cast v0, Lkotlin/jvm/internal/l0;

    .line 359
    .line 360
    check-cast v1, Lhy0/d0;

    .line 361
    .line 362
    const-string v2, "it"

    .line 363
    .line 364
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 368
    .line 369
    .line 370
    iget-object v0, v1, Lhy0/d0;->a:Lhy0/e0;

    .line 371
    .line 372
    iget-object v1, v1, Lhy0/d0;->b:Lhy0/a0;

    .line 373
    .line 374
    if-nez v0, :cond_d

    .line 375
    .line 376
    const-string v0, "*"

    .line 377
    .line 378
    goto :goto_7

    .line 379
    :cond_d
    instance-of v2, v1, Lkotlin/jvm/internal/l0;

    .line 380
    .line 381
    if-eqz v2, :cond_e

    .line 382
    .line 383
    move-object v4, v1

    .line 384
    check-cast v4, Lkotlin/jvm/internal/l0;

    .line 385
    .line 386
    :cond_e
    if-eqz v4, :cond_10

    .line 387
    .line 388
    invoke-virtual {v4, v5}, Lkotlin/jvm/internal/l0;->a(Z)Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object v2

    .line 392
    if-nez v2, :cond_f

    .line 393
    .line 394
    goto :goto_5

    .line 395
    :cond_f
    move-object v1, v2

    .line 396
    goto :goto_6

    .line 397
    :cond_10
    :goto_5
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object v1

    .line 401
    :goto_6
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 402
    .line 403
    .line 404
    move-result v0

    .line 405
    if-eqz v0, :cond_13

    .line 406
    .line 407
    if-eq v0, v5, :cond_12

    .line 408
    .line 409
    const/4 v2, 0x2

    .line 410
    if-ne v0, v2, :cond_11

    .line 411
    .line 412
    const-string v0, "out "

    .line 413
    .line 414
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    goto :goto_7

    .line 419
    :cond_11
    new-instance v0, La8/r0;

    .line 420
    .line 421
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 422
    .line 423
    .line 424
    throw v0

    .line 425
    :cond_12
    const-string v0, "in "

    .line 426
    .line 427
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    goto :goto_7

    .line 432
    :cond_13
    move-object v0, v1

    .line 433
    :goto_7
    return-object v0

    .line 434
    :pswitch_9
    check-cast v0, Lss0/e;

    .line 435
    .line 436
    check-cast v1, Lss0/k;

    .line 437
    .line 438
    const-string v2, "$this$mapData"

    .line 439
    .line 440
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 441
    .line 442
    .line 443
    iget-object v1, v1, Lss0/k;->i:Lss0/a0;

    .line 444
    .line 445
    if-eqz v1, :cond_14

    .line 446
    .line 447
    iget-object v1, v1, Lss0/a0;->a:Lss0/b;

    .line 448
    .line 449
    if-eqz v1, :cond_14

    .line 450
    .line 451
    invoke-static {v1, v0}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 452
    .line 453
    .line 454
    move-result-object v0

    .line 455
    if-nez v0, :cond_15

    .line 456
    .line 457
    :cond_14
    sget-object v0, Llf0/i;->i:Llf0/i;

    .line 458
    .line 459
    :cond_15
    return-object v0

    .line 460
    :pswitch_a
    check-cast v0, Lz70/b;

    .line 461
    .line 462
    check-cast v1, Lp31/f;

    .line 463
    .line 464
    const-string v2, "it"

    .line 465
    .line 466
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    iget-object v1, v1, Lp31/f;->a:Li31/e;

    .line 470
    .line 471
    iget-object v1, v1, Li31/e;->e:Li31/f;

    .line 472
    .line 473
    if-eqz v1, :cond_16

    .line 474
    .line 475
    iget-wide v2, v1, Li31/f;->b:D

    .line 476
    .line 477
    iget-object v1, v1, Li31/f;->a:Ljava/lang/String;

    .line 478
    .line 479
    new-instance v4, Ljava/lang/StringBuilder;

    .line 480
    .line 481
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 482
    .line 483
    .line 484
    invoke-virtual {v4, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 485
    .line 486
    .line 487
    const-string v2, " "

    .line 488
    .line 489
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 490
    .line 491
    .line 492
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 493
    .line 494
    .line 495
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 496
    .line 497
    .line 498
    move-result-object v1

    .line 499
    if-nez v1, :cond_17

    .line 500
    .line 501
    :cond_16
    iget-object v0, v0, Lz70/b;->a:Lij0/a;

    .line 502
    .line 503
    new-array v1, v6, [Ljava/lang/Object;

    .line 504
    .line 505
    check-cast v0, Ljj0/f;

    .line 506
    .line 507
    const v2, 0x7f121139

    .line 508
    .line 509
    .line 510
    invoke-virtual {v0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 511
    .line 512
    .line 513
    move-result-object v1

    .line 514
    :cond_17
    return-object v1

    .line 515
    :pswitch_b
    check-cast v0, Lk4/o;

    .line 516
    .line 517
    check-cast v1, Lk4/f0;

    .line 518
    .line 519
    iget-object v4, v1, Lk4/f0;->b:Lk4/x;

    .line 520
    .line 521
    iget v5, v1, Lk4/f0;->c:I

    .line 522
    .line 523
    iget v6, v1, Lk4/f0;->d:I

    .line 524
    .line 525
    iget-object v7, v1, Lk4/f0;->e:Ljava/lang/Object;

    .line 526
    .line 527
    new-instance v2, Lk4/f0;

    .line 528
    .line 529
    const/4 v3, 0x0

    .line 530
    invoke-direct/range {v2 .. v7}, Lk4/f0;-><init>(Lk4/n;Lk4/x;IILjava/lang/Object;)V

    .line 531
    .line 532
    .line 533
    invoke-virtual {v0, v2}, Lk4/o;->a(Lk4/f0;)Lk4/i0;

    .line 534
    .line 535
    .line 536
    move-result-object v0

    .line 537
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 538
    .line 539
    .line 540
    move-result-object v0

    .line 541
    return-object v0

    .line 542
    :pswitch_c
    check-cast v0, Lk31/j0;

    .line 543
    .line 544
    check-cast v1, Li31/j;

    .line 545
    .line 546
    const-string v2, "$this$update"

    .line 547
    .line 548
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 549
    .line 550
    .line 551
    iget-object v2, v0, Lk31/j0;->a:Lz21/c;

    .line 552
    .line 553
    if-nez v2, :cond_18

    .line 554
    .line 555
    iget-object v2, v1, Li31/j;->a:Lz21/c;

    .line 556
    .line 557
    :cond_18
    move-object v4, v2

    .line 558
    iget-object v2, v0, Lk31/j0;->b:Lz21/e;

    .line 559
    .line 560
    if-nez v2, :cond_19

    .line 561
    .line 562
    iget-object v2, v1, Li31/j;->b:Lz21/e;

    .line 563
    .line 564
    :cond_19
    move-object v5, v2

    .line 565
    iget-boolean v6, v0, Lk31/j0;->c:Z

    .line 566
    .line 567
    iget-boolean v7, v0, Lk31/j0;->d:Z

    .line 568
    .line 569
    iget-object v9, v0, Lk31/j0;->e:Ljava/lang/Integer;

    .line 570
    .line 571
    iget-object v8, v1, Li31/j;->e:Li31/g;

    .line 572
    .line 573
    const-string v0, "moduleVersion"

    .line 574
    .line 575
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    const-string v0, "preferredModuleVersions"

    .line 579
    .line 580
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 581
    .line 582
    .line 583
    new-instance v3, Li31/j;

    .line 584
    .line 585
    invoke-direct/range {v3 .. v9}, Li31/j;-><init>(Lz21/c;Lz21/e;ZZLi31/g;Ljava/lang/Integer;)V

    .line 586
    .line 587
    .line 588
    return-object v3

    .line 589
    :pswitch_d
    check-cast v0, Ln2/b;

    .line 590
    .line 591
    check-cast v1, Lt3/d1;

    .line 592
    .line 593
    iget-object v1, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 594
    .line 595
    iget v0, v0, Ln2/b;->f:I

    .line 596
    .line 597
    :goto_8
    if-ge v6, v0, :cond_1a

    .line 598
    .line 599
    aget-object v2, v1, v6

    .line 600
    .line 601
    check-cast v2, Lt3/r0;

    .line 602
    .line 603
    invoke-interface {v2}, Lt3/r0;->c()V

    .line 604
    .line 605
    .line 606
    add-int/lit8 v6, v6, 0x1

    .line 607
    .line 608
    goto :goto_8

    .line 609
    :cond_1a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 610
    .line 611
    return-object v0

    .line 612
    :pswitch_e
    check-cast v0, Ljz0/p;

    .line 613
    .line 614
    iget-object v0, v0, Ljz0/p;->c:Ljava/util/ArrayList;

    .line 615
    .line 616
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 617
    .line 618
    .line 619
    move-result-object v0

    .line 620
    :goto_9
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 621
    .line 622
    .line 623
    move-result v2

    .line 624
    if-eqz v2, :cond_1b

    .line 625
    .line 626
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    move-result-object v2

    .line 630
    check-cast v2, Ljz0/o;

    .line 631
    .line 632
    iget-object v3, v2, Ljz0/o;->a:Ljz0/r;

    .line 633
    .line 634
    iget-object v2, v2, Ljz0/o;->b:Ljava/lang/Object;

    .line 635
    .line 636
    invoke-virtual {v3, v1, v2}, Ljz0/r;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    goto :goto_9

    .line 640
    :cond_1b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 641
    .line 642
    return-object v0

    .line 643
    :pswitch_f
    check-cast v0, Ljh/l;

    .line 644
    .line 645
    check-cast v1, Llx0/o;

    .line 646
    .line 647
    iget-object v2, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 648
    .line 649
    instance-of v3, v2, Llx0/n;

    .line 650
    .line 651
    if-nez v3, :cond_1d

    .line 652
    .line 653
    check-cast v2, Lah/h;

    .line 654
    .line 655
    iput-object v2, v0, Ljh/l;->l:Lah/h;

    .line 656
    .line 657
    iget-object v3, v0, Ljh/l;->i:Lyy0/c2;

    .line 658
    .line 659
    :cond_1c
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 660
    .line 661
    .line 662
    move-result-object v4

    .line 663
    move-object v5, v4

    .line 664
    check-cast v5, Llc/q;

    .line 665
    .line 666
    invoke-static {v2}, Llp/zb;->m(Lah/h;)Ljh/h;

    .line 667
    .line 668
    .line 669
    move-result-object v5

    .line 670
    new-instance v6, Llc/q;

    .line 671
    .line 672
    invoke-direct {v6, v5}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 673
    .line 674
    .line 675
    invoke-virtual {v3, v4, v6}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 676
    .line 677
    .line 678
    move-result v4

    .line 679
    if-eqz v4, :cond_1c

    .line 680
    .line 681
    :cond_1d
    iget-object v1, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 682
    .line 683
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 684
    .line 685
    .line 686
    move-result-object v1

    .line 687
    if-eqz v1, :cond_1e

    .line 688
    .line 689
    iget-object v2, v0, Ljh/l;->k:Llx0/q;

    .line 690
    .line 691
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 692
    .line 693
    .line 694
    move-result-object v2

    .line 695
    check-cast v2, Lzb/k0;

    .line 696
    .line 697
    const-string v3, "DATA_POLLING_TAG"

    .line 698
    .line 699
    invoke-static {v2, v3}, Lzb/k0;->a(Lzb/k0;Ljava/lang/String;)V

    .line 700
    .line 701
    .line 702
    invoke-virtual {v0, v1}, Ljh/l;->d(Ljava/lang/Throwable;)V

    .line 703
    .line 704
    .line 705
    :cond_1e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 706
    .line 707
    return-object v0

    .line 708
    :pswitch_10
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;

    .line 709
    .line 710
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 711
    .line 712
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 713
    .line 714
    .line 715
    move-result-object v0

    .line 716
    return-object v0

    .line 717
    :pswitch_11
    check-cast v0, Lj81/a;

    .line 718
    .line 719
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 720
    .line 721
    const-string v2, "input"

    .line 722
    .line 723
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 724
    .line 725
    .line 726
    instance-of v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 727
    .line 728
    if-eqz v2, :cond_1f

    .line 729
    .line 730
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 731
    .line 732
    invoke-static {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 733
    .line 734
    .line 735
    move-result-object v2

    .line 736
    sget-object v3, Ls71/p;->E:Ls71/p;

    .line 737
    .line 738
    if-ne v2, v3, :cond_1f

    .line 739
    .line 740
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;

    .line 741
    .line 742
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 743
    .line 744
    .line 745
    move-result-object v0

    .line 746
    invoke-direct {v4, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBSubStateMachine$InvalidTouchState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)V

    .line 747
    .line 748
    .line 749
    :cond_1f
    return-object v4

    .line 750
    :pswitch_12
    check-cast v0, Li2/l0;

    .line 751
    .line 752
    check-cast v1, Ld4/l;

    .line 753
    .line 754
    invoke-interface {v0}, Li2/l0;->invoke()F

    .line 755
    .line 756
    .line 757
    move-result v2

    .line 758
    const/4 v3, 0x0

    .line 759
    cmpl-float v2, v2, v3

    .line 760
    .line 761
    if-lez v2, :cond_20

    .line 762
    .line 763
    new-instance v2, Ld4/h;

    .line 764
    .line 765
    invoke-interface {v0}, Li2/l0;->invoke()F

    .line 766
    .line 767
    .line 768
    move-result v0

    .line 769
    new-instance v4, Lgy0/e;

    .line 770
    .line 771
    const/high16 v5, 0x3f800000    # 1.0f

    .line 772
    .line 773
    invoke-direct {v4, v3, v5}, Lgy0/e;-><init>(FF)V

    .line 774
    .line 775
    .line 776
    invoke-direct {v2, v0, v4, v6}, Ld4/h;-><init>(FLgy0/e;I)V

    .line 777
    .line 778
    .line 779
    invoke-static {v1, v2}, Ld4/x;->h(Ld4/l;Ld4/h;)V

    .line 780
    .line 781
    .line 782
    :cond_20
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 783
    .line 784
    return-object v0

    .line 785
    :pswitch_13
    move-object v2, v0

    .line 786
    check-cast v2, Lig/i;

    .line 787
    .line 788
    move-object v3, v1

    .line 789
    check-cast v3, Lsi/e;

    .line 790
    .line 791
    const-string v0, "it"

    .line 792
    .line 793
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 794
    .line 795
    .line 796
    iget-object v5, v2, Lig/i;->i:Lyy0/c2;

    .line 797
    .line 798
    :goto_a
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 799
    .line 800
    .line 801
    move-result-object v0

    .line 802
    move-object v1, v0

    .line 803
    check-cast v1, Lig/f;

    .line 804
    .line 805
    iget-object v7, v2, Lig/i;->g:Lhz/a;

    .line 806
    .line 807
    invoke-virtual {v7}, Lhz/a;->invoke()Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    move-result-object v7

    .line 811
    check-cast v7, Lgz0/p;

    .line 812
    .line 813
    iget-object v8, v2, Lig/i;->h:Lhz/a;

    .line 814
    .line 815
    invoke-virtual {v8}, Lhz/a;->invoke()Ljava/lang/Object;

    .line 816
    .line 817
    .line 818
    move-result-object v8

    .line 819
    check-cast v8, Lgz0/b0;

    .line 820
    .line 821
    const-string v9, ""

    .line 822
    .line 823
    const-string v10, "now"

    .line 824
    .line 825
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    new-instance v10, Lig/a;

    .line 829
    .line 830
    iget-object v11, v3, Lsi/e;->j:Ljava/lang/String;

    .line 831
    .line 832
    if-nez v11, :cond_21

    .line 833
    .line 834
    move-object v8, v9

    .line 835
    goto :goto_b

    .line 836
    :cond_21
    sget-object v12, Lgz0/p;->Companion:Lgz0/o;

    .line 837
    .line 838
    invoke-static {v12, v11}, Lgz0/o;->b(Lgz0/o;Ljava/lang/CharSequence;)Lgz0/p;

    .line 839
    .line 840
    .line 841
    move-result-object v12

    .line 842
    invoke-static {v12, v8}, Lkp/u9;->e(Lgz0/p;Lgz0/b0;)Lgz0/w;

    .line 843
    .line 844
    .line 845
    move-result-object v8

    .line 846
    iget-object v8, v8, Lgz0/w;->d:Ljava/time/LocalDateTime;

    .line 847
    .line 848
    invoke-virtual {v8}, Ljava/time/LocalDateTime;->getHour()I

    .line 849
    .line 850
    .line 851
    move-result v12

    .line 852
    invoke-virtual {v8}, Ljava/time/LocalDateTime;->getMinute()I

    .line 853
    .line 854
    .line 855
    move-result v8

    .line 856
    int-to-long v12, v12

    .line 857
    int-to-long v14, v8

    .line 858
    invoke-static {v12, v13, v14, v15}, Llp/ha;->b(JJ)Ljava/lang/String;

    .line 859
    .line 860
    .line 861
    move-result-object v8

    .line 862
    :goto_b
    if-nez v11, :cond_22

    .line 863
    .line 864
    move-object v15, v5

    .line 865
    move-object v4, v9

    .line 866
    goto :goto_c

    .line 867
    :cond_22
    sget-object v9, Lgz0/p;->Companion:Lgz0/o;

    .line 868
    .line 869
    invoke-static {v9, v11}, Lgz0/o;->b(Lgz0/o;Ljava/lang/CharSequence;)Lgz0/p;

    .line 870
    .line 871
    .line 872
    move-result-object v9

    .line 873
    const-string v11, "other"

    .line 874
    .line 875
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 876
    .line 877
    .line 878
    sget v11, Lmy0/c;->g:I

    .line 879
    .line 880
    iget-object v7, v7, Lgz0/p;->d:Ljava/time/Instant;

    .line 881
    .line 882
    invoke-virtual {v7}, Ljava/time/Instant;->getEpochSecond()J

    .line 883
    .line 884
    .line 885
    move-result-wide v11

    .line 886
    iget-object v9, v9, Lgz0/p;->d:Ljava/time/Instant;

    .line 887
    .line 888
    invoke-virtual {v9}, Ljava/time/Instant;->getEpochSecond()J

    .line 889
    .line 890
    .line 891
    move-result-wide v13

    .line 892
    sub-long/2addr v11, v13

    .line 893
    sget-object v13, Lmy0/e;->h:Lmy0/e;

    .line 894
    .line 895
    invoke-static {v11, v12, v13}, Lmy0/h;->t(JLmy0/e;)J

    .line 896
    .line 897
    .line 898
    move-result-wide v11

    .line 899
    invoke-virtual {v7}, Ljava/time/Instant;->getNano()I

    .line 900
    .line 901
    .line 902
    move-result v7

    .line 903
    invoke-virtual {v9}, Ljava/time/Instant;->getNano()I

    .line 904
    .line 905
    .line 906
    move-result v9

    .line 907
    sub-int/2addr v7, v9

    .line 908
    sget-object v9, Lmy0/e;->e:Lmy0/e;

    .line 909
    .line 910
    invoke-static {v7, v9}, Lmy0/h;->s(ILmy0/e;)J

    .line 911
    .line 912
    .line 913
    move-result-wide v13

    .line 914
    invoke-static {v11, v12, v13, v14}, Lmy0/c;->k(JJ)J

    .line 915
    .line 916
    .line 917
    move-result-wide v11

    .line 918
    sget-object v7, Lmy0/e;->j:Lmy0/e;

    .line 919
    .line 920
    invoke-static {v11, v12, v7}, Lmy0/c;->n(JLmy0/e;)J

    .line 921
    .line 922
    .line 923
    move-result-wide v13

    .line 924
    sget-object v7, Lmy0/e;->i:Lmy0/e;

    .line 925
    .line 926
    invoke-static {v11, v12, v7}, Lmy0/c;->n(JLmy0/e;)J

    .line 927
    .line 928
    .line 929
    move-result-wide v11

    .line 930
    const/16 v7, 0x3c

    .line 931
    .line 932
    move-object v15, v5

    .line 933
    int-to-long v4, v7

    .line 934
    rem-long/2addr v11, v4

    .line 935
    invoke-static {v13, v14, v11, v12}, Llp/ha;->b(JJ)Ljava/lang/String;

    .line 936
    .line 937
    .line 938
    move-result-object v4

    .line 939
    :goto_c
    invoke-direct {v10, v8, v4}, Lig/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 940
    .line 941
    .line 942
    const/16 v4, 0x35

    .line 943
    .line 944
    const/4 v9, 0x0

    .line 945
    invoke-static {v1, v10, v9, v6, v4}, Lig/f;->a(Lig/f;Lig/a;Llc/l;ZI)Lig/f;

    .line 946
    .line 947
    .line 948
    move-result-object v1

    .line 949
    invoke-virtual {v15, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 950
    .line 951
    .line 952
    move-result v0

    .line 953
    if-eqz v0, :cond_23

    .line 954
    .line 955
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 956
    .line 957
    return-object v0

    .line 958
    :cond_23
    move-object v5, v15

    .line 959
    const/4 v4, 0x0

    .line 960
    goto/16 :goto_a

    .line 961
    .line 962
    :pswitch_14
    check-cast v0, Lic0/p;

    .line 963
    .line 964
    check-cast v1, Lcz/myskoda/api/bff/v1/AuthenticationDto;

    .line 965
    .line 966
    const-string v2, "$this$requestSynchronous"

    .line 967
    .line 968
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 969
    .line 970
    .line 971
    iget-object v0, v0, Lic0/p;->a:Llc0/l;

    .line 972
    .line 973
    const-string v2, "Required value was null."

    .line 974
    .line 975
    new-instance v3, Llc0/k;

    .line 976
    .line 977
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/AuthenticationDto;->getAccessToken()Ljava/lang/String;

    .line 978
    .line 979
    .line 980
    move-result-object v4

    .line 981
    if-eqz v4, :cond_26

    .line 982
    .line 983
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/AuthenticationDto;->getRefreshToken()Ljava/lang/String;

    .line 984
    .line 985
    .line 986
    move-result-object v5

    .line 987
    if-eqz v5, :cond_25

    .line 988
    .line 989
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/AuthenticationDto;->getIdToken()Ljava/lang/String;

    .line 990
    .line 991
    .line 992
    move-result-object v1

    .line 993
    if-eqz v1, :cond_24

    .line 994
    .line 995
    invoke-direct {v3, v0, v4, v5, v1}, Llc0/k;-><init>(Llc0/l;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 996
    .line 997
    .line 998
    return-object v3

    .line 999
    :cond_24
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1000
    .line 1001
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1002
    .line 1003
    .line 1004
    throw v0

    .line 1005
    :cond_25
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1006
    .line 1007
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1008
    .line 1009
    .line 1010
    throw v0

    .line 1011
    :cond_26
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1012
    .line 1013
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1014
    .line 1015
    .line 1016
    throw v0

    .line 1017
    :pswitch_15
    check-cast v0, Llc0/l;

    .line 1018
    .line 1019
    check-cast v1, Lcz/myskoda/api/bff/v1/AuthenticationDto;

    .line 1020
    .line 1021
    const-string v2, "$this$requestSynchronous"

    .line 1022
    .line 1023
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1024
    .line 1025
    .line 1026
    const-string v2, "Required value was null."

    .line 1027
    .line 1028
    const-string v3, "tokenType"

    .line 1029
    .line 1030
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1031
    .line 1032
    .line 1033
    new-instance v3, Llc0/k;

    .line 1034
    .line 1035
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/AuthenticationDto;->getAccessToken()Ljava/lang/String;

    .line 1036
    .line 1037
    .line 1038
    move-result-object v4

    .line 1039
    if-eqz v4, :cond_29

    .line 1040
    .line 1041
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/AuthenticationDto;->getRefreshToken()Ljava/lang/String;

    .line 1042
    .line 1043
    .line 1044
    move-result-object v5

    .line 1045
    if-eqz v5, :cond_28

    .line 1046
    .line 1047
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/AuthenticationDto;->getIdToken()Ljava/lang/String;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v1

    .line 1051
    if-eqz v1, :cond_27

    .line 1052
    .line 1053
    invoke-direct {v3, v0, v4, v5, v1}, Llc0/k;-><init>(Llc0/l;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 1054
    .line 1055
    .line 1056
    return-object v3

    .line 1057
    :cond_27
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1058
    .line 1059
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1060
    .line 1061
    .line 1062
    throw v0

    .line 1063
    :cond_28
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1064
    .line 1065
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1066
    .line 1067
    .line 1068
    throw v0

    .line 1069
    :cond_29
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1070
    .line 1071
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1072
    .line 1073
    .line 1074
    throw v0

    .line 1075
    :pswitch_16
    check-cast v0, Lic/j;

    .line 1076
    .line 1077
    check-cast v1, Lgi/c;

    .line 1078
    .line 1079
    const-string v2, "$this$log"

    .line 1080
    .line 1081
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1082
    .line 1083
    .line 1084
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1085
    .line 1086
    const-string v2, "onUiEvent: "

    .line 1087
    .line 1088
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1089
    .line 1090
    .line 1091
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1092
    .line 1093
    .line 1094
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v0

    .line 1098
    return-object v0

    .line 1099
    :pswitch_17
    check-cast v0, Li91/l1;

    .line 1100
    .line 1101
    check-cast v1, Ld3/b;

    .line 1102
    .line 1103
    invoke-virtual {v0}, Li91/l1;->f()V

    .line 1104
    .line 1105
    .line 1106
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1107
    .line 1108
    return-object v0

    .line 1109
    :pswitch_18
    check-cast v0, Lg61/h;

    .line 1110
    .line 1111
    check-cast v1, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 1112
    .line 1113
    const-string v2, "it"

    .line 1114
    .line 1115
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1116
    .line 1117
    .line 1118
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->getStatus()Lyy0/a2;

    .line 1119
    .line 1120
    .line 1121
    move-result-object v1

    .line 1122
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v1

    .line 1126
    check-cast v1, Lg61/p;

    .line 1127
    .line 1128
    instance-of v2, v1, Lg61/i;

    .line 1129
    .line 1130
    if-eqz v2, :cond_2a

    .line 1131
    .line 1132
    check-cast v1, Lg61/i;

    .line 1133
    .line 1134
    iget-object v1, v1, Lg61/i;->a:Lg61/h;

    .line 1135
    .line 1136
    if-ne v1, v0, :cond_2a

    .line 1137
    .line 1138
    goto :goto_d

    .line 1139
    :cond_2a
    move v5, v6

    .line 1140
    :goto_d
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v0

    .line 1144
    return-object v0

    .line 1145
    :pswitch_19
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 1146
    .line 1147
    check-cast v1, Ljava/lang/String;

    .line 1148
    .line 1149
    const-string v2, "vinToRemove"

    .line 1150
    .line 1151
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1152
    .line 1153
    .line 1154
    iget-object v0, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 1155
    .line 1156
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1157
    .line 1158
    .line 1159
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1160
    .line 1161
    return-object v0

    .line 1162
    :pswitch_1a
    check-cast v0, Ll2/f1;

    .line 1163
    .line 1164
    check-cast v1, Ljava/lang/Float;

    .line 1165
    .line 1166
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1167
    .line 1168
    .line 1169
    move-result v1

    .line 1170
    invoke-virtual {v0, v1}, Ll2/f1;->p(F)V

    .line 1171
    .line 1172
    .line 1173
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1174
    .line 1175
    return-object v0

    .line 1176
    :pswitch_1b
    check-cast v0, Lh50/c;

    .line 1177
    .line 1178
    check-cast v1, Lm1/f;

    .line 1179
    .line 1180
    const-string v2, "$this$LazyColumn"

    .line 1181
    .line 1182
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1183
    .line 1184
    .line 1185
    new-instance v2, Li50/a;

    .line 1186
    .line 1187
    invoke-direct {v2, v0, v5}, Li50/a;-><init>(Lh50/c;I)V

    .line 1188
    .line 1189
    .line 1190
    new-instance v4, Lt2/b;

    .line 1191
    .line 1192
    const v6, -0x67bff9c5

    .line 1193
    .line 1194
    .line 1195
    invoke-direct {v4, v2, v5, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1196
    .line 1197
    .line 1198
    invoke-static {v1, v4, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1199
    .line 1200
    .line 1201
    iget-object v2, v0, Lh50/c;->b:Ljava/util/List;

    .line 1202
    .line 1203
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 1204
    .line 1205
    .line 1206
    move-result v4

    .line 1207
    new-instance v6, Lak/p;

    .line 1208
    .line 1209
    const/16 v7, 0x17

    .line 1210
    .line 1211
    invoke-direct {v6, v2, v7}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 1212
    .line 1213
    .line 1214
    new-instance v7, Ldl/i;

    .line 1215
    .line 1216
    invoke-direct {v7, v2, v0, v3}, Ldl/i;-><init>(Ljava/util/List;Ljava/lang/Object;I)V

    .line 1217
    .line 1218
    .line 1219
    new-instance v0, Lt2/b;

    .line 1220
    .line 1221
    const v2, 0x799532c4

    .line 1222
    .line 1223
    .line 1224
    invoke-direct {v0, v7, v5, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1225
    .line 1226
    .line 1227
    const/4 v9, 0x0

    .line 1228
    invoke-virtual {v1, v4, v9, v6, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1229
    .line 1230
    .line 1231
    sget-object v0, Li50/c;->a:Lt2/b;

    .line 1232
    .line 1233
    invoke-static {v1, v0, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1234
    .line 1235
    .line 1236
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1237
    .line 1238
    return-object v0

    .line 1239
    :pswitch_1c
    check-cast v0, Lh40/o1;

    .line 1240
    .line 1241
    check-cast v1, Lm1/f;

    .line 1242
    .line 1243
    const-string v2, "$this$LazyColumn"

    .line 1244
    .line 1245
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1246
    .line 1247
    .line 1248
    iget-boolean v2, v0, Lh40/o1;->b:Z

    .line 1249
    .line 1250
    if-eqz v2, :cond_2b

    .line 1251
    .line 1252
    iget-boolean v2, v0, Lh40/o1;->c:Z

    .line 1253
    .line 1254
    if-nez v2, :cond_2b

    .line 1255
    .line 1256
    sget-object v0, Li40/q;->l:Lt2/b;

    .line 1257
    .line 1258
    invoke-static {v1, v0, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1259
    .line 1260
    .line 1261
    goto :goto_10

    .line 1262
    :cond_2b
    iget-object v0, v0, Lh40/o1;->e:Ljava/util/List;

    .line 1263
    .line 1264
    check-cast v0, Ljava/lang/Iterable;

    .line 1265
    .line 1266
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1267
    .line 1268
    .line 1269
    move-result-object v0

    .line 1270
    move v2, v6

    .line 1271
    :goto_e
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1272
    .line 1273
    .line 1274
    move-result v4

    .line 1275
    if-eqz v4, :cond_2f

    .line 1276
    .line 1277
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1278
    .line 1279
    .line 1280
    move-result-object v4

    .line 1281
    add-int/lit8 v7, v2, 0x1

    .line 1282
    .line 1283
    if-ltz v2, :cond_2e

    .line 1284
    .line 1285
    check-cast v4, Lh40/n1;

    .line 1286
    .line 1287
    new-instance v8, Li40/c1;

    .line 1288
    .line 1289
    invoke-direct {v8, v2, v4, v6}, Li40/c1;-><init>(ILjava/lang/Object;I)V

    .line 1290
    .line 1291
    .line 1292
    new-instance v2, Lt2/b;

    .line 1293
    .line 1294
    const v10, -0x65cabdaf

    .line 1295
    .line 1296
    .line 1297
    invoke-direct {v2, v8, v5, v10}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1298
    .line 1299
    .line 1300
    invoke-static {v1, v2, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1301
    .line 1302
    .line 1303
    iget-object v2, v4, Lh40/n1;->b:Ljava/util/List;

    .line 1304
    .line 1305
    check-cast v2, Ljava/lang/Iterable;

    .line 1306
    .line 1307
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1308
    .line 1309
    .line 1310
    move-result-object v2

    .line 1311
    move v4, v6

    .line 1312
    :goto_f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1313
    .line 1314
    .line 1315
    move-result v8

    .line 1316
    if-eqz v8, :cond_2d

    .line 1317
    .line 1318
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v8

    .line 1322
    add-int/lit8 v10, v4, 0x1

    .line 1323
    .line 1324
    if-ltz v4, :cond_2c

    .line 1325
    .line 1326
    check-cast v8, Lh40/j4;

    .line 1327
    .line 1328
    new-instance v11, Li40/c1;

    .line 1329
    .line 1330
    invoke-direct {v11, v4, v8, v5}, Li40/c1;-><init>(ILjava/lang/Object;I)V

    .line 1331
    .line 1332
    .line 1333
    new-instance v4, Lt2/b;

    .line 1334
    .line 1335
    const v8, 0x39002935

    .line 1336
    .line 1337
    .line 1338
    invoke-direct {v4, v11, v5, v8}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1339
    .line 1340
    .line 1341
    invoke-static {v1, v4, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1342
    .line 1343
    .line 1344
    move v4, v10

    .line 1345
    goto :goto_f

    .line 1346
    :cond_2c
    invoke-static {}, Ljp/k1;->r()V

    .line 1347
    .line 1348
    .line 1349
    const/4 v9, 0x0

    .line 1350
    throw v9

    .line 1351
    :cond_2d
    const/4 v9, 0x0

    .line 1352
    move v2, v7

    .line 1353
    goto :goto_e

    .line 1354
    :cond_2e
    const/4 v9, 0x0

    .line 1355
    invoke-static {}, Ljp/k1;->r()V

    .line 1356
    .line 1357
    .line 1358
    throw v9

    .line 1359
    :cond_2f
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1360
    .line 1361
    return-object v0

    .line 1362
    nop

    .line 1363
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
