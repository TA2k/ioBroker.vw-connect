.class public final synthetic Le81/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z


# direct methods
.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Le81/b;->d:I

    iput-boolean p2, p0, Le81/b;->e:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Z)V
    .locals 1

    .line 2
    const/16 v0, 0x16

    iput v0, p0, Le81/b;->d:I

    sget-object v0, Loi/b;->d:Loi/b;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Le81/b;->e:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le81/b;->d:I

    .line 4
    .line 5
    const-string v2, "$this$sdkViewModel"

    .line 6
    .line 7
    iget-boolean v0, v0, Le81/b;->e:Z

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Landroid/content/Context;

    .line 15
    .line 16
    const-string v2, "context"

    .line 17
    .line 18
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v2, Landroid/webkit/WebView;

    .line 22
    .line 23
    invoke-direct {v2, v1}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V

    .line 24
    .line 25
    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    const v0, -0xe9e8e8

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2, v0}, Landroid/webkit/WebView;->setBackgroundColor(I)V

    .line 32
    .line 33
    .line 34
    :cond_0
    return-object v2

    .line 35
    :pswitch_0
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 38
    .line 39
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;->a(ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubScreenState;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    return-object v0

    .line 44
    :pswitch_1
    move-object/from16 v1, p1

    .line 45
    .line 46
    check-cast v1, Lhi/a;

    .line 47
    .line 48
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 52
    .line 53
    const-class v3, Lwg/b;

    .line 54
    .line 55
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v1, Lii/a;

    .line 60
    .line 61
    invoke-virtual {v1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    move-object v6, v3

    .line 66
    check-cast v6, Lwg/b;

    .line 67
    .line 68
    const-class v3, Ldh/u;

    .line 69
    .line 70
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-virtual {v1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    check-cast v3, Ldh/u;

    .line 79
    .line 80
    const-class v4, Lxg/b;

    .line 81
    .line 82
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Lxg/b;

    .line 91
    .line 92
    new-instance v2, Lrh/u;

    .line 93
    .line 94
    new-instance v4, Lr40/b;

    .line 95
    .line 96
    const/4 v10, 0x0

    .line 97
    const/16 v11, 0xb

    .line 98
    .line 99
    const/4 v5, 0x0

    .line 100
    const-class v7, Lwg/b;

    .line 101
    .line 102
    const-string v8, "getWallbox"

    .line 103
    .line 104
    const-string v9, "getWallbox-d1pmJ48()Ljava/lang/Object;"

    .line 105
    .line 106
    invoke-direct/range {v4 .. v11}, Lr40/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 107
    .line 108
    .line 109
    new-instance v7, Ljd/b;

    .line 110
    .line 111
    const/4 v13, 0x0

    .line 112
    const/16 v14, 0x16

    .line 113
    .line 114
    const/4 v8, 0x2

    .line 115
    const-class v10, Ldh/u;

    .line 116
    .line 117
    const-string v11, "pairChargingStation"

    .line 118
    .line 119
    const-string v12, "pairChargingStation-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/pairingWallbox/PairChargingStationRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 120
    .line 121
    move-object v9, v3

    .line 122
    invoke-direct/range {v7 .. v14}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 123
    .line 124
    .line 125
    invoke-direct {v2, v0, v4, v1, v7}, Lrh/u;-><init>(ZLr40/b;Lxg/b;Ljd/b;)V

    .line 126
    .line 127
    .line 128
    iget-object v0, v2, Lrh/u;->e:Lr40/b;

    .line 129
    .line 130
    invoke-virtual {v0}, Lr40/b;->invoke()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    check-cast v0, Llx0/o;

    .line 135
    .line 136
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 137
    .line 138
    instance-of v1, v0, Llx0/n;

    .line 139
    .line 140
    if-nez v1, :cond_5

    .line 141
    .line 142
    check-cast v0, Lbh/c;

    .line 143
    .line 144
    const-string v1, "<this>"

    .line 145
    .line 146
    iget-object v3, v2, Lrh/u;->h:Lyy0/c2;

    .line 147
    .line 148
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    const-string v1, "config"

    .line 152
    .line 153
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    :cond_1
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    move-object v4, v1

    .line 161
    check-cast v4, Lrh/v;

    .line 162
    .line 163
    iget-object v5, v0, Lbh/c;->f:Ljava/util/List;

    .line 164
    .line 165
    check-cast v5, Ljava/lang/Iterable;

    .line 166
    .line 167
    new-instance v6, Ljava/util/ArrayList;

    .line 168
    .line 169
    const/16 v7, 0xa

    .line 170
    .line 171
    invoke-static {v5, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 172
    .line 173
    .line 174
    move-result v7

    .line 175
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 176
    .line 177
    .line 178
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 179
    .line 180
    .line 181
    move-result-object v5

    .line 182
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 183
    .line 184
    .line 185
    move-result v7

    .line 186
    if-eqz v7, :cond_4

    .line 187
    .line 188
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    check-cast v7, Lbh/k;

    .line 193
    .line 194
    instance-of v8, v7, Lbh/f;

    .line 195
    .line 196
    const/4 v13, 0x0

    .line 197
    if-eqz v8, :cond_2

    .line 198
    .line 199
    check-cast v7, Lbh/f;

    .line 200
    .line 201
    iget-object v10, v7, Lbh/f;->b:Ljava/lang/String;

    .line 202
    .line 203
    iget-object v12, v7, Lbh/f;->c:Ljava/lang/String;

    .line 204
    .line 205
    iget-object v15, v7, Lbh/f;->d:Ljava/lang/String;

    .line 206
    .line 207
    iget-object v8, v7, Lbh/f;->f:Ljava/lang/String;

    .line 208
    .line 209
    iget-object v14, v7, Lbh/f;->e:Ljava/lang/String;

    .line 210
    .line 211
    new-instance v9, Lrh/d;

    .line 212
    .line 213
    const-string v11, ""

    .line 214
    .line 215
    sget-object v17, Lrh/a;->a:Lrh/a;

    .line 216
    .line 217
    move-object/from16 v16, v8

    .line 218
    .line 219
    invoke-direct/range {v9 .. v17}, Lrh/d;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrh/c;)V

    .line 220
    .line 221
    .line 222
    goto :goto_1

    .line 223
    :cond_2
    instance-of v8, v7, Lbh/i;

    .line 224
    .line 225
    if-eqz v8, :cond_3

    .line 226
    .line 227
    check-cast v7, Lbh/i;

    .line 228
    .line 229
    iget-object v10, v7, Lbh/i;->b:Ljava/lang/String;

    .line 230
    .line 231
    iget-object v12, v7, Lbh/i;->c:Ljava/lang/String;

    .line 232
    .line 233
    iget-object v15, v7, Lbh/i;->d:Ljava/lang/String;

    .line 234
    .line 235
    iget-object v8, v7, Lbh/i;->f:Ljava/lang/String;

    .line 236
    .line 237
    iget-object v14, v7, Lbh/i;->e:Ljava/lang/String;

    .line 238
    .line 239
    new-instance v9, Lrh/d;

    .line 240
    .line 241
    const-string v11, ""

    .line 242
    .line 243
    sget-object v17, Lrh/b;->a:Lrh/b;

    .line 244
    .line 245
    move-object/from16 v16, v8

    .line 246
    .line 247
    invoke-direct/range {v9 .. v17}, Lrh/d;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrh/c;)V

    .line 248
    .line 249
    .line 250
    :goto_1
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    goto :goto_0

    .line 254
    :cond_3
    new-instance v0, La8/r0;

    .line 255
    .line 256
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 257
    .line 258
    .line 259
    throw v0

    .line 260
    :cond_4
    iget-boolean v5, v0, Lbh/c;->c:Z

    .line 261
    .line 262
    const/4 v10, 0x0

    .line 263
    const/16 v11, 0x7c

    .line 264
    .line 265
    const/4 v7, 0x0

    .line 266
    const/4 v8, 0x0

    .line 267
    const/4 v9, 0x0

    .line 268
    invoke-static/range {v4 .. v11}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 269
    .line 270
    .line 271
    move-result-object v4

    .line 272
    invoke-virtual {v3, v1, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-result v1

    .line 276
    if-eqz v1, :cond_1

    .line 277
    .line 278
    :cond_5
    return-object v2

    .line 279
    :pswitch_2
    move-object/from16 v1, p1

    .line 280
    .line 281
    check-cast v1, Lgi/c;

    .line 282
    .line 283
    const-string v2, "$this$log"

    .line 284
    .line 285
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    new-instance v1, Ljava/lang/StringBuilder;

    .line 289
    .line 290
    const-string v2, "Received 428 "

    .line 291
    .line 292
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 296
    .line 297
    .line 298
    const-string v0, " from BFF"

    .line 299
    .line 300
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 301
    .line 302
    .line 303
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    return-object v0

    .line 308
    :pswitch_3
    move-object/from16 v1, p1

    .line 309
    .line 310
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 311
    .line 312
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState$Paused;->a(ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubScreenState;

    .line 313
    .line 314
    .line 315
    move-result-object v0

    .line 316
    return-object v0

    .line 317
    :pswitch_4
    sget-object v1, Loi/b;->d:Loi/b;

    .line 318
    .line 319
    move-object/from16 v1, p1

    .line 320
    .line 321
    check-cast v1, Lhi/a;

    .line 322
    .line 323
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    const-class v2, Lpi/b;

    .line 327
    .line 328
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 329
    .line 330
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 331
    .line 332
    .line 333
    move-result-object v2

    .line 334
    check-cast v1, Lii/a;

    .line 335
    .line 336
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v1

    .line 340
    check-cast v1, Lpi/b;

    .line 341
    .line 342
    new-instance v2, Loi/c;

    .line 343
    .line 344
    new-instance v3, Lny/f0;

    .line 345
    .line 346
    const/4 v4, 0x6

    .line 347
    const/4 v5, 0x0

    .line 348
    invoke-direct {v3, v1, v5, v4}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 349
    .line 350
    .line 351
    new-instance v4, Lyy0/m1;

    .line 352
    .line 353
    invoke-direct {v4, v3}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 354
    .line 355
    .line 356
    iget-object v3, v1, Lpi/b;->a:Lvy0/b0;

    .line 357
    .line 358
    iget-object v1, v1, Lpi/b;->e:Ll20/c;

    .line 359
    .line 360
    invoke-virtual {v1}, Ll20/c;->invoke()Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    move-result-object v1

    .line 364
    sget-object v6, Lyy0/u1;->a:Lyy0/w1;

    .line 365
    .line 366
    invoke-static {v4, v3, v6, v1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 367
    .line 368
    .line 369
    move-result-object v1

    .line 370
    invoke-direct {v2, v1}, Loi/c;-><init>(Lyy0/l1;)V

    .line 371
    .line 372
    .line 373
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    iget-object v1, v2, Loi/c;->e:Lyy0/c2;

    .line 378
    .line 379
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    invoke-virtual {v1, v5, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 383
    .line 384
    .line 385
    return-object v2

    .line 386
    :pswitch_5
    move-object/from16 v1, p1

    .line 387
    .line 388
    check-cast v1, Lmc/v;

    .line 389
    .line 390
    const-string v2, "it"

    .line 391
    .line 392
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 393
    .line 394
    .line 395
    iget-object v1, v1, Lmc/v;->b:Lmc/z;

    .line 396
    .line 397
    const-string v2, "logo"

    .line 398
    .line 399
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 400
    .line 401
    .line 402
    const/4 v2, 0x2

    .line 403
    const/4 v3, 0x1

    .line 404
    if-eqz v0, :cond_9

    .line 405
    .line 406
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    if-eqz v0, :cond_8

    .line 411
    .line 412
    if-eq v0, v3, :cond_7

    .line 413
    .line 414
    if-ne v0, v2, :cond_6

    .line 415
    .line 416
    const v0, 0x7f080591

    .line 417
    .line 418
    .line 419
    goto :goto_2

    .line 420
    :cond_6
    new-instance v0, La8/r0;

    .line 421
    .line 422
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 423
    .line 424
    .line 425
    throw v0

    .line 426
    :cond_7
    const v0, 0x7f08058f

    .line 427
    .line 428
    .line 429
    goto :goto_2

    .line 430
    :cond_8
    const v0, 0x7f080593

    .line 431
    .line 432
    .line 433
    goto :goto_2

    .line 434
    :cond_9
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 435
    .line 436
    .line 437
    move-result v0

    .line 438
    if-eqz v0, :cond_c

    .line 439
    .line 440
    if-eq v0, v3, :cond_b

    .line 441
    .line 442
    if-ne v0, v2, :cond_a

    .line 443
    .line 444
    const v0, 0x7f080590

    .line 445
    .line 446
    .line 447
    goto :goto_2

    .line 448
    :cond_a
    new-instance v0, La8/r0;

    .line 449
    .line 450
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 451
    .line 452
    .line 453
    throw v0

    .line 454
    :cond_b
    const v0, 0x7f08058e

    .line 455
    .line 456
    .line 457
    goto :goto_2

    .line 458
    :cond_c
    const v0, 0x7f080592

    .line 459
    .line 460
    .line 461
    :goto_2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    return-object v0

    .line 466
    :pswitch_6
    move-object/from16 v1, p1

    .line 467
    .line 468
    check-cast v1, Lz71/j;

    .line 469
    .line 470
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->d(Lz71/j;Z)Llx0/b0;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    return-object v0

    .line 475
    :pswitch_7
    move-object/from16 v1, p1

    .line 476
    .line 477
    check-cast v1, Lz71/j;

    .line 478
    .line 479
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->f(Lz71/j;Z)Llx0/b0;

    .line 480
    .line 481
    .line 482
    move-result-object v0

    .line 483
    return-object v0

    .line 484
    :pswitch_8
    move-object/from16 v1, p1

    .line 485
    .line 486
    check-cast v1, Lz71/j;

    .line 487
    .line 488
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/TouchDiagnosisViewModelController;->g(Lz71/j;Z)Llx0/b0;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    return-object v0

    .line 493
    :pswitch_9
    move-object/from16 v1, p1

    .line 494
    .line 495
    check-cast v1, Lz71/i;

    .line 496
    .line 497
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->l(Lz71/i;Z)Llx0/b0;

    .line 498
    .line 499
    .line 500
    move-result-object v0

    .line 501
    return-object v0

    .line 502
    :pswitch_a
    move-object/from16 v1, p1

    .line 503
    .line 504
    check-cast v1, Lz71/i;

    .line 505
    .line 506
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->j(Lz71/i;Z)Llx0/b0;

    .line 507
    .line 508
    .line 509
    move-result-object v0

    .line 510
    return-object v0

    .line 511
    :pswitch_b
    move-object/from16 v1, p1

    .line 512
    .line 513
    check-cast v1, Lz71/i;

    .line 514
    .line 515
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->e(Lz71/i;Z)Llx0/b0;

    .line 516
    .line 517
    .line 518
    move-result-object v0

    .line 519
    return-object v0

    .line 520
    :pswitch_c
    move-object/from16 v1, p1

    .line 521
    .line 522
    check-cast v1, Lz71/i;

    .line 523
    .line 524
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->g(Lz71/i;Z)Llx0/b0;

    .line 525
    .line 526
    .line 527
    move-result-object v0

    .line 528
    return-object v0

    .line 529
    :pswitch_d
    move-object/from16 v1, p1

    .line 530
    .line 531
    check-cast v1, Lz71/i;

    .line 532
    .line 533
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ScenarioSelectionViewModelController;->h(Lz71/i;Z)Llx0/b0;

    .line 534
    .line 535
    .line 536
    move-result-object v0

    .line 537
    return-object v0

    .line 538
    :pswitch_e
    move-object/from16 v1, p1

    .line 539
    .line 540
    check-cast v1, Lz71/g;

    .line 541
    .line 542
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->m(Lz71/g;Z)Llx0/b0;

    .line 543
    .line 544
    .line 545
    move-result-object v0

    .line 546
    return-object v0

    .line 547
    :pswitch_f
    move-object/from16 v1, p1

    .line 548
    .line 549
    check-cast v1, Lz71/g;

    .line 550
    .line 551
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->j(Lz71/g;Z)Llx0/b0;

    .line 552
    .line 553
    .line 554
    move-result-object v0

    .line 555
    return-object v0

    .line 556
    :pswitch_10
    move-object/from16 v1, p1

    .line 557
    .line 558
    check-cast v1, Lz71/g;

    .line 559
    .line 560
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->p(Lz71/g;Z)Llx0/b0;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    return-object v0

    .line 565
    :pswitch_11
    move-object/from16 v1, p1

    .line 566
    .line 567
    check-cast v1, Lz71/e;

    .line 568
    .line 569
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->d(Lz71/e;Z)Llx0/b0;

    .line 570
    .line 571
    .line 572
    move-result-object v0

    .line 573
    return-object v0

    .line 574
    :pswitch_12
    move-object/from16 v1, p1

    .line 575
    .line 576
    check-cast v1, Lz71/d;

    .line 577
    .line 578
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->e(Lz71/d;Z)Llx0/b0;

    .line 579
    .line 580
    .line 581
    move-result-object v0

    .line 582
    return-object v0

    .line 583
    :pswitch_13
    move-object/from16 v1, p1

    .line 584
    .line 585
    check-cast v1, Lz71/d;

    .line 586
    .line 587
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->o(Lz71/d;Z)Llx0/b0;

    .line 588
    .line 589
    .line 590
    move-result-object v0

    .line 591
    return-object v0

    .line 592
    :pswitch_14
    move-object/from16 v1, p1

    .line 593
    .line 594
    check-cast v1, Lz71/d;

    .line 595
    .line 596
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->n(Lz71/d;Z)Llx0/b0;

    .line 597
    .line 598
    .line 599
    move-result-object v0

    .line 600
    return-object v0

    .line 601
    :pswitch_15
    move-object/from16 v1, p1

    .line 602
    .line 603
    check-cast v1, Lz71/d;

    .line 604
    .line 605
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveViewModelController;->m(Lz71/d;Z)Llx0/b0;

    .line 606
    .line 607
    .line 608
    move-result-object v0

    .line 609
    return-object v0

    .line 610
    :pswitch_16
    move-object/from16 v1, p1

    .line 611
    .line 612
    check-cast v1, Lz71/c;

    .line 613
    .line 614
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->e(Lz71/c;Z)Llx0/b0;

    .line 615
    .line 616
    .line 617
    move-result-object v0

    .line 618
    return-object v0

    .line 619
    :pswitch_17
    move-object/from16 v1, p1

    .line 620
    .line 621
    check-cast v1, Lz71/c;

    .line 622
    .line 623
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveCorrectionViewModelController;->d(Lz71/c;Z)Llx0/b0;

    .line 624
    .line 625
    .line 626
    move-result-object v0

    .line 627
    return-object v0

    .line 628
    :pswitch_18
    move-object/from16 v1, p1

    .line 629
    .line 630
    check-cast v1, Lz71/b;

    .line 631
    .line 632
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;->e(Lz71/b;Z)Llx0/b0;

    .line 633
    .line 634
    .line 635
    move-result-object v0

    .line 636
    return-object v0

    .line 637
    :pswitch_19
    move-object/from16 v1, p1

    .line 638
    .line 639
    check-cast v1, Lz71/b;

    .line 640
    .line 641
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;->c(Lz71/b;Z)Llx0/b0;

    .line 642
    .line 643
    .line 644
    move-result-object v0

    .line 645
    return-object v0

    .line 646
    :pswitch_1a
    move-object/from16 v1, p1

    .line 647
    .line 648
    check-cast v1, Lz71/b;

    .line 649
    .line 650
    invoke-static {v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/DriveActivationViewModelController;->h(Lz71/b;Z)Llx0/b0;

    .line 651
    .line 652
    .line 653
    move-result-object v0

    .line 654
    return-object v0

    .line 655
    :pswitch_data_0
    .packed-switch 0x0
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
