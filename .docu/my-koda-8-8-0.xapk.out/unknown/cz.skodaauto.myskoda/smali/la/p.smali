.class public final synthetic Lla/p;
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
    iput p2, p0, Lla/p;->d:I

    iput-object p1, p0, Lla/p;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lmj0/a;Ljava/time/OffsetDateTime;)V
    .locals 0

    .line 2
    const/16 p1, 0xd

    iput p1, p0, Lla/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lla/p;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lp1/a0;Lg1/e2;)V
    .locals 0

    .line 3
    const/16 p2, 0x1d

    iput p2, p0, Lla/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lla/p;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 39

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lla/p;->d:I

    .line 6
    .line 7
    const-string v3, "entered drag with non-zero pending scroll"

    .line 8
    .line 9
    const/high16 v4, 0x3f000000    # 0.5f

    .line 10
    .line 11
    const/4 v5, 0x2

    .line 12
    const/4 v6, 0x3

    .line 13
    const/4 v7, 0x0

    .line 14
    const/4 v8, 0x0

    .line 15
    const/4 v9, 0x0

    .line 16
    const-string v10, "$this$log"

    .line 17
    .line 18
    const/4 v11, 0x1

    .line 19
    sget-object v12, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    iget-object v0, v0, Lla/p;->e:Ljava/lang/Object;

    .line 22
    .line 23
    packed-switch v2, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    check-cast v0, Lp1/a0;

    .line 27
    .line 28
    check-cast v1, Ljava/lang/Float;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    iget-object v0, v0, Lp1/a0;->b:Lp1/v;

    .line 35
    .line 36
    invoke-virtual {v0}, Lp1/v;->o()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_0

    .line 41
    .line 42
    invoke-virtual {v0}, Lp1/v;->o()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    int-to-float v2, v2

    .line 47
    div-float v8, v1, v2

    .line 48
    .line 49
    :cond_0
    invoke-static {v8}, Lcy0/a;->i(F)I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-virtual {v0}, Lp1/v;->k()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    add-int/2addr v2, v1

    .line 58
    invoke-virtual {v0, v2}, Lp1/v;->j(I)I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    iget-object v0, v0, Lp1/v;->s:Ll2/g1;

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ll2/g1;->p(I)V

    .line 65
    .line 66
    .line 67
    return-object v12

    .line 68
    :pswitch_0
    check-cast v0, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    check-cast v1, Ljava/lang/Byte;

    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/lang/Byte;->byteValue()B

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    const/16 v3, 0x20

    .line 77
    .line 78
    if-ne v2, v3, :cond_1

    .line 79
    .line 80
    const-string v1, "%20"

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    sget-object v3, Low0/a;->a:Ljava/util/Set;

    .line 87
    .line 88
    invoke-interface {v3, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    if-nez v3, :cond_3

    .line 93
    .line 94
    sget-object v3, Low0/a;->c:Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_2

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_2
    invoke-static {v2}, Low0/a;->g(B)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_3
    :goto_0
    int-to-char v1, v2

    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    :goto_1
    return-object v12

    .line 116
    :pswitch_1
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;

    .line 117
    .line 118
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 119
    .line 120
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    return-object v0

    .line 125
    :pswitch_2
    check-cast v0, Lo81/a;

    .line 126
    .line 127
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 128
    .line 129
    const-string v2, "input"

    .line 130
    .line 131
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    instance-of v2, v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 135
    .line 136
    if-eqz v2, :cond_4

    .line 137
    .line 138
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 139
    .line 140
    invoke-static {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    sget-object v3, Ls71/p;->E:Ls71/p;

    .line 145
    .line 146
    if-ne v2, v3, :cond_4

    .line 147
    .line 148
    new-instance v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;

    .line 149
    .line 150
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    invoke-direct {v9, v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBSubStateMachine$InvalidTouchState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)V

    .line 155
    .line 156
    .line 157
    :cond_4
    return-object v9

    .line 158
    :pswitch_3
    check-cast v0, Lu2/g;

    .line 159
    .line 160
    if-eqz v0, :cond_5

    .line 161
    .line 162
    invoke-interface {v0, v1}, Lu2/g;->d(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v11

    .line 166
    :cond_5
    invoke-static {v11}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    return-object v0

    .line 171
    :pswitch_4
    check-cast v0, Lo1/h0;

    .line 172
    .line 173
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 174
    .line 175
    new-instance v1, La2/j;

    .line 176
    .line 177
    const/16 v2, 0xb

    .line 178
    .line 179
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 180
    .line 181
    .line 182
    return-object v1

    .line 183
    :pswitch_5
    check-cast v0, Lo1/z;

    .line 184
    .line 185
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 186
    .line 187
    new-instance v1, La2/j;

    .line 188
    .line 189
    const/16 v2, 0x9

    .line 190
    .line 191
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 192
    .line 193
    .line 194
    return-object v1

    .line 195
    :pswitch_6
    check-cast v0, Lnz/z;

    .line 196
    .line 197
    check-cast v1, Ljava/lang/Boolean;

    .line 198
    .line 199
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 200
    .line 201
    .line 202
    move-result v1

    .line 203
    sget v2, Lnz/z;->B:I

    .line 204
    .line 205
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    move-object v13, v2

    .line 210
    check-cast v13, Lnz/s;

    .line 211
    .line 212
    const-string v2, "<this>"

    .line 213
    .line 214
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    if-eqz v1, :cond_6

    .line 218
    .line 219
    :goto_2
    move/from16 v19, v7

    .line 220
    .line 221
    goto :goto_3

    .line 222
    :cond_6
    iget-boolean v7, v13, Lnz/s;->i:Z

    .line 223
    .line 224
    goto :goto_2

    .line 225
    :goto_3
    const/16 v37, 0x0

    .line 226
    .line 227
    const v38, 0xff9fef7

    .line 228
    .line 229
    .line 230
    const/4 v14, 0x0

    .line 231
    const/4 v15, 0x0

    .line 232
    const/16 v16, 0x0

    .line 233
    .line 234
    const/16 v17, 0x1

    .line 235
    .line 236
    const/16 v18, 0x0

    .line 237
    .line 238
    const/16 v20, 0x0

    .line 239
    .line 240
    const/16 v21, 0x0

    .line 241
    .line 242
    const/16 v22, 0x0

    .line 243
    .line 244
    const/16 v23, 0x0

    .line 245
    .line 246
    const/16 v24, 0x0

    .line 247
    .line 248
    const/16 v25, 0x0

    .line 249
    .line 250
    const/16 v26, 0x0

    .line 251
    .line 252
    const/16 v27, 0x0

    .line 253
    .line 254
    const/16 v28, 0x0

    .line 255
    .line 256
    const/16 v29, 0x0

    .line 257
    .line 258
    const/16 v30, 0x0

    .line 259
    .line 260
    const/16 v31, 0x0

    .line 261
    .line 262
    const/16 v32, 0x0

    .line 263
    .line 264
    const/16 v33, 0x0

    .line 265
    .line 266
    const/16 v34, 0x0

    .line 267
    .line 268
    const/16 v35, 0x0

    .line 269
    .line 270
    const/16 v36, 0x0

    .line 271
    .line 272
    invoke-static/range {v13 .. v38}, Lnz/s;->a(Lnz/s;Ler0/g;Llf0/i;ZZZZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;Lmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;ZI)Lnz/s;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 277
    .line 278
    .line 279
    return-object v12

    .line 280
    :pswitch_7
    check-cast v0, Lb/r;

    .line 281
    .line 282
    check-cast v1, Lly/b;

    .line 283
    .line 284
    const/4 v2, -0x1

    .line 285
    if-nez v1, :cond_7

    .line 286
    .line 287
    move v1, v2

    .line 288
    goto :goto_4

    .line 289
    :cond_7
    sget-object v3, Lny/d0;->a:[I

    .line 290
    .line 291
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    aget v1, v3, v1

    .line 296
    .line 297
    :goto_4
    const/16 v3, 0x1c

    .line 298
    .line 299
    if-eq v1, v11, :cond_9

    .line 300
    .line 301
    if-eq v1, v5, :cond_9

    .line 302
    .line 303
    if-eq v1, v6, :cond_9

    .line 304
    .line 305
    sget-boolean v1, Llp/nb;->a:Z

    .line 306
    .line 307
    const/high16 v4, -0x1000000

    .line 308
    .line 309
    if-eqz v1, :cond_8

    .line 310
    .line 311
    new-instance v1, Lb/k0;

    .line 312
    .line 313
    new-instance v2, La00/a;

    .line 314
    .line 315
    invoke-direct {v2, v3}, La00/a;-><init>(I)V

    .line 316
    .line 317
    .line 318
    invoke-direct {v1, v4, v4, v5, v2}, Lb/k0;-><init>(IIILay0/k;)V

    .line 319
    .line 320
    .line 321
    goto :goto_5

    .line 322
    :cond_8
    new-instance v1, Lb/k0;

    .line 323
    .line 324
    new-instance v3, La00/a;

    .line 325
    .line 326
    const/16 v5, 0x1b

    .line 327
    .line 328
    invoke-direct {v3, v5}, La00/a;-><init>(I)V

    .line 329
    .line 330
    .line 331
    invoke-direct {v1, v2, v4, v11, v3}, Lb/k0;-><init>(IIILay0/k;)V

    .line 332
    .line 333
    .line 334
    :goto_5
    invoke-static {v0, v1, v1}, Lb/u;->a(Lb/r;Lb/k0;Lb/k0;)V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    invoke-static {v0, v11}, Ljp/pf;->b(Landroid/view/Window;Z)V

    .line 342
    .line 343
    .line 344
    goto :goto_6

    .line 345
    :cond_9
    new-instance v1, Lb/k0;

    .line 346
    .line 347
    new-instance v2, La00/a;

    .line 348
    .line 349
    invoke-direct {v2, v3}, La00/a;-><init>(I)V

    .line 350
    .line 351
    .line 352
    invoke-direct {v1, v7, v7, v5, v2}, Lb/k0;-><init>(IIILay0/k;)V

    .line 353
    .line 354
    .line 355
    new-instance v2, Lb/k0;

    .line 356
    .line 357
    new-instance v4, La00/a;

    .line 358
    .line 359
    invoke-direct {v4, v3}, La00/a;-><init>(I)V

    .line 360
    .line 361
    .line 362
    invoke-direct {v2, v7, v7, v5, v4}, Lb/k0;-><init>(IIILay0/k;)V

    .line 363
    .line 364
    .line 365
    invoke-static {v0, v1, v2}, Lb/u;->a(Lb/r;Lb/k0;Lb/k0;)V

    .line 366
    .line 367
    .line 368
    :goto_6
    return-object v12

    .line 369
    :pswitch_8
    check-cast v0, Lm70/b;

    .line 370
    .line 371
    check-cast v1, Ljava/time/LocalDate;

    .line 372
    .line 373
    const-string v2, "date"

    .line 374
    .line 375
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    const/16 v2, 0x7e0

    .line 379
    .line 380
    invoke-static {v2, v11, v11}, Ljava/time/LocalDate;->of(III)Ljava/time/LocalDate;

    .line 381
    .line 382
    .line 383
    move-result-object v2

    .line 384
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 385
    .line 386
    .line 387
    move-result-object v3

    .line 388
    invoke-virtual {v1, v3}, Ljava/time/LocalDate;->isAfter(Ljava/time/chrono/ChronoLocalDate;)Z

    .line 389
    .line 390
    .line 391
    move-result v3

    .line 392
    if-nez v3, :cond_a

    .line 393
    .line 394
    invoke-virtual {v1, v2}, Ljava/time/LocalDate;->isBefore(Ljava/time/chrono/ChronoLocalDate;)Z

    .line 395
    .line 396
    .line 397
    move-result v2

    .line 398
    if-nez v2, :cond_a

    .line 399
    .line 400
    iget-object v0, v0, Lm70/b;->h:Ljava/util/List;

    .line 401
    .line 402
    invoke-interface {v0, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    move-result v0

    .line 406
    if-nez v0, :cond_a

    .line 407
    .line 408
    move v7, v11

    .line 409
    :cond_a
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 410
    .line 411
    .line 412
    move-result-object v0

    .line 413
    return-object v0

    .line 414
    :pswitch_9
    check-cast v0, Ln1/v;

    .line 415
    .line 416
    check-cast v1, Ljava/lang/Float;

    .line 417
    .line 418
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 419
    .line 420
    .line 421
    move-result v1

    .line 422
    neg-float v1, v1

    .line 423
    cmpg-float v2, v1, v8

    .line 424
    .line 425
    if-gez v2, :cond_b

    .line 426
    .line 427
    invoke-virtual {v0}, Ln1/v;->d()Z

    .line 428
    .line 429
    .line 430
    move-result v2

    .line 431
    if-eqz v2, :cond_14

    .line 432
    .line 433
    :cond_b
    cmpl-float v2, v1, v8

    .line 434
    .line 435
    if-lez v2, :cond_c

    .line 436
    .line 437
    invoke-virtual {v0}, Ln1/v;->b()Z

    .line 438
    .line 439
    .line 440
    move-result v2

    .line 441
    if-nez v2, :cond_c

    .line 442
    .line 443
    goto/16 :goto_a

    .line 444
    .line 445
    :cond_c
    iget v2, v0, Ln1/v;->g:F

    .line 446
    .line 447
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 448
    .line 449
    .line 450
    move-result v2

    .line 451
    cmpg-float v2, v2, v4

    .line 452
    .line 453
    if-gtz v2, :cond_d

    .line 454
    .line 455
    goto :goto_7

    .line 456
    :cond_d
    invoke-static {v3}, Lj1/b;->c(Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    :goto_7
    iget v2, v0, Ln1/v;->g:F

    .line 460
    .line 461
    add-float/2addr v2, v1

    .line 462
    iput v2, v0, Ln1/v;->g:F

    .line 463
    .line 464
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 465
    .line 466
    .line 467
    move-result v2

    .line 468
    cmpl-float v2, v2, v4

    .line 469
    .line 470
    if-lez v2, :cond_12

    .line 471
    .line 472
    iget v2, v0, Ln1/v;->g:F

    .line 473
    .line 474
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 475
    .line 476
    .line 477
    move-result v3

    .line 478
    iget-object v5, v0, Ln1/v;->e:Ll2/j1;

    .line 479
    .line 480
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v5

    .line 484
    check-cast v5, Ln1/n;

    .line 485
    .line 486
    iget-boolean v6, v0, Ln1/v;->b:Z

    .line 487
    .line 488
    xor-int/2addr v6, v11

    .line 489
    invoke-virtual {v5, v3, v6}, Ln1/n;->a(IZ)Ln1/n;

    .line 490
    .line 491
    .line 492
    move-result-object v5

    .line 493
    if-eqz v5, :cond_e

    .line 494
    .line 495
    iget-object v6, v0, Ln1/v;->c:Ln1/n;

    .line 496
    .line 497
    if-eqz v6, :cond_e

    .line 498
    .line 499
    invoke-virtual {v6, v3, v11}, Ln1/n;->a(IZ)Ln1/n;

    .line 500
    .line 501
    .line 502
    move-result-object v3

    .line 503
    if-eqz v3, :cond_f

    .line 504
    .line 505
    iput-object v3, v0, Ln1/v;->c:Ln1/n;

    .line 506
    .line 507
    :cond_e
    move-object v9, v5

    .line 508
    :cond_f
    if-eqz v9, :cond_10

    .line 509
    .line 510
    iget-boolean v3, v0, Ln1/v;->b:Z

    .line 511
    .line 512
    invoke-virtual {v0, v9, v3, v11}, Ln1/v;->f(Ln1/n;ZZ)V

    .line 513
    .line 514
    .line 515
    iget-object v3, v0, Ln1/v;->r:Ll2/b1;

    .line 516
    .line 517
    invoke-interface {v3, v12}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 518
    .line 519
    .line 520
    iget v3, v0, Ln1/v;->g:F

    .line 521
    .line 522
    sub-float/2addr v2, v3

    .line 523
    invoke-virtual {v0, v2, v9}, Ln1/v;->h(FLn1/n;)V

    .line 524
    .line 525
    .line 526
    goto :goto_8

    .line 527
    :cond_10
    iget-object v3, v0, Ln1/v;->j:Lv3/h0;

    .line 528
    .line 529
    if-eqz v3, :cond_11

    .line 530
    .line 531
    invoke-virtual {v3}, Lv3/h0;->l()V

    .line 532
    .line 533
    .line 534
    :cond_11
    iget v3, v0, Ln1/v;->g:F

    .line 535
    .line 536
    sub-float/2addr v2, v3

    .line 537
    invoke-virtual {v0}, Ln1/v;->g()Ln1/n;

    .line 538
    .line 539
    .line 540
    move-result-object v3

    .line 541
    invoke-virtual {v0, v2, v3}, Ln1/v;->h(FLn1/n;)V

    .line 542
    .line 543
    .line 544
    :cond_12
    :goto_8
    iget v2, v0, Ln1/v;->g:F

    .line 545
    .line 546
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 547
    .line 548
    .line 549
    move-result v2

    .line 550
    cmpg-float v2, v2, v4

    .line 551
    .line 552
    if-gtz v2, :cond_13

    .line 553
    .line 554
    :goto_9
    move v8, v1

    .line 555
    goto :goto_a

    .line 556
    :cond_13
    iget v2, v0, Ln1/v;->g:F

    .line 557
    .line 558
    sub-float/2addr v1, v2

    .line 559
    iput v8, v0, Ln1/v;->g:F

    .line 560
    .line 561
    goto :goto_9

    .line 562
    :cond_14
    :goto_a
    neg-float v0, v8

    .line 563
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 564
    .line 565
    .line 566
    move-result-object v0

    .line 567
    return-object v0

    .line 568
    :pswitch_a
    check-cast v0, Lca/m;

    .line 569
    .line 570
    check-cast v1, Ljava/lang/Integer;

    .line 571
    .line 572
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 573
    .line 574
    .line 575
    move-result v1

    .line 576
    invoke-virtual {v0, v1}, Lca/m;->i(I)I

    .line 577
    .line 578
    .line 579
    move-result v0

    .line 580
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 581
    .line 582
    .line 583
    move-result-object v0

    .line 584
    return-object v0

    .line 585
    :pswitch_b
    check-cast v0, Lmx0/f;

    .line 586
    .line 587
    check-cast v1, Ljava/util/Map$Entry;

    .line 588
    .line 589
    const-string v2, "it"

    .line 590
    .line 591
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    new-instance v2, Ljava/lang/StringBuilder;

    .line 595
    .line 596
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 597
    .line 598
    .line 599
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    move-result-object v3

    .line 603
    const-string v4, "(this Map)"

    .line 604
    .line 605
    if-ne v3, v0, :cond_15

    .line 606
    .line 607
    move-object v3, v4

    .line 608
    goto :goto_b

    .line 609
    :cond_15
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 610
    .line 611
    .line 612
    move-result-object v3

    .line 613
    :goto_b
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 614
    .line 615
    .line 616
    const/16 v3, 0x3d

    .line 617
    .line 618
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 619
    .line 620
    .line 621
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v1

    .line 625
    if-ne v1, v0, :cond_16

    .line 626
    .line 627
    goto :goto_c

    .line 628
    :cond_16
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 629
    .line 630
    .line 631
    move-result-object v4

    .line 632
    :goto_c
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 633
    .line 634
    .line 635
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 636
    .line 637
    .line 638
    move-result-object v0

    .line 639
    return-object v0

    .line 640
    :pswitch_c
    check-cast v0, Lmx0/a;

    .line 641
    .line 642
    if-ne v1, v0, :cond_17

    .line 643
    .line 644
    const-string v0, "(this Collection)"

    .line 645
    .line 646
    goto :goto_d

    .line 647
    :cond_17
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 648
    .line 649
    .line 650
    move-result-object v0

    .line 651
    :goto_d
    return-object v0

    .line 652
    :pswitch_d
    check-cast v0, Lkotlin/jvm/internal/d0;

    .line 653
    .line 654
    check-cast v1, Lip0/c;

    .line 655
    .line 656
    new-instance v2, Ljava/lang/StringBuilder;

    .line 657
    .line 658
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 659
    .line 660
    .line 661
    iget v3, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 662
    .line 663
    add-int/lit8 v4, v3, 0x1

    .line 664
    .line 665
    iput v4, v0, Lkotlin/jvm/internal/d0;->d:I

    .line 666
    .line 667
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 668
    .line 669
    .line 670
    const/16 v0, 0x3a

    .line 671
    .line 672
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 673
    .line 674
    .line 675
    iget-object v0, v1, Lip0/c;->a:Ljava/lang/String;

    .line 676
    .line 677
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 678
    .line 679
    .line 680
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 681
    .line 682
    .line 683
    move-result-object v0

    .line 684
    return-object v0

    .line 685
    :pswitch_e
    check-cast v0, Lhg/b;

    .line 686
    .line 687
    check-cast v1, Lm1/f;

    .line 688
    .line 689
    const-string v2, "$this$LazyColumn"

    .line 690
    .line 691
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 692
    .line 693
    .line 694
    sget-object v2, Lmk/a;->d:Lt2/b;

    .line 695
    .line 696
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 697
    .line 698
    .line 699
    sget-object v2, Lmk/a;->e:Lt2/b;

    .line 700
    .line 701
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 702
    .line 703
    .line 704
    sget-object v2, Lmk/a;->f:Lt2/b;

    .line 705
    .line 706
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 707
    .line 708
    .line 709
    sget-object v2, Lmk/a;->g:Lt2/b;

    .line 710
    .line 711
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 712
    .line 713
    .line 714
    iget-boolean v2, v0, Lhg/b;->g:Z

    .line 715
    .line 716
    if-eqz v2, :cond_18

    .line 717
    .line 718
    sget-object v2, Lmk/a;->h:Lt2/b;

    .line 719
    .line 720
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 721
    .line 722
    .line 723
    sget-object v2, Lmk/a;->i:Lt2/b;

    .line 724
    .line 725
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 726
    .line 727
    .line 728
    :cond_18
    iget-object v2, v0, Lhg/b;->a:Ljava/util/ArrayList;

    .line 729
    .line 730
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 731
    .line 732
    .line 733
    move-result-object v2

    .line 734
    :goto_e
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 735
    .line 736
    .line 737
    move-result v3

    .line 738
    if-eqz v3, :cond_19

    .line 739
    .line 740
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 741
    .line 742
    .line 743
    move-result-object v3

    .line 744
    check-cast v3, Lhg/a;

    .line 745
    .line 746
    new-instance v4, Lkv0/d;

    .line 747
    .line 748
    invoke-direct {v4, v3, v6}, Lkv0/d;-><init>(Ljava/lang/Object;I)V

    .line 749
    .line 750
    .line 751
    new-instance v3, Lt2/b;

    .line 752
    .line 753
    const v7, 0x28b6ea78

    .line 754
    .line 755
    .line 756
    invoke-direct {v3, v4, v11, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 757
    .line 758
    .line 759
    invoke-static {v1, v3, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 760
    .line 761
    .line 762
    goto :goto_e

    .line 763
    :cond_19
    sget-object v2, Lmk/a;->a:Lt2/b;

    .line 764
    .line 765
    invoke-static {v1, v2, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 766
    .line 767
    .line 768
    iget-boolean v2, v0, Lhg/b;->e:Z

    .line 769
    .line 770
    if-eqz v2, :cond_1a

    .line 771
    .line 772
    new-instance v2, Lkv0/d;

    .line 773
    .line 774
    invoke-direct {v2, v0, v5}, Lkv0/d;-><init>(Ljava/lang/Object;I)V

    .line 775
    .line 776
    .line 777
    new-instance v0, Lt2/b;

    .line 778
    .line 779
    const v3, 0x36992d69

    .line 780
    .line 781
    .line 782
    invoke-direct {v0, v2, v11, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 783
    .line 784
    .line 785
    invoke-static {v1, v0, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 786
    .line 787
    .line 788
    sget-object v0, Lmk/a;->b:Lt2/b;

    .line 789
    .line 790
    invoke-static {v1, v0, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 791
    .line 792
    .line 793
    :cond_1a
    sget-object v0, Lmk/a;->c:Lt2/b;

    .line 794
    .line 795
    invoke-static {v1, v0, v6}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 796
    .line 797
    .line 798
    return-object v12

    .line 799
    :pswitch_f
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 800
    .line 801
    check-cast v1, Lua/a;

    .line 802
    .line 803
    const-string v2, "_connection"

    .line 804
    .line 805
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 806
    .line 807
    .line 808
    const-string v2, "DELETE FROM app_log WHERE timestamp < ?"

    .line 809
    .line 810
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 811
    .line 812
    .line 813
    move-result-object v1

    .line 814
    :try_start_0
    invoke-static {v0}, Lvo/a;->l(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 815
    .line 816
    .line 817
    move-result-object v0

    .line 818
    invoke-interface {v1, v11, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 819
    .line 820
    .line 821
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 822
    .line 823
    .line 824
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 825
    .line 826
    .line 827
    return-object v12

    .line 828
    :catchall_0
    move-exception v0

    .line 829
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 830
    .line 831
    .line 832
    throw v0

    .line 833
    :pswitch_10
    check-cast v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;

    .line 834
    .line 835
    check-cast v1, Lgi/c;

    .line 836
    .line 837
    invoke-virtual {v0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse$ApiError;->getCode()I

    .line 838
    .line 839
    .line 840
    move-result v0

    .line 841
    const-string v1, "APIErrorCode "

    .line 842
    .line 843
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 844
    .line 845
    .line 846
    move-result-object v0

    .line 847
    return-object v0

    .line 848
    :pswitch_11
    check-cast v0, Lnc/z;

    .line 849
    .line 850
    check-cast v1, Lgi/c;

    .line 851
    .line 852
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 853
    .line 854
    .line 855
    iget-object v0, v0, Lnc/z;->h:Ljava/lang/String;

    .line 856
    .line 857
    const-string v1, "Successful response: Display Name "

    .line 858
    .line 859
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 860
    .line 861
    .line 862
    move-result-object v0

    .line 863
    return-object v0

    .line 864
    :pswitch_12
    check-cast v0, Lmc/j;

    .line 865
    .line 866
    check-cast v1, Lgi/c;

    .line 867
    .line 868
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 869
    .line 870
    .line 871
    iget-object v0, v0, Lmc/j;->a:Lmc/y;

    .line 872
    .line 873
    new-instance v1, Ljava/lang/StringBuilder;

    .line 874
    .line 875
    const-string v2, "onPaymentTypeSelected. "

    .line 876
    .line 877
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 878
    .line 879
    .line 880
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 881
    .line 882
    .line 883
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 884
    .line 885
    .line 886
    move-result-object v0

    .line 887
    return-object v0

    .line 888
    :pswitch_13
    check-cast v0, Lmc/i;

    .line 889
    .line 890
    check-cast v1, Lgi/c;

    .line 891
    .line 892
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 893
    .line 894
    .line 895
    iget-object v0, v0, Lmc/i;->a:Ljava/lang/String;

    .line 896
    .line 897
    const-string v1, "onError. "

    .line 898
    .line 899
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 900
    .line 901
    .line 902
    move-result-object v0

    .line 903
    return-object v0

    .line 904
    :pswitch_14
    check-cast v0, Lmc/k;

    .line 905
    .line 906
    check-cast v1, Lgi/c;

    .line 907
    .line 908
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 909
    .line 910
    .line 911
    new-instance v1, Ljava/lang/StringBuilder;

    .line 912
    .line 913
    const-string v2, "onSuccess. "

    .line 914
    .line 915
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 916
    .line 917
    .line 918
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 919
    .line 920
    .line 921
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 922
    .line 923
    .line 924
    move-result-object v0

    .line 925
    return-object v0

    .line 926
    :pswitch_15
    check-cast v0, Lmc/p;

    .line 927
    .line 928
    check-cast v1, Lgi/c;

    .line 929
    .line 930
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 931
    .line 932
    .line 933
    iget-object v0, v0, Lmc/p;->j:Lyy0/c2;

    .line 934
    .line 935
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move-result-object v0

    .line 939
    const-string v1, "onBackClick. selectedProvider is "

    .line 940
    .line 941
    invoke-static {v0, v1}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 942
    .line 943
    .line 944
    move-result-object v0

    .line 945
    return-object v0

    .line 946
    :pswitch_16
    check-cast v0, Lmc/t;

    .line 947
    .line 948
    check-cast v1, Lgi/c;

    .line 949
    .line 950
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 951
    .line 952
    .line 953
    iget-boolean v1, v0, Lmc/t;->c:Z

    .line 954
    .line 955
    if-eqz v1, :cond_1b

    .line 956
    .line 957
    const-string v0, "onEventHandled. executeSubmit"

    .line 958
    .line 959
    goto :goto_f

    .line 960
    :cond_1b
    iget-boolean v0, v0, Lmc/t;->d:Z

    .line 961
    .line 962
    if-eqz v0, :cond_1c

    .line 963
    .line 964
    const-string v0, "onEventHandled. executeHideForm"

    .line 965
    .line 966
    goto :goto_f

    .line 967
    :cond_1c
    const-string v0, "onEventHandled. unknown"

    .line 968
    .line 969
    :goto_f
    return-object v0

    .line 970
    :pswitch_17
    check-cast v0, Lmc/h;

    .line 971
    .line 972
    check-cast v1, Lgi/c;

    .line 973
    .line 974
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 975
    .line 976
    .line 977
    iget-object v1, v0, Lmc/h;->a:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;

    .line 978
    .line 979
    if-eqz v1, :cond_1d

    .line 980
    .line 981
    invoke-virtual {v1}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->getPaymentOptionCode()Ljava/lang/String;

    .line 982
    .line 983
    .line 984
    move-result-object v1

    .line 985
    goto :goto_10

    .line 986
    :cond_1d
    move-object v1, v9

    .line 987
    :goto_10
    iget-object v0, v0, Lmc/h;->a:Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;

    .line 988
    .line 989
    if-eqz v0, :cond_1e

    .line 990
    .line 991
    invoke-virtual {v0}, Lcom/contoworks/kontocloud/uicomponents/widget/PaymentForm$OnSubmitCallback$OnBeforeSubmitArgs;->getData()Ljava/util/Map;

    .line 992
    .line 993
    .line 994
    move-result-object v9

    .line 995
    :cond_1e
    new-instance v0, Ljava/lang/StringBuilder;

    .line 996
    .line 997
    const-string v2, "onBeforeSubmit. "

    .line 998
    .line 999
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1000
    .line 1001
    .line 1002
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1003
    .line 1004
    .line 1005
    const-string v1, "/"

    .line 1006
    .line 1007
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1008
    .line 1009
    .line 1010
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1011
    .line 1012
    .line 1013
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v0

    .line 1017
    return-object v0

    .line 1018
    :pswitch_18
    check-cast v0, Ll70/d;

    .line 1019
    .line 1020
    check-cast v1, Lm70/j;

    .line 1021
    .line 1022
    const-string v2, "row"

    .line 1023
    .line 1024
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1025
    .line 1026
    .line 1027
    iget-object v1, v1, Lm70/j;->a:Ll70/d;

    .line 1028
    .line 1029
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1030
    .line 1031
    .line 1032
    move-result v0

    .line 1033
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1034
    .line 1035
    .line 1036
    move-result-object v0

    .line 1037
    return-object v0

    .line 1038
    :pswitch_19
    check-cast v0, Lm1/t;

    .line 1039
    .line 1040
    check-cast v1, Ljava/lang/Float;

    .line 1041
    .line 1042
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1043
    .line 1044
    .line 1045
    move-result v1

    .line 1046
    neg-float v1, v1

    .line 1047
    cmpg-float v2, v1, v8

    .line 1048
    .line 1049
    if-gez v2, :cond_1f

    .line 1050
    .line 1051
    invoke-virtual {v0}, Lm1/t;->d()Z

    .line 1052
    .line 1053
    .line 1054
    move-result v2

    .line 1055
    if-eqz v2, :cond_28

    .line 1056
    .line 1057
    :cond_1f
    cmpl-float v2, v1, v8

    .line 1058
    .line 1059
    if-lez v2, :cond_20

    .line 1060
    .line 1061
    invoke-virtual {v0}, Lm1/t;->b()Z

    .line 1062
    .line 1063
    .line 1064
    move-result v2

    .line 1065
    if-nez v2, :cond_20

    .line 1066
    .line 1067
    goto/16 :goto_14

    .line 1068
    .line 1069
    :cond_20
    iget v2, v0, Lm1/t;->h:F

    .line 1070
    .line 1071
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 1072
    .line 1073
    .line 1074
    move-result v2

    .line 1075
    cmpg-float v2, v2, v4

    .line 1076
    .line 1077
    if-gtz v2, :cond_21

    .line 1078
    .line 1079
    goto :goto_11

    .line 1080
    :cond_21
    invoke-static {v3}, Lj1/b;->c(Ljava/lang/String;)V

    .line 1081
    .line 1082
    .line 1083
    :goto_11
    iput-boolean v11, v0, Lm1/t;->d:Z

    .line 1084
    .line 1085
    iget v2, v0, Lm1/t;->h:F

    .line 1086
    .line 1087
    add-float/2addr v2, v1

    .line 1088
    iput v2, v0, Lm1/t;->h:F

    .line 1089
    .line 1090
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 1091
    .line 1092
    .line 1093
    move-result v2

    .line 1094
    cmpl-float v2, v2, v4

    .line 1095
    .line 1096
    if-lez v2, :cond_26

    .line 1097
    .line 1098
    iget v2, v0, Lm1/t;->h:F

    .line 1099
    .line 1100
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 1101
    .line 1102
    .line 1103
    move-result v3

    .line 1104
    iget-object v5, v0, Lm1/t;->f:Ll2/j1;

    .line 1105
    .line 1106
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v5

    .line 1110
    check-cast v5, Lm1/l;

    .line 1111
    .line 1112
    iget-boolean v6, v0, Lm1/t;->b:Z

    .line 1113
    .line 1114
    xor-int/2addr v6, v11

    .line 1115
    invoke-virtual {v5, v3, v6}, Lm1/l;->a(IZ)Lm1/l;

    .line 1116
    .line 1117
    .line 1118
    move-result-object v5

    .line 1119
    if-eqz v5, :cond_22

    .line 1120
    .line 1121
    iget-object v6, v0, Lm1/t;->c:Lm1/l;

    .line 1122
    .line 1123
    if-eqz v6, :cond_22

    .line 1124
    .line 1125
    invoke-virtual {v6, v3, v11}, Lm1/l;->a(IZ)Lm1/l;

    .line 1126
    .line 1127
    .line 1128
    move-result-object v3

    .line 1129
    if-eqz v3, :cond_23

    .line 1130
    .line 1131
    iput-object v3, v0, Lm1/t;->c:Lm1/l;

    .line 1132
    .line 1133
    :cond_22
    move-object v9, v5

    .line 1134
    :cond_23
    if-eqz v9, :cond_24

    .line 1135
    .line 1136
    iget-boolean v3, v0, Lm1/t;->b:Z

    .line 1137
    .line 1138
    invoke-virtual {v0, v9, v3, v11}, Lm1/t;->g(Lm1/l;ZZ)V

    .line 1139
    .line 1140
    .line 1141
    iget-object v3, v0, Lm1/t;->v:Ll2/b1;

    .line 1142
    .line 1143
    invoke-interface {v3, v12}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1144
    .line 1145
    .line 1146
    iget v3, v0, Lm1/t;->h:F

    .line 1147
    .line 1148
    sub-float/2addr v2, v3

    .line 1149
    invoke-virtual {v0, v2, v9}, Lm1/t;->i(FLm1/l;)V

    .line 1150
    .line 1151
    .line 1152
    goto :goto_12

    .line 1153
    :cond_24
    iget-object v3, v0, Lm1/t;->k:Lv3/h0;

    .line 1154
    .line 1155
    if-eqz v3, :cond_25

    .line 1156
    .line 1157
    invoke-virtual {v3}, Lv3/h0;->l()V

    .line 1158
    .line 1159
    .line 1160
    :cond_25
    iget v3, v0, Lm1/t;->h:F

    .line 1161
    .line 1162
    sub-float/2addr v2, v3

    .line 1163
    invoke-virtual {v0}, Lm1/t;->h()Lm1/l;

    .line 1164
    .line 1165
    .line 1166
    move-result-object v3

    .line 1167
    invoke-virtual {v0, v2, v3}, Lm1/t;->i(FLm1/l;)V

    .line 1168
    .line 1169
    .line 1170
    :cond_26
    :goto_12
    iget v2, v0, Lm1/t;->h:F

    .line 1171
    .line 1172
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 1173
    .line 1174
    .line 1175
    move-result v2

    .line 1176
    cmpg-float v2, v2, v4

    .line 1177
    .line 1178
    if-gtz v2, :cond_27

    .line 1179
    .line 1180
    :goto_13
    move v8, v1

    .line 1181
    goto :goto_14

    .line 1182
    :cond_27
    iget v2, v0, Lm1/t;->h:F

    .line 1183
    .line 1184
    sub-float/2addr v1, v2

    .line 1185
    iput v8, v0, Lm1/t;->h:F

    .line 1186
    .line 1187
    goto :goto_13

    .line 1188
    :cond_28
    :goto_14
    neg-float v0, v8

    .line 1189
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v0

    .line 1193
    return-object v0

    .line 1194
    :pswitch_1a
    check-cast v0, Lm1/i;

    .line 1195
    .line 1196
    check-cast v1, Ljava/lang/Integer;

    .line 1197
    .line 1198
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1199
    .line 1200
    .line 1201
    move-result v1

    .line 1202
    iget-wide v2, v0, Lm1/i;->h:J

    .line 1203
    .line 1204
    invoke-virtual {v0, v1, v2, v3}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1205
    .line 1206
    .line 1207
    move-result-object v0

    .line 1208
    return-object v0

    .line 1209
    :pswitch_1b
    check-cast v0, Lly0/k;

    .line 1210
    .line 1211
    check-cast v1, Ljava/lang/Integer;

    .line 1212
    .line 1213
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1214
    .line 1215
    .line 1216
    move-result v1

    .line 1217
    invoke-virtual {v0, v1}, Lly0/k;->e(I)Lly0/i;

    .line 1218
    .line 1219
    .line 1220
    move-result-object v0

    .line 1221
    return-object v0

    .line 1222
    :pswitch_1c
    check-cast v0, Lla/r;

    .line 1223
    .line 1224
    check-cast v1, Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 1225
    .line 1226
    const-string v2, "db"

    .line 1227
    .line 1228
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1229
    .line 1230
    .line 1231
    iput-object v1, v0, Lla/r;->h:Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 1232
    .line 1233
    return-object v12

    .line 1234
    nop

    .line 1235
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
