.class public final Lyk0/p;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Lyk0/q;

.field public final synthetic f:Lbl0/h0;

.field public final synthetic g:Lxj0/f;

.field public final synthetic h:I

.field public final synthetic i:Lbl0/h;


# direct methods
.method public constructor <init>(Lyk0/q;Lbl0/h0;Lxj0/f;ILbl0/h;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lyk0/p;->e:Lyk0/q;

    .line 2
    .line 3
    iput-object p2, p0, Lyk0/p;->f:Lbl0/h0;

    .line 4
    .line 5
    iput-object p3, p0, Lyk0/p;->g:Lxj0/f;

    .line 6
    .line 7
    iput p4, p0, Lyk0/p;->h:I

    .line 8
    .line 9
    iput-object p5, p0, Lyk0/p;->i:Lbl0/h;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Lyk0/p;

    .line 2
    .line 3
    iget v4, p0, Lyk0/p;->h:I

    .line 4
    .line 5
    iget-object v5, p0, Lyk0/p;->i:Lbl0/h;

    .line 6
    .line 7
    iget-object v1, p0, Lyk0/p;->e:Lyk0/q;

    .line 8
    .line 9
    iget-object v2, p0, Lyk0/p;->f:Lbl0/h0;

    .line 10
    .line 11
    iget-object v3, p0, Lyk0/p;->g:Lxj0/f;

    .line 12
    .line 13
    move-object v6, p1

    .line 14
    invoke-direct/range {v0 .. v6}, Lyk0/p;-><init>(Lyk0/q;Lbl0/h0;Lxj0/f;ILbl0/h;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lyk0/p;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lyk0/p;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lyk0/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lyk0/p;->d:I

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    const/4 v4, 0x1

    .line 9
    if-eqz v2, :cond_2

    .line 10
    .line 11
    if-eq v2, v4, :cond_1

    .line 12
    .line 13
    if-ne v2, v3, :cond_0

    .line 14
    .line 15
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-object p1

    .line 19
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw v0

    .line 27
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    move-object/from16 v2, p1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object v2, v0, Lyk0/p;->e:Lyk0/q;

    .line 37
    .line 38
    iget-object v2, v2, Lyk0/q;->b:Lti0/a;

    .line 39
    .line 40
    iput v4, v0, Lyk0/p;->d:I

    .line 41
    .line 42
    invoke-interface {v2, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    if-ne v2, v1, :cond_3

    .line 47
    .line 48
    goto/16 :goto_e

    .line 49
    .line 50
    :cond_3
    :goto_0
    check-cast v2, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 51
    .line 52
    iget-object v5, v0, Lyk0/p;->f:Lbl0/h0;

    .line 53
    .line 54
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    packed-switch v6, :pswitch_data_0

    .line 59
    .line 60
    .line 61
    new-instance v0, La8/r0;

    .line 62
    .line 63
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :pswitch_0
    const-string v6, "SERVICE"

    .line 68
    .line 69
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    goto :goto_1

    .line 74
    :pswitch_1
    const-string v6, "HOTEL"

    .line 75
    .line 76
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    goto :goto_1

    .line 81
    :pswitch_2
    const-string v6, "RESTAURANT"

    .line 82
    .line 83
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    goto :goto_1

    .line 88
    :pswitch_3
    const-string v6, "PAY_PARKING"

    .line 89
    .line 90
    const-string v7, "PAY_PARKING_ZONE"

    .line 91
    .line 92
    filled-new-array {v6, v7}, [Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    invoke-static {v6}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 97
    .line 98
    .line 99
    move-result-object v6

    .line 100
    goto :goto_1

    .line 101
    :pswitch_4
    const-string v6, "PARKING"

    .line 102
    .line 103
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    goto :goto_1

    .line 108
    :pswitch_5
    const-string v6, "PAY_GAS_STATION"

    .line 109
    .line 110
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    goto :goto_1

    .line 115
    :pswitch_6
    const-string v6, "GAS_STATION"

    .line 116
    .line 117
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 118
    .line 119
    .line 120
    move-result-object v6

    .line 121
    goto :goto_1

    .line 122
    :pswitch_7
    const-string v6, "CHARGING_STATION"

    .line 123
    .line 124
    invoke-static {v6}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    :goto_1
    new-instance v7, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 129
    .line 130
    iget-object v8, v0, Lyk0/p;->g:Lxj0/f;

    .line 131
    .line 132
    iget-wide v9, v8, Lxj0/f;->a:D

    .line 133
    .line 134
    iget-wide v11, v8, Lxj0/f;->b:D

    .line 135
    .line 136
    invoke-direct {v7, v9, v10, v11, v12}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 137
    .line 138
    .line 139
    const/16 v8, 0xa

    .line 140
    .line 141
    const/4 v9, 0x3

    .line 142
    iget-object v10, v0, Lyk0/p;->i:Lbl0/h;

    .line 143
    .line 144
    if-eqz v10, :cond_16

    .line 145
    .line 146
    iget-object v12, v10, Lbl0/h;->a:Lbl0/e;

    .line 147
    .line 148
    iget-object v13, v10, Lbl0/h;->e:Ljava/util/List;

    .line 149
    .line 150
    iget-object v14, v12, Lbl0/e;->a:Lbl0/g;

    .line 151
    .line 152
    sget-object v15, Lbl0/g;->e:Lbl0/g;

    .line 153
    .line 154
    if-eq v14, v15, :cond_4

    .line 155
    .line 156
    iget v14, v14, Lbl0/g;->d:I

    .line 157
    .line 158
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 159
    .line 160
    .line 161
    move-result-object v14

    .line 162
    move-object/from16 v16, v14

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_4
    const/16 v16, 0x0

    .line 166
    .line 167
    :goto_2
    iget-object v12, v12, Lbl0/e;->b:Lbl0/g;

    .line 168
    .line 169
    sget-object v14, Lbl0/g;->h:Lbl0/g;

    .line 170
    .line 171
    if-eq v12, v14, :cond_5

    .line 172
    .line 173
    iget v12, v12, Lbl0/g;->d:I

    .line 174
    .line 175
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 176
    .line 177
    .line 178
    move-result-object v12

    .line 179
    move-object/from16 v17, v12

    .line 180
    .line 181
    goto :goto_3

    .line 182
    :cond_5
    const/16 v17, 0x0

    .line 183
    .line 184
    :goto_3
    iget-boolean v12, v10, Lbl0/h;->b:Z

    .line 185
    .line 186
    invoke-static {v12}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 187
    .line 188
    .line 189
    move-result-object v18

    .line 190
    iget-object v12, v10, Lbl0/h;->d:Ljava/util/List;

    .line 191
    .line 192
    check-cast v12, Ljava/lang/Iterable;

    .line 193
    .line 194
    new-instance v14, Ljava/util/ArrayList;

    .line 195
    .line 196
    invoke-static {v12, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 197
    .line 198
    .line 199
    move-result v15

    .line 200
    invoke-direct {v14, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 201
    .line 202
    .line 203
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 204
    .line 205
    .line 206
    move-result-object v12

    .line 207
    :goto_4
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 208
    .line 209
    .line 210
    move-result v15

    .line 211
    if-eqz v15, :cond_a

    .line 212
    .line 213
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v15

    .line 217
    check-cast v15, Lbl0/c;

    .line 218
    .line 219
    invoke-virtual {v15}, Ljava/lang/Enum;->ordinal()I

    .line 220
    .line 221
    .line 222
    move-result v15

    .line 223
    if-eqz v15, :cond_9

    .line 224
    .line 225
    if-eq v15, v4, :cond_8

    .line 226
    .line 227
    if-eq v15, v3, :cond_7

    .line 228
    .line 229
    if-ne v15, v9, :cond_6

    .line 230
    .line 231
    const-string v15, "ONLINE"

    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_6
    new-instance v0, La8/r0;

    .line 235
    .line 236
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 237
    .line 238
    .line 239
    throw v0

    .line 240
    :cond_7
    const-string v15, "PLUG_AND_CHARGE"

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_8
    const-string v15, "ELLI_REMOTE"

    .line 244
    .line 245
    goto :goto_5

    .line 246
    :cond_9
    const-string v15, "RFID"

    .line 247
    .line 248
    :goto_5
    invoke-virtual {v14, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    goto :goto_4

    .line 252
    :cond_a
    check-cast v13, Ljava/lang/Iterable;

    .line 253
    .line 254
    new-instance v12, Ljava/util/ArrayList;

    .line 255
    .line 256
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 257
    .line 258
    .line 259
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 260
    .line 261
    .line 262
    move-result-object v15

    .line 263
    :goto_6
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 264
    .line 265
    .line 266
    move-result v19

    .line 267
    if-eqz v19, :cond_f

    .line 268
    .line 269
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v19

    .line 273
    check-cast v19, Lbl0/d;

    .line 274
    .line 275
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Enum;->ordinal()I

    .line 276
    .line 277
    .line 278
    move-result v11

    .line 279
    if-eqz v11, :cond_d

    .line 280
    .line 281
    if-eq v11, v4, :cond_d

    .line 282
    .line 283
    if-eq v11, v3, :cond_c

    .line 284
    .line 285
    if-ne v11, v9, :cond_b

    .line 286
    .line 287
    const-string v11, "IONITY"

    .line 288
    .line 289
    invoke-static {v11}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 290
    .line 291
    .line 292
    move-result-object v11

    .line 293
    goto :goto_7

    .line 294
    :cond_b
    new-instance v0, La8/r0;

    .line 295
    .line 296
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 297
    .line 298
    .line 299
    throw v0

    .line 300
    :cond_c
    const-string v11, "BP"

    .line 301
    .line 302
    const-string v8, "ARAL"

    .line 303
    .line 304
    filled-new-array {v11, v8}, [Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v8

    .line 308
    invoke-static {v8}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 309
    .line 310
    .line 311
    move-result-object v11

    .line 312
    goto :goto_7

    .line 313
    :cond_d
    const/4 v11, 0x0

    .line 314
    :goto_7
    if-eqz v11, :cond_e

    .line 315
    .line 316
    invoke-virtual {v12, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 317
    .line 318
    .line 319
    :cond_e
    const/16 v8, 0xa

    .line 320
    .line 321
    goto :goto_6

    .line 322
    :cond_f
    invoke-static {v12}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 323
    .line 324
    .line 325
    move-result-object v20

    .line 326
    new-instance v8, Ljava/util/ArrayList;

    .line 327
    .line 328
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 329
    .line 330
    .line 331
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 332
    .line 333
    .line 334
    move-result-object v11

    .line 335
    :cond_10
    :goto_8
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 336
    .line 337
    .line 338
    move-result v12

    .line 339
    if-eqz v12, :cond_15

    .line 340
    .line 341
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v12

    .line 345
    check-cast v12, Lbl0/d;

    .line 346
    .line 347
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 348
    .line 349
    .line 350
    move-result v12

    .line 351
    if-eqz v12, :cond_14

    .line 352
    .line 353
    if-eq v12, v4, :cond_13

    .line 354
    .line 355
    if-eq v12, v3, :cond_11

    .line 356
    .line 357
    if-ne v12, v9, :cond_12

    .line 358
    .line 359
    :cond_11
    const/4 v12, 0x0

    .line 360
    goto :goto_9

    .line 361
    :cond_12
    new-instance v0, La8/r0;

    .line 362
    .line 363
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 364
    .line 365
    .line 366
    throw v0

    .line 367
    :cond_13
    const-string v12, "ELLI_SELECTED"

    .line 368
    .line 369
    goto :goto_9

    .line 370
    :cond_14
    const-string v12, "WE_CHARGE"

    .line 371
    .line 372
    :goto_9
    if-eqz v12, :cond_10

    .line 373
    .line 374
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 375
    .line 376
    .line 377
    goto :goto_8

    .line 378
    :cond_15
    new-instance v15, Lcz/myskoda/api/bff_maps/v3/ChargingStationFilterDto;

    .line 379
    .line 380
    move-object/from16 v21, v8

    .line 381
    .line 382
    move-object/from16 v19, v14

    .line 383
    .line 384
    invoke-direct/range {v15 .. v21}, Lcz/myskoda/api/bff_maps/v3/ChargingStationFilterDto;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 385
    .line 386
    .line 387
    goto :goto_a

    .line 388
    :cond_16
    const/4 v15, 0x0

    .line 389
    :goto_a
    sget-object v8, Lbl0/h0;->d:Lbl0/h0;

    .line 390
    .line 391
    if-ne v5, v8, :cond_17

    .line 392
    .line 393
    goto :goto_b

    .line 394
    :cond_17
    const/4 v15, 0x0

    .line 395
    :goto_b
    if-eqz v10, :cond_1c

    .line 396
    .line 397
    iget-object v5, v10, Lbl0/h;->c:Ljava/util/List;

    .line 398
    .line 399
    check-cast v5, Ljava/lang/Iterable;

    .line 400
    .line 401
    new-instance v11, Ljava/util/ArrayList;

    .line 402
    .line 403
    const/16 v8, 0xa

    .line 404
    .line 405
    invoke-static {v5, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 406
    .line 407
    .line 408
    move-result v8

    .line 409
    invoke-direct {v11, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 410
    .line 411
    .line 412
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 413
    .line 414
    .line 415
    move-result-object v5

    .line 416
    :goto_c
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 417
    .line 418
    .line 419
    move-result v8

    .line 420
    if-eqz v8, :cond_1d

    .line 421
    .line 422
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v8

    .line 426
    check-cast v8, Lbl0/b;

    .line 427
    .line 428
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 429
    .line 430
    .line 431
    move-result v8

    .line 432
    if-eqz v8, :cond_1b

    .line 433
    .line 434
    if-eq v8, v4, :cond_1a

    .line 435
    .line 436
    if-eq v8, v3, :cond_19

    .line 437
    .line 438
    if-ne v8, v9, :cond_18

    .line 439
    .line 440
    const-string v8, "PETROL_STATION"

    .line 441
    .line 442
    goto :goto_d

    .line 443
    :cond_18
    new-instance v0, La8/r0;

    .line 444
    .line 445
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 446
    .line 447
    .line 448
    throw v0

    .line 449
    :cond_19
    const-string v8, "ENTERTAINMENT"

    .line 450
    .line 451
    goto :goto_d

    .line 452
    :cond_1a
    const-string v8, "FOOD_AND_DRINK"

    .line 453
    .line 454
    goto :goto_d

    .line 455
    :cond_1b
    const-string v8, "SHOP"

    .line 456
    .line 457
    :goto_d
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 458
    .line 459
    .line 460
    goto :goto_c

    .line 461
    :cond_1c
    const/4 v11, 0x0

    .line 462
    :cond_1d
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 463
    .line 464
    .line 465
    move-result-object v4

    .line 466
    new-instance v5, Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequirementsDto;

    .line 467
    .line 468
    invoke-direct {v5, v15, v11, v4}, Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequirementsDto;-><init>(Lcz/myskoda/api/bff_maps/v3/ChargingStationFilterDto;Ljava/util/List;Ljava/time/OffsetDateTime;)V

    .line 469
    .line 470
    .line 471
    new-instance v4, Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;

    .line 472
    .line 473
    iget v8, v0, Lyk0/p;->h:I

    .line 474
    .line 475
    invoke-direct {v4, v6, v7, v8, v5}, Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;-><init>(Ljava/util/List;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;ILcz/myskoda/api/bff_maps/v3/NearbyPlacesRequirementsDto;)V

    .line 476
    .line 477
    .line 478
    iput v3, v0, Lyk0/p;->d:I

    .line 479
    .line 480
    invoke-interface {v2, v4, v0}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->searchNearbyPlaces(Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    if-ne v0, v1, :cond_1e

    .line 485
    .line 486
    :goto_e
    return-object v1

    .line 487
    :cond_1e
    return-object v0

    .line 488
    nop

    .line 489
    :pswitch_data_0
    .packed-switch 0x0
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
