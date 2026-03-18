.class public final synthetic Lxc/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lxc/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxc/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lxc/b;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lxc/b;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lxc/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v10, v1

    .line 11
    check-cast v10, Lyy0/l1;

    .line 12
    .line 13
    iget-object v1, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v1

    .line 16
    check-cast v3, Lxh/e;

    .line 17
    .line 18
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v4, v0

    .line 21
    check-cast v4, Lxh/e;

    .line 22
    .line 23
    move-object/from16 v0, p1

    .line 24
    .line 25
    check-cast v0, Lhi/a;

    .line 26
    .line 27
    const-string v1, "$this$sdkViewModel"

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-class v1, Luc/g;

    .line 33
    .line 34
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 35
    .line 36
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v0, Lii/a;

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    move-object v13, v0

    .line 47
    check-cast v13, Luc/g;

    .line 48
    .line 49
    new-instance v5, Lz70/u;

    .line 50
    .line 51
    const/16 v17, 0x0

    .line 52
    .line 53
    const/16 v18, 0x8

    .line 54
    .line 55
    const/4 v12, 0x1

    .line 56
    const-class v14, Luc/g;

    .line 57
    .line 58
    const-string v15, "getChargingCards"

    .line 59
    .line 60
    const-string v16, "getChargingCards-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 61
    .line 62
    move-object v11, v5

    .line 63
    invoke-direct/range {v11 .. v18}, Lz70/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 64
    .line 65
    .line 66
    new-instance v6, Lth/b;

    .line 67
    .line 68
    const/16 v18, 0xa

    .line 69
    .line 70
    const/4 v12, 0x2

    .line 71
    const-class v14, Luc/g;

    .line 72
    .line 73
    const-string v15, "activateChargingCard"

    .line 74
    .line 75
    const-string v16, "activateChargingCard-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 76
    .line 77
    move-object v11, v6

    .line 78
    invoke-direct/range {v11 .. v18}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 79
    .line 80
    .line 81
    new-instance v7, Lth/b;

    .line 82
    .line 83
    const/16 v18, 0xb

    .line 84
    .line 85
    const-class v14, Luc/g;

    .line 86
    .line 87
    const-string v15, "deactivateChargingCard"

    .line 88
    .line 89
    const-string v16, "deactivateChargingCard-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 90
    .line 91
    move-object v11, v7

    .line 92
    invoke-direct/range {v11 .. v18}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 93
    .line 94
    .line 95
    new-instance v8, Lth/b;

    .line 96
    .line 97
    const/16 v18, 0xc

    .line 98
    .line 99
    const-class v14, Luc/g;

    .line 100
    .line 101
    const-string v15, "addChargingCard"

    .line 102
    .line 103
    const-string v16, "addChargingCard-gIAlu-s(Lcariad/charging/multicharge/kitten/chargingcard/models/ChargingCardPostRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 104
    .line 105
    move-object v11, v8

    .line 106
    invoke-direct/range {v11 .. v18}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 107
    .line 108
    .line 109
    new-instance v2, Lzc/k;

    .line 110
    .line 111
    new-instance v9, Lyp0/d;

    .line 112
    .line 113
    const/4 v0, 0x7

    .line 114
    invoke-direct {v9, v13, v0}, Lyp0/d;-><init>(Ljava/lang/Object;I)V

    .line 115
    .line 116
    .line 117
    invoke-direct/range {v2 .. v10}, Lzc/k;-><init>(Lxh/e;Lxh/e;Lz70/u;Lth/b;Lth/b;Lth/b;Lyp0/d;Lyy0/l1;)V

    .line 118
    .line 119
    .line 120
    return-object v2

    .line 121
    :pswitch_0
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v1, Lay0/o;

    .line 124
    .line 125
    move-object/from16 v2, p1

    .line 126
    .line 127
    check-cast v2, Lzb/u0;

    .line 128
    .line 129
    const-string v3, "$this$wthReferences"

    .line 130
    .line 131
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    iget-object v2, v2, Lzb/u0;->a:Lz9/y;

    .line 135
    .line 136
    iget-object v3, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 137
    .line 138
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 139
    .line 140
    invoke-interface {v1, v2, v3, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 144
    .line 145
    return-object v0

    .line 146
    :pswitch_1
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v1, Lh/i;

    .line 149
    .line 150
    iget-object v2, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v2, Landroidx/fragment/app/j1;

    .line 153
    .line 154
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v0, Lay0/k;

    .line 157
    .line 158
    move-object/from16 v3, p1

    .line 159
    .line 160
    check-cast v3, Ljava/lang/Long;

    .line 161
    .line 162
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 166
    .line 167
    .line 168
    move-result-wide v3

    .line 169
    invoke-static {v3, v4}, Ljava/time/Instant;->ofEpochMilli(J)Ljava/time/Instant;

    .line 170
    .line 171
    .line 172
    move-result-object v3

    .line 173
    sget-object v4, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 174
    .line 175
    invoke-virtual {v3, v4}, Ljava/time/Instant;->atOffset(Ljava/time/ZoneOffset;)Ljava/time/OffsetDateTime;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    const-string v4, "atOffset(...)"

    .line 180
    .line 181
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    new-instance v4, Lcom/google/android/material/timepicker/l;

    .line 189
    .line 190
    const/4 v5, 0x0

    .line 191
    invoke-direct {v4, v5}, Lcom/google/android/material/timepicker/l;-><init>(I)V

    .line 192
    .line 193
    .line 194
    invoke-static {v1}, Landroid/text/format/DateFormat;->is24HourFormat(Landroid/content/Context;)Z

    .line 195
    .line 196
    .line 197
    move-result v1

    .line 198
    iget v6, v4, Lcom/google/android/material/timepicker/l;->g:I

    .line 199
    .line 200
    iget v4, v4, Lcom/google/android/material/timepicker/l;->h:I

    .line 201
    .line 202
    new-instance v7, Lcom/google/android/material/timepicker/l;

    .line 203
    .line 204
    invoke-direct {v7, v1}, Lcom/google/android/material/timepicker/l;-><init>(I)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v7, v4}, Lcom/google/android/material/timepicker/l;->j(I)V

    .line 208
    .line 209
    .line 210
    const/16 v1, 0xc

    .line 211
    .line 212
    if-lt v6, v1, :cond_0

    .line 213
    .line 214
    const/4 v1, 0x1

    .line 215
    goto :goto_1

    .line 216
    :cond_0
    move v1, v5

    .line 217
    :goto_1
    iput v1, v7, Lcom/google/android/material/timepicker/l;->j:I

    .line 218
    .line 219
    iput v6, v7, Lcom/google/android/material/timepicker/l;->g:I

    .line 220
    .line 221
    new-instance v1, Lcom/google/android/material/timepicker/i;

    .line 222
    .line 223
    invoke-direct {v1}, Lcom/google/android/material/timepicker/i;-><init>()V

    .line 224
    .line 225
    .line 226
    new-instance v4, Landroid/os/Bundle;

    .line 227
    .line 228
    invoke-direct {v4}, Landroid/os/Bundle;-><init>()V

    .line 229
    .line 230
    .line 231
    const-string v6, "TIME_PICKER_TIME_MODEL"

    .line 232
    .line 233
    invoke-virtual {v4, v6, v7}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 234
    .line 235
    .line 236
    const-string v6, "TIME_PICKER_TITLE_RES"

    .line 237
    .line 238
    invoke-virtual {v4, v6, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 239
    .line 240
    .line 241
    const-string v6, "TIME_PICKER_POSITIVE_BUTTON_TEXT_RES"

    .line 242
    .line 243
    invoke-virtual {v4, v6, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 244
    .line 245
    .line 246
    const-string v6, "TIME_PICKER_NEGATIVE_BUTTON_TEXT_RES"

    .line 247
    .line 248
    invoke-virtual {v4, v6, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 249
    .line 250
    .line 251
    const-string v6, "TIME_PICKER_OVERRIDE_THEME_RES_ID"

    .line 252
    .line 253
    invoke-virtual {v4, v6, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v1, v4}, Landroidx/fragment/app/j0;->setArguments(Landroid/os/Bundle;)V

    .line 257
    .line 258
    .line 259
    new-instance v4, Lz70/g;

    .line 260
    .line 261
    invoke-direct {v4, v1, v3, v0}, Lz70/g;-><init>(Lcom/google/android/material/timepicker/i;Ljava/time/LocalDate;Lay0/k;)V

    .line 262
    .line 263
    .line 264
    iget-object v0, v1, Lcom/google/android/material/timepicker/i;->t:Ljava/util/LinkedHashSet;

    .line 265
    .line 266
    invoke-interface {v0, v4}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    const-string v0, "SERVICE_BOOK_TIME_PICKER"

    .line 270
    .line 271
    invoke-virtual {v1, v2, v0}, Landroidx/fragment/app/x;->k(Landroidx/fragment/app/j1;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    goto/16 :goto_0

    .line 275
    .line 276
    :pswitch_2
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 277
    .line 278
    move-object v5, v1

    .line 279
    check-cast v5, Lyj/b;

    .line 280
    .line 281
    iget-object v1, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 282
    .line 283
    move-object v6, v1

    .line 284
    check-cast v6, Lyj/b;

    .line 285
    .line 286
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 287
    .line 288
    move-object v7, v0

    .line 289
    check-cast v7, Ly1/i;

    .line 290
    .line 291
    move-object/from16 v0, p1

    .line 292
    .line 293
    check-cast v0, Lhi/a;

    .line 294
    .line 295
    const-string v1, "$this$sdkViewModel"

    .line 296
    .line 297
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    const-class v1, Lwd/d;

    .line 301
    .line 302
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 303
    .line 304
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    check-cast v0, Lii/a;

    .line 309
    .line 310
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    check-cast v0, Lwd/d;

    .line 315
    .line 316
    new-instance v2, Lyd/u;

    .line 317
    .line 318
    new-instance v3, Lus0/a;

    .line 319
    .line 320
    const/4 v1, 0x6

    .line 321
    const/4 v4, 0x0

    .line 322
    invoke-direct {v3, v0, v4, v1}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 323
    .line 324
    .line 325
    new-instance v1, Lwp0/c;

    .line 326
    .line 327
    const/16 v8, 0x12

    .line 328
    .line 329
    invoke-direct {v1, v0, v4, v8}, Lwp0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 330
    .line 331
    .line 332
    move-object v4, v1

    .line 333
    invoke-direct/range {v2 .. v7}, Lyd/u;-><init>(Lus0/a;Lwp0/c;Lyj/b;Lyj/b;Ly1/i;)V

    .line 334
    .line 335
    .line 336
    return-object v2

    .line 337
    :pswitch_3
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v1, Lw1/c;

    .line 340
    .line 341
    iget-object v2, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v2, Landroid/content/Context;

    .line 344
    .line 345
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v0, Lw1/g;

    .line 348
    .line 349
    move-object/from16 v3, p1

    .line 350
    .line 351
    check-cast v3, Lf1/e;

    .line 352
    .line 353
    iget-object v1, v1, Lw1/c;->a:Ljava/lang/Object;

    .line 354
    .line 355
    move-object v4, v1

    .line 356
    check-cast v4, Ljava/util/Collection;

    .line 357
    .line 358
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 359
    .line 360
    .line 361
    move-result v4

    .line 362
    const/4 v5, 0x0

    .line 363
    move v6, v5

    .line 364
    :goto_2
    if-ge v6, v4, :cond_b

    .line 365
    .line 366
    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v7

    .line 370
    check-cast v7, Lw1/b;

    .line 371
    .line 372
    instance-of v8, v7, Lw1/d;

    .line 373
    .line 374
    const/4 v9, 0x6

    .line 375
    const/4 v10, 0x0

    .line 376
    const/4 v11, 0x1

    .line 377
    if-eqz v8, :cond_2

    .line 378
    .line 379
    new-instance v8, Lal/q;

    .line 380
    .line 381
    check-cast v7, Lw1/d;

    .line 382
    .line 383
    const/4 v12, 0x6

    .line 384
    invoke-direct {v8, v7, v12}, Lal/q;-><init>(Ljava/lang/Object;I)V

    .line 385
    .line 386
    .line 387
    iget v12, v7, Lw1/d;->c:I

    .line 388
    .line 389
    if-nez v12, :cond_1

    .line 390
    .line 391
    goto :goto_3

    .line 392
    :cond_1
    new-instance v10, Le1/u;

    .line 393
    .line 394
    const/16 v12, 0xb

    .line 395
    .line 396
    invoke-direct {v10, v7, v12}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 397
    .line 398
    .line 399
    new-instance v12, Lt2/b;

    .line 400
    .line 401
    const v13, -0x731428a5

    .line 402
    .line 403
    .line 404
    invoke-direct {v12, v10, v11, v13}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 405
    .line 406
    .line 407
    move-object v10, v12

    .line 408
    :goto_3
    new-instance v11, Lvu/d;

    .line 409
    .line 410
    const/16 v12, 0x16

    .line 411
    .line 412
    invoke-direct {v11, v12, v7, v0}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 413
    .line 414
    .line 415
    invoke-static {v3, v8, v10, v11, v9}, Lf1/e;->b(Lf1/e;Lay0/n;Lt2/b;Lay0/a;I)V

    .line 416
    .line 417
    .line 418
    goto/16 :goto_5

    .line 419
    .line 420
    :cond_2
    instance-of v8, v7, Lw1/h;

    .line 421
    .line 422
    if-eqz v8, :cond_9

    .line 423
    .line 424
    check-cast v7, Lw1/h;

    .line 425
    .line 426
    if-nez v2, :cond_3

    .line 427
    .line 428
    goto/16 :goto_5

    .line 429
    .line 430
    :cond_3
    iget v8, v7, Lw1/h;->c:I

    .line 431
    .line 432
    iget-object v7, v7, Lw1/h;->b:Landroid/view/textclassifier/TextClassification;

    .line 433
    .line 434
    if-gez v8, :cond_5

    .line 435
    .line 436
    new-instance v8, Lal/q;

    .line 437
    .line 438
    const/4 v12, 0x7

    .line 439
    invoke-direct {v8, v7, v12}, Lal/q;-><init>(Ljava/lang/Object;I)V

    .line 440
    .line 441
    .line 442
    invoke-virtual {v7}, Landroid/view/textclassifier/TextClassification;->getIcon()Landroid/graphics/drawable/Drawable;

    .line 443
    .line 444
    .line 445
    move-result-object v12

    .line 446
    if-eqz v12, :cond_4

    .line 447
    .line 448
    new-instance v10, Le1/u;

    .line 449
    .line 450
    const/16 v13, 0xc

    .line 451
    .line 452
    invoke-direct {v10, v12, v13}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 453
    .line 454
    .line 455
    new-instance v12, Lt2/b;

    .line 456
    .line 457
    const v13, -0x42f30a7b

    .line 458
    .line 459
    .line 460
    invoke-direct {v12, v10, v11, v13}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 461
    .line 462
    .line 463
    move-object v10, v12

    .line 464
    :cond_4
    new-instance v11, Lvu/d;

    .line 465
    .line 466
    const/16 v12, 0x17

    .line 467
    .line 468
    invoke-direct {v11, v12, v2, v7}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    invoke-static {v3, v8, v10, v11, v9}, Lf1/e;->b(Lf1/e;Lay0/n;Lt2/b;Lay0/a;I)V

    .line 472
    .line 473
    .line 474
    goto :goto_5

    .line 475
    :cond_5
    invoke-virtual {v7}, Landroid/view/textclassifier/TextClassification;->getActions()Ljava/util/List;

    .line 476
    .line 477
    .line 478
    move-result-object v7

    .line 479
    invoke-interface {v7, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v7

    .line 483
    check-cast v7, Landroid/app/RemoteAction;

    .line 484
    .line 485
    if-nez v8, :cond_6

    .line 486
    .line 487
    move v8, v11

    .line 488
    goto :goto_4

    .line 489
    :cond_6
    move v8, v5

    .line 490
    :goto_4
    new-instance v12, Lal/q;

    .line 491
    .line 492
    const/16 v13, 0x8

    .line 493
    .line 494
    invoke-direct {v12, v7, v13}, Lal/q;-><init>(Ljava/lang/Object;I)V

    .line 495
    .line 496
    .line 497
    if-nez v8, :cond_7

    .line 498
    .line 499
    invoke-virtual {v7}, Landroid/app/RemoteAction;->shouldShowIcon()Z

    .line 500
    .line 501
    .line 502
    move-result v8

    .line 503
    if-eqz v8, :cond_8

    .line 504
    .line 505
    :cond_7
    new-instance v8, Le1/u;

    .line 506
    .line 507
    const/16 v10, 0xd

    .line 508
    .line 509
    invoke-direct {v8, v7, v10}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 510
    .line 511
    .line 512
    new-instance v10, Lt2/b;

    .line 513
    .line 514
    const v13, -0x4b2bf918

    .line 515
    .line 516
    .line 517
    invoke-direct {v10, v8, v11, v13}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 518
    .line 519
    .line 520
    :cond_8
    new-instance v8, Ly1/i;

    .line 521
    .line 522
    const/4 v11, 0x1

    .line 523
    invoke-direct {v8, v7, v11}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 524
    .line 525
    .line 526
    invoke-static {v3, v12, v10, v8, v9}, Lf1/e;->b(Lf1/e;Lay0/n;Lt2/b;Lay0/a;I)V

    .line 527
    .line 528
    .line 529
    goto :goto_5

    .line 530
    :cond_9
    instance-of v7, v7, Lw1/f;

    .line 531
    .line 532
    if-eqz v7, :cond_a

    .line 533
    .line 534
    iget-object v7, v3, Lf1/e;->a:Lv2/o;

    .line 535
    .line 536
    sget-object v8, Lf1/b;->a:Lt2/b;

    .line 537
    .line 538
    invoke-virtual {v7, v8}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 539
    .line 540
    .line 541
    :cond_a
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 542
    .line 543
    goto/16 :goto_2

    .line 544
    .line 545
    :cond_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 546
    .line 547
    return-object v0

    .line 548
    :pswitch_4
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 549
    .line 550
    check-cast v1, Ll2/b1;

    .line 551
    .line 552
    iget-object v2, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 553
    .line 554
    check-cast v2, Ll2/b1;

    .line 555
    .line 556
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 557
    .line 558
    check-cast v0, Lle/a;

    .line 559
    .line 560
    move-object/from16 v3, p1

    .line 561
    .line 562
    check-cast v3, Ljava/util/Map;

    .line 563
    .line 564
    const-string v4, "seasonalData"

    .line 565
    .line 566
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 567
    .line 568
    .line 569
    sget-object v4, Lqe/a;->e:Lqe/a;

    .line 570
    .line 571
    invoke-interface {v1, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 572
    .line 573
    .line 574
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 575
    .line 576
    .line 577
    move-result-object v1

    .line 578
    check-cast v1, Lqe/d;

    .line 579
    .line 580
    invoke-static {v3}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 581
    .line 582
    .line 583
    move-result-object v3

    .line 584
    const/4 v4, 0x3

    .line 585
    const/4 v5, 0x0

    .line 586
    invoke-static {v1, v5, v3, v4}, Lqe/d;->a(Lqe/d;Lje/r;Ljava/util/LinkedHashMap;I)Lqe/d;

    .line 587
    .line 588
    .line 589
    move-result-object v1

    .line 590
    invoke-interface {v2, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 591
    .line 592
    .line 593
    invoke-virtual {v0}, Lle/a;->invoke()Ljava/lang/Object;

    .line 594
    .line 595
    .line 596
    goto/16 :goto_0

    .line 597
    .line 598
    :pswitch_5
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 599
    .line 600
    check-cast v1, Ll2/b1;

    .line 601
    .line 602
    iget-object v2, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 603
    .line 604
    check-cast v2, Ll2/b1;

    .line 605
    .line 606
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 607
    .line 608
    check-cast v0, Ll2/b1;

    .line 609
    .line 610
    move-object/from16 v3, p1

    .line 611
    .line 612
    check-cast v3, Ljava/util/List;

    .line 613
    .line 614
    const-string v4, "it"

    .line 615
    .line 616
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v2

    .line 623
    check-cast v2, Lqe/a;

    .line 624
    .line 625
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 626
    .line 627
    .line 628
    move-result-object v0

    .line 629
    check-cast v0, Ljava/util/List;

    .line 630
    .line 631
    invoke-static {v1, v2, v0, v3}, Ljp/kf;->h(Ll2/b1;Lqe/a;Ljava/util/List;Ljava/util/List;)V

    .line 632
    .line 633
    .line 634
    goto/16 :goto_0

    .line 635
    .line 636
    :pswitch_6
    iget-object v1, v0, Lxc/b;->e:Ljava/lang/Object;

    .line 637
    .line 638
    move-object v5, v1

    .line 639
    check-cast v5, Lyj/b;

    .line 640
    .line 641
    iget-object v1, v0, Lxc/b;->f:Ljava/lang/Object;

    .line 642
    .line 643
    move-object v6, v1

    .line 644
    check-cast v6, Lyj/b;

    .line 645
    .line 646
    iget-object v0, v0, Lxc/b;->g:Ljava/lang/Object;

    .line 647
    .line 648
    move-object v7, v0

    .line 649
    check-cast v7, Ljava/lang/String;

    .line 650
    .line 651
    move-object/from16 v0, p1

    .line 652
    .line 653
    check-cast v0, Lhi/a;

    .line 654
    .line 655
    const-string v1, "$this$sdkViewModel"

    .line 656
    .line 657
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 658
    .line 659
    .line 660
    const-class v1, Luc/g;

    .line 661
    .line 662
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 663
    .line 664
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 665
    .line 666
    .line 667
    move-result-object v1

    .line 668
    check-cast v0, Lii/a;

    .line 669
    .line 670
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 671
    .line 672
    .line 673
    move-result-object v0

    .line 674
    move-object v10, v0

    .line 675
    check-cast v10, Luc/g;

    .line 676
    .line 677
    new-instance v3, Lwc/a;

    .line 678
    .line 679
    const/4 v14, 0x0

    .line 680
    const/16 v15, 0xf

    .line 681
    .line 682
    const/4 v9, 0x1

    .line 683
    const-class v11, Luc/g;

    .line 684
    .line 685
    const-string v12, "initOrderChargingCard"

    .line 686
    .line 687
    const-string v13, "initOrderChargingCard-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 688
    .line 689
    move-object v8, v3

    .line 690
    invoke-direct/range {v8 .. v15}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 691
    .line 692
    .line 693
    new-instance v4, Lth/b;

    .line 694
    .line 695
    const/16 v15, 0x9

    .line 696
    .line 697
    const/4 v9, 0x2

    .line 698
    const-class v11, Luc/g;

    .line 699
    .line 700
    const-string v12, "completeChargingCardOrder"

    .line 701
    .line 702
    const-string v13, "completeChargingCardOrder-gIAlu-s(Lcariad/charging/multicharge/kitten/chargingcard/presentation/order/OrderChargingCardRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 703
    .line 704
    move-object v8, v4

    .line 705
    invoke-direct/range {v8 .. v15}, Lth/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 706
    .line 707
    .line 708
    new-instance v2, Lxc/h;

    .line 709
    .line 710
    invoke-direct/range {v2 .. v7}, Lxc/h;-><init>(Lwc/a;Lth/b;Lyj/b;Lyj/b;Ljava/lang/String;)V

    .line 711
    .line 712
    .line 713
    return-object v2

    .line 714
    nop

    .line 715
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
