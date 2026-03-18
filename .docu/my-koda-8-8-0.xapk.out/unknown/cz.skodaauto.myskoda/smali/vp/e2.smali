.class public final Lvp/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvp/j2;

.field public final synthetic f:Landroid/os/Bundle;


# direct methods
.method public synthetic constructor <init>(Lvp/j2;Landroid/os/Bundle;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/e2;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lvp/e2;->f:Landroid/os/Bundle;

    .line 4
    .line 5
    iput-object p1, p0, Lvp/e2;->e:Lvp/j2;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvp/e2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lvp/e2;->e:Lvp/j2;

    .line 9
    .line 10
    iget-object v2, v1, Lvp/j2;->A:Lro/f;

    .line 11
    .line 12
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Lvp/g1;

    .line 15
    .line 16
    iget-object v0, v0, Lvp/e2;->f:Landroid/os/Bundle;

    .line 17
    .line 18
    invoke-virtual {v0}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    move-object v8, v0

    .line 25
    goto/16 :goto_3

    .line 26
    .line 27
    :cond_0
    new-instance v8, Landroid/os/Bundle;

    .line 28
    .line 29
    iget-object v3, v1, Lvp/g1;->h:Lvp/w0;

    .line 30
    .line 31
    iget-object v9, v1, Lvp/g1;->l:Lvp/d4;

    .line 32
    .line 33
    iget-object v10, v1, Lvp/g1;->g:Lvp/h;

    .line 34
    .line 35
    iget-object v11, v1, Lvp/g1;->i:Lvp/p0;

    .line 36
    .line 37
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 38
    .line 39
    .line 40
    iget-object v3, v3, Lvp/w0;->C:Lun/a;

    .line 41
    .line 42
    invoke-virtual {v3}, Lun/a;->b()Landroid/os/Bundle;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-direct {v8, v3}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object v12

    .line 57
    :cond_1
    :goto_0
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    if-eqz v3, :cond_6

    .line 62
    .line 63
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    move-object v13, v3

    .line 68
    check-cast v13, Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v0, v13}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v14

    .line 74
    if-eqz v14, :cond_3

    .line 75
    .line 76
    instance-of v3, v14, Ljava/lang/String;

    .line 77
    .line 78
    if-nez v3, :cond_3

    .line 79
    .line 80
    instance-of v3, v14, Ljava/lang/Long;

    .line 81
    .line 82
    if-nez v3, :cond_3

    .line 83
    .line 84
    instance-of v3, v14, Ljava/lang/Double;

    .line 85
    .line 86
    if-nez v3, :cond_3

    .line 87
    .line 88
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v14}, Lvp/d4;->i1(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    if-eqz v3, :cond_2

    .line 96
    .line 97
    const/4 v6, 0x0

    .line 98
    const/4 v7, 0x0

    .line 99
    const/4 v3, 0x0

    .line 100
    const/16 v4, 0x1b

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    invoke-static/range {v2 .. v7}, Lvp/d4;->q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V

    .line 104
    .line 105
    .line 106
    :cond_2
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 107
    .line 108
    .line 109
    iget-object v3, v11, Lvp/p0;->o:Lvp/n0;

    .line 110
    .line 111
    const-string v4, "Invalid default event parameter type. Name, value"

    .line 112
    .line 113
    invoke-virtual {v3, v13, v14, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_3
    invoke-static {v13}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-eqz v3, :cond_4

    .line 122
    .line 123
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 124
    .line 125
    .line 126
    iget-object v3, v11, Lvp/p0;->o:Lvp/n0;

    .line 127
    .line 128
    const-string v4, "Invalid default event parameter name. Name"

    .line 129
    .line 130
    invoke-virtual {v3, v13, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_4
    if-nez v14, :cond_5

    .line 135
    .line 136
    invoke-virtual {v8, v13}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_5
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    const/16 v3, 0x1f4

    .line 147
    .line 148
    const-string v4, "param"

    .line 149
    .line 150
    invoke-virtual {v9, v14, v4, v3, v13}, Lvp/d4;->j1(Ljava/lang/Object;Ljava/lang/String;ILjava/lang/String;)Z

    .line 151
    .line 152
    .line 153
    move-result v3

    .line 154
    if-eqz v3, :cond_1

    .line 155
    .line 156
    invoke-virtual {v9, v8, v13, v14}, Lvp/d4;->p0(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    goto :goto_0

    .line 160
    :cond_6
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 161
    .line 162
    .line 163
    iget-object v3, v10, Lap0/o;->e:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v3, Lvp/g1;

    .line 166
    .line 167
    iget-object v3, v3, Lvp/g1;->l:Lvp/d4;

    .line 168
    .line 169
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 170
    .line 171
    .line 172
    const v4, 0xc02a560

    .line 173
    .line 174
    .line 175
    invoke-virtual {v3, v4}, Lvp/d4;->F0(I)Z

    .line 176
    .line 177
    .line 178
    move-result v3

    .line 179
    if-eqz v3, :cond_7

    .line 180
    .line 181
    const/16 v3, 0x64

    .line 182
    .line 183
    goto :goto_1

    .line 184
    :cond_7
    const/16 v3, 0x19

    .line 185
    .line 186
    :goto_1
    invoke-virtual {v8}, Landroid/os/BaseBundle;->size()I

    .line 187
    .line 188
    .line 189
    move-result v4

    .line 190
    if-gt v4, v3, :cond_8

    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_8
    new-instance v4, Ljava/util/TreeSet;

    .line 194
    .line 195
    invoke-virtual {v8}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 196
    .line 197
    .line 198
    move-result-object v5

    .line 199
    invoke-direct {v4, v5}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v4}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    .line 203
    .line 204
    .line 205
    move-result-object v4

    .line 206
    const/4 v5, 0x0

    .line 207
    :cond_9
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    if-eqz v6, :cond_a

    .line 212
    .line 213
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v6

    .line 217
    check-cast v6, Ljava/lang/String;

    .line 218
    .line 219
    add-int/lit8 v5, v5, 0x1

    .line 220
    .line 221
    if-le v5, v3, :cond_9

    .line 222
    .line 223
    invoke-virtual {v8, v6}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    goto :goto_2

    .line 227
    :cond_a
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 228
    .line 229
    .line 230
    const/4 v6, 0x0

    .line 231
    const/4 v7, 0x0

    .line 232
    const/4 v3, 0x0

    .line 233
    const/16 v4, 0x1a

    .line 234
    .line 235
    const/4 v5, 0x0

    .line 236
    invoke-static/range {v2 .. v7}, Lvp/d4;->q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V

    .line 237
    .line 238
    .line 239
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 240
    .line 241
    .line 242
    iget-object v2, v11, Lvp/p0;->o:Lvp/n0;

    .line 243
    .line 244
    const-string v3, "Too many default event parameters set. Discarding beyond event parameter limit"

    .line 245
    .line 246
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    :goto_3
    iget-object v2, v1, Lvp/g1;->h:Lvp/w0;

    .line 250
    .line 251
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 252
    .line 253
    .line 254
    iget-object v2, v2, Lvp/w0;->C:Lun/a;

    .line 255
    .line 256
    invoke-virtual {v2, v8}, Lun/a;->c(Landroid/os/Bundle;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v0}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 260
    .line 261
    .line 262
    move-result v0

    .line 263
    if-eqz v0, :cond_b

    .line 264
    .line 265
    iget-object v0, v1, Lvp/g1;->g:Lvp/h;

    .line 266
    .line 267
    const/4 v2, 0x0

    .line 268
    sget-object v3, Lvp/z;->W0:Lvp/y;

    .line 269
    .line 270
    invoke-virtual {v0, v2, v3}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 271
    .line 272
    .line 273
    move-result v0

    .line 274
    if-eqz v0, :cond_c

    .line 275
    .line 276
    :cond_b
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    invoke-virtual {v0, v8}, Lvp/d3;->f0(Landroid/os/Bundle;)V

    .line 281
    .line 282
    .line 283
    :cond_c
    return-void

    .line 284
    :pswitch_0
    const-string v1, "app_id"

    .line 285
    .line 286
    iget-object v2, v0, Lvp/e2;->e:Lvp/j2;

    .line 287
    .line 288
    invoke-virtual {v2}, Lvp/x;->a0()V

    .line 289
    .line 290
    .line 291
    invoke-virtual {v2}, Lvp/b0;->b0()V

    .line 292
    .line 293
    .line 294
    const-string v3, "name"

    .line 295
    .line 296
    iget-object v0, v0, Lvp/e2;->f:Landroid/os/Bundle;

    .line 297
    .line 298
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v8

    .line 302
    const-string v3, "origin"

    .line 303
    .line 304
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v12

    .line 308
    invoke-static {v8}, Lno/c0;->e(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    invoke-static {v12}, Lno/c0;->e(Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    const-string v3, "value"

    .line 315
    .line 316
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v4

    .line 320
    invoke-static {v4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 321
    .line 322
    .line 323
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 324
    .line 325
    check-cast v2, Lvp/g1;

    .line 326
    .line 327
    invoke-virtual {v2}, Lvp/g1;->a()Z

    .line 328
    .line 329
    .line 330
    move-result v4

    .line 331
    if-nez v4, :cond_d

    .line 332
    .line 333
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 334
    .line 335
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 336
    .line 337
    .line 338
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 339
    .line 340
    const-string v1, "Conditional property not set since app measurement is disabled"

    .line 341
    .line 342
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 343
    .line 344
    .line 345
    goto/16 :goto_4

    .line 346
    .line 347
    :cond_d
    new-instance v4, Lvp/b4;

    .line 348
    .line 349
    const-string v5, "triggered_timestamp"

    .line 350
    .line 351
    invoke-virtual {v0, v5}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 352
    .line 353
    .line 354
    move-result-wide v5

    .line 355
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v7

    .line 359
    move-object v9, v12

    .line 360
    invoke-direct/range {v4 .. v9}, Lvp/b4;-><init>(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    :try_start_0
    iget-object v9, v2, Lvp/g1;->l:Lvp/d4;

    .line 364
    .line 365
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    const-string v3, "triggered_event_name"

    .line 372
    .line 373
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v10

    .line 377
    const-string v3, "triggered_event_params"

    .line 378
    .line 379
    invoke-virtual {v0, v3}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 380
    .line 381
    .line 382
    move-result-object v11

    .line 383
    const-wide/16 v13, 0x0

    .line 384
    .line 385
    const/4 v15, 0x1

    .line 386
    invoke-virtual/range {v9 .. v15}, Lvp/d4;->C0(Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/String;JZ)Lvp/t;

    .line 387
    .line 388
    .line 389
    move-result-object v20

    .line 390
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 391
    .line 392
    .line 393
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    const-string v3, "timed_out_event_name"

    .line 397
    .line 398
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v10

    .line 402
    const-string v3, "timed_out_event_params"

    .line 403
    .line 404
    invoke-virtual {v0, v3}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 405
    .line 406
    .line 407
    move-result-object v11

    .line 408
    const-wide/16 v13, 0x0

    .line 409
    .line 410
    const/4 v15, 0x1

    .line 411
    invoke-virtual/range {v9 .. v15}, Lvp/d4;->C0(Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/String;JZ)Lvp/t;

    .line 412
    .line 413
    .line 414
    move-result-object v17

    .line 415
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    const-string v3, "expired_event_name"

    .line 419
    .line 420
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object v10

    .line 424
    const-string v3, "expired_event_params"

    .line 425
    .line 426
    invoke-virtual {v0, v3}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 427
    .line 428
    .line 429
    move-result-object v11

    .line 430
    const-wide/16 v13, 0x0

    .line 431
    .line 432
    const/4 v15, 0x1

    .line 433
    invoke-virtual/range {v9 .. v15}, Lvp/d4;->C0(Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/String;JZ)Lvp/t;

    .line 434
    .line 435
    .line 436
    move-result-object v23
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 437
    new-instance v9, Lvp/f;

    .line 438
    .line 439
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 440
    .line 441
    .line 442
    move-result-object v10

    .line 443
    const-string v1, "creation_timestamp"

    .line 444
    .line 445
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 446
    .line 447
    .line 448
    move-result-wide v13

    .line 449
    const-string v1, "trigger_event_name"

    .line 450
    .line 451
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v16

    .line 455
    const-string v1, "trigger_timeout"

    .line 456
    .line 457
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 458
    .line 459
    .line 460
    move-result-wide v18

    .line 461
    const-string v1, "time_to_live"

    .line 462
    .line 463
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 464
    .line 465
    .line 466
    move-result-wide v21

    .line 467
    const/4 v15, 0x0

    .line 468
    move-object v11, v12

    .line 469
    move-object v12, v4

    .line 470
    invoke-direct/range {v9 .. v23}, Lvp/f;-><init>(Ljava/lang/String;Ljava/lang/String;Lvp/b4;JZLjava/lang/String;Lvp/t;JLvp/t;JLvp/t;)V

    .line 471
    .line 472
    .line 473
    invoke-virtual {v2}, Lvp/g1;->o()Lvp/d3;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    invoke-virtual {v0, v9}, Lvp/d3;->t0(Lvp/f;)V

    .line 478
    .line 479
    .line 480
    :catch_0
    :goto_4
    return-void

    .line 481
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
