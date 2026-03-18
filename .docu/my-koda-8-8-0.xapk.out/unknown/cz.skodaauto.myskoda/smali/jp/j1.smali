.class public abstract Ljp/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;
    .locals 0

    .line 1
    const-string p4, "<this>"

    .line 2
    .line 3
    invoke-static {p0, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p4, "context"

    .line 7
    .line 8
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0, p1, p2, p3}, Lmw/e;->a(Lkw/g;D)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-lez p1, :cond_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "`CartesianValueFormatter.format` returned an empty string. Use `HorizontalAxis.ItemPlacer` and `VerticalAxis.ItemPlacer`, not empty strings, to control which x and y values are labeled."

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

.method public static b(B)Z
    .locals 1

    .line 1
    const/16 v0, -0x41

    .line 2
    .line 3
    if-le p0, v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public static final c(Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;)Lcn0/c;
    .locals 6

    .line 1
    new-instance v0, Lcn0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->getTraceId()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->getStatus()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const-string v3, "<this>"

    .line 12
    .line 13
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    sparse-switch v4, :sswitch_data_0

    .line 21
    .line 22
    .line 23
    goto/16 :goto_5

    .line 24
    .line 25
    :sswitch_0
    const-string v4, "COMPLETED_WARNING"

    .line 26
    .line 27
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_24

    .line 32
    .line 33
    sget-object v2, Lcn0/b;->f:Lcn0/b;

    .line 34
    .line 35
    :goto_0
    move-object v4, v3

    .line 36
    goto :goto_1

    .line 37
    :sswitch_1
    const-string v4, "ERROR"

    .line 38
    .line 39
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    if-eqz v4, :cond_24

    .line 44
    .line 45
    sget-object v2, Lcn0/b;->g:Lcn0/b;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :sswitch_2
    const-string v4, "IN_PROGRESS"

    .line 49
    .line 50
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    if-eqz v4, :cond_24

    .line 55
    .line 56
    sget-object v2, Lcn0/b;->d:Lcn0/b;

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :sswitch_3
    const-string v4, "COMPLETED_SUCCESS"

    .line 60
    .line 61
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_24

    .line 66
    .line 67
    sget-object v2, Lcn0/b;->e:Lcn0/b;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :goto_1
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->getErrorCode()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    move-object v5, v4

    .line 75
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->getRequestId()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/operationrequest/data/OperationRequestDto;->getOperation()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    sparse-switch v5, :sswitch_data_1

    .line 91
    .line 92
    .line 93
    goto/16 :goto_3

    .line 94
    .line 95
    :sswitch_4
    const-string v5, "stop-window-heating"

    .line 96
    .line 97
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-nez p0, :cond_0

    .line 102
    .line 103
    goto/16 :goto_3

    .line 104
    .line 105
    :cond_0
    sget-object p0, Lcn0/a;->g:Lcn0/a;

    .line 106
    .line 107
    :goto_2
    move-object v5, p0

    .line 108
    goto/16 :goto_4

    .line 109
    .line 110
    :sswitch_5
    const-string v5, "activate-deactivate-wakeup"

    .line 111
    .line 112
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-nez p0, :cond_1

    .line 117
    .line 118
    goto/16 :goto_3

    .line 119
    .line 120
    :cond_1
    sget-object p0, Lcn0/a;->N:Lcn0/a;

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :sswitch_6
    const-string v5, "stop-charging"

    .line 124
    .line 125
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    if-nez p0, :cond_2

    .line 130
    .line 131
    goto/16 :goto_3

    .line 132
    .line 133
    :cond_2
    sget-object p0, Lcn0/a;->q:Lcn0/a;

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :sswitch_7
    const-string v5, "set-air-conditioning-at-unlock"

    .line 137
    .line 138
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result p0

    .line 142
    if-nez p0, :cond_3

    .line 143
    .line 144
    goto/16 :goto_3

    .line 145
    .line 146
    :cond_3
    sget-object p0, Lcn0/a;->i:Lcn0/a;

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :sswitch_8
    const-string v5, "update-charge-mode"

    .line 150
    .line 151
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    if-nez p0, :cond_4

    .line 156
    .line 157
    goto/16 :goto_3

    .line 158
    .line 159
    :cond_4
    sget-object p0, Lcn0/a;->x:Lcn0/a;

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :sswitch_9
    const-string v5, "start-flash"

    .line 163
    .line 164
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result p0

    .line 168
    if-nez p0, :cond_5

    .line 169
    .line 170
    goto/16 :goto_3

    .line 171
    .line 172
    :cond_5
    sget-object p0, Lcn0/a;->o:Lcn0/a;

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :sswitch_a
    const-string v5, "start-air-conditioning"

    .line 176
    .line 177
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result p0

    .line 181
    if-nez p0, :cond_6

    .line 182
    .line 183
    goto/16 :goto_3

    .line 184
    .line 185
    :cond_6
    sget-object p0, Lcn0/a;->d:Lcn0/a;

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :sswitch_b
    const-string v5, "update-charging-profiles"

    .line 189
    .line 190
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result p0

    .line 194
    if-nez p0, :cond_7

    .line 195
    .line 196
    goto/16 :goto_3

    .line 197
    .line 198
    :cond_7
    sget-object p0, Lcn0/a;->B:Lcn0/a;

    .line 199
    .line 200
    goto :goto_2

    .line 201
    :sswitch_c
    const-string v5, "start-window-heating"

    .line 202
    .line 203
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result p0

    .line 207
    if-nez p0, :cond_8

    .line 208
    .line 209
    goto/16 :goto_3

    .line 210
    .line 211
    :cond_8
    sget-object p0, Lcn0/a;->f:Lcn0/a;

    .line 212
    .line 213
    goto :goto_2

    .line 214
    :sswitch_d
    const-string v5, "update-charging-current"

    .line 215
    .line 216
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result p0

    .line 220
    if-nez p0, :cond_9

    .line 221
    .line 222
    goto/16 :goto_3

    .line 223
    .line 224
    :cond_9
    sget-object p0, Lcn0/a;->G:Lcn0/a;

    .line 225
    .line 226
    goto :goto_2

    .line 227
    :sswitch_e
    const-string v5, "update-minimal-soc"

    .line 228
    .line 229
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result p0

    .line 233
    if-nez p0, :cond_a

    .line 234
    .line 235
    goto/16 :goto_3

    .line 236
    .line 237
    :cond_a
    sget-object p0, Lcn0/a;->F:Lcn0/a;

    .line 238
    .line 239
    goto/16 :goto_2

    .line 240
    .line 241
    :sswitch_f
    const-string v5, "delete-charging-profile"

    .line 242
    .line 243
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result p0

    .line 247
    if-nez p0, :cond_b

    .line 248
    .line 249
    goto/16 :goto_3

    .line 250
    .line 251
    :cond_b
    sget-object p0, Lcn0/a;->A:Lcn0/a;

    .line 252
    .line 253
    goto/16 :goto_2

    .line 254
    .line 255
    :sswitch_10
    const-string v5, "update-care-mode"

    .line 256
    .line 257
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result p0

    .line 261
    if-nez p0, :cond_c

    .line 262
    .line 263
    goto/16 :goto_3

    .line 264
    .line 265
    :cond_c
    sget-object p0, Lcn0/a;->C:Lcn0/a;

    .line 266
    .line 267
    goto/16 :goto_2

    .line 268
    .line 269
    :sswitch_11
    const-string v5, "windows-heating"

    .line 270
    .line 271
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result p0

    .line 275
    if-nez p0, :cond_d

    .line 276
    .line 277
    goto/16 :goto_3

    .line 278
    .line 279
    :cond_d
    sget-object p0, Lcn0/a;->j:Lcn0/a;

    .line 280
    .line 281
    goto/16 :goto_2

    .line 282
    .line 283
    :sswitch_12
    const-string v5, "start-active-ventilation"

    .line 284
    .line 285
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result p0

    .line 289
    if-nez p0, :cond_e

    .line 290
    .line 291
    goto/16 :goto_3

    .line 292
    .line 293
    :cond_e
    sget-object p0, Lcn0/a;->t:Lcn0/a;

    .line 294
    .line 295
    goto/16 :goto_2

    .line 296
    .line 297
    :sswitch_13
    const-string v5, "set-air-conditioning-seats-heating"

    .line 298
    .line 299
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 300
    .line 301
    .line 302
    move-result p0

    .line 303
    if-nez p0, :cond_f

    .line 304
    .line 305
    goto/16 :goto_3

    .line 306
    .line 307
    :cond_f
    sget-object p0, Lcn0/a;->l:Lcn0/a;

    .line 308
    .line 309
    goto/16 :goto_2

    .line 310
    .line 311
    :sswitch_14
    const-string v5, "stop-auxiliary-heating"

    .line 312
    .line 313
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    move-result p0

    .line 317
    if-nez p0, :cond_10

    .line 318
    .line 319
    goto/16 :goto_3

    .line 320
    .line 321
    :cond_10
    sget-object p0, Lcn0/a;->s:Lcn0/a;

    .line 322
    .line 323
    goto/16 :goto_2

    .line 324
    .line 325
    :sswitch_15
    const-string v5, "lock"

    .line 326
    .line 327
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result p0

    .line 331
    if-nez p0, :cond_11

    .line 332
    .line 333
    goto/16 :goto_3

    .line 334
    .line 335
    :cond_11
    sget-object p0, Lcn0/a;->I:Lcn0/a;

    .line 336
    .line 337
    goto/16 :goto_2

    .line 338
    .line 339
    :sswitch_16
    const-string v5, "set-air-conditioning-timers"

    .line 340
    .line 341
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result p0

    .line 345
    if-nez p0, :cond_12

    .line 346
    .line 347
    goto/16 :goto_3

    .line 348
    .line 349
    :cond_12
    sget-object p0, Lcn0/a;->m:Lcn0/a;

    .line 350
    .line 351
    goto/16 :goto_2

    .line 352
    .line 353
    :sswitch_17
    const-string v5, "update-battery-support"

    .line 354
    .line 355
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result p0

    .line 359
    if-nez p0, :cond_13

    .line 360
    .line 361
    goto/16 :goto_3

    .line 362
    .line 363
    :cond_13
    sget-object p0, Lcn0/a;->w:Lcn0/a;

    .line 364
    .line 365
    goto/16 :goto_2

    .line 366
    .line 367
    :sswitch_18
    const-string v5, "start-auxiliary-heating"

    .line 368
    .line 369
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result p0

    .line 373
    if-nez p0, :cond_14

    .line 374
    .line 375
    goto/16 :goto_3

    .line 376
    .line 377
    :cond_14
    sget-object p0, Lcn0/a;->r:Lcn0/a;

    .line 378
    .line 379
    goto/16 :goto_2

    .line 380
    .line 381
    :sswitch_19
    const-string v5, "start-charging"

    .line 382
    .line 383
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 384
    .line 385
    .line 386
    move-result p0

    .line 387
    if-nez p0, :cond_15

    .line 388
    .line 389
    goto/16 :goto_3

    .line 390
    .line 391
    :cond_15
    sget-object p0, Lcn0/a;->n:Lcn0/a;

    .line 392
    .line 393
    goto/16 :goto_2

    .line 394
    .line 395
    :sswitch_1a
    const-string v5, "update-auto-unlock-plug"

    .line 396
    .line 397
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 398
    .line 399
    .line 400
    move-result p0

    .line 401
    if-nez p0, :cond_16

    .line 402
    .line 403
    goto/16 :goto_3

    .line 404
    .line 405
    :cond_16
    sget-object p0, Lcn0/a;->D:Lcn0/a;

    .line 406
    .line 407
    goto/16 :goto_2

    .line 408
    .line 409
    :sswitch_1b
    const-string v5, "wakeup"

    .line 410
    .line 411
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    move-result p0

    .line 415
    if-nez p0, :cond_17

    .line 416
    .line 417
    goto/16 :goto_3

    .line 418
    .line 419
    :cond_17
    sget-object p0, Lcn0/a;->M:Lcn0/a;

    .line 420
    .line 421
    goto/16 :goto_2

    .line 422
    .line 423
    :sswitch_1c
    const-string v5, "unlock"

    .line 424
    .line 425
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 426
    .line 427
    .line 428
    move-result p0

    .line 429
    if-nez p0, :cond_18

    .line 430
    .line 431
    goto/16 :goto_3

    .line 432
    .line 433
    :cond_18
    sget-object p0, Lcn0/a;->J:Lcn0/a;

    .line 434
    .line 435
    goto/16 :goto_2

    .line 436
    .line 437
    :sswitch_1d
    const-string v5, "update-departure-timers"

    .line 438
    .line 439
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 440
    .line 441
    .line 442
    move-result p0

    .line 443
    if-nez p0, :cond_19

    .line 444
    .line 445
    goto/16 :goto_3

    .line 446
    .line 447
    :cond_19
    sget-object p0, Lcn0/a;->E:Lcn0/a;

    .line 448
    .line 449
    goto/16 :goto_2

    .line 450
    .line 451
    :sswitch_1e
    const-string v5, "stop-active-ventilation"

    .line 452
    .line 453
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 454
    .line 455
    .line 456
    move-result p0

    .line 457
    if-nez p0, :cond_1a

    .line 458
    .line 459
    goto/16 :goto_3

    .line 460
    .line 461
    :cond_1a
    sget-object p0, Lcn0/a;->u:Lcn0/a;

    .line 462
    .line 463
    goto/16 :goto_2

    .line 464
    .line 465
    :sswitch_1f
    const-string v5, "update-charge-limit"

    .line 466
    .line 467
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result p0

    .line 471
    if-nez p0, :cond_1b

    .line 472
    .line 473
    goto/16 :goto_3

    .line 474
    .line 475
    :cond_1b
    sget-object p0, Lcn0/a;->y:Lcn0/a;

    .line 476
    .line 477
    goto/16 :goto_2

    .line 478
    .line 479
    :sswitch_20
    const-string v5, "create-charging-profile"

    .line 480
    .line 481
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 482
    .line 483
    .line 484
    move-result p0

    .line 485
    if-nez p0, :cond_1c

    .line 486
    .line 487
    goto :goto_3

    .line 488
    :cond_1c
    sget-object p0, Lcn0/a;->z:Lcn0/a;

    .line 489
    .line 490
    goto/16 :goto_2

    .line 491
    .line 492
    :sswitch_21
    const-string v5, "set-air-conditioning-target-temperature"

    .line 493
    .line 494
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 495
    .line 496
    .line 497
    move-result p0

    .line 498
    if-nez p0, :cond_1d

    .line 499
    .line 500
    goto :goto_3

    .line 501
    :cond_1d
    sget-object p0, Lcn0/a;->h:Lcn0/a;

    .line 502
    .line 503
    goto/16 :goto_2

    .line 504
    .line 505
    :sswitch_22
    const-string v5, "update-target-temperature"

    .line 506
    .line 507
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 508
    .line 509
    .line 510
    move-result p0

    .line 511
    if-nez p0, :cond_1e

    .line 512
    .line 513
    goto :goto_3

    .line 514
    :cond_1e
    sget-object p0, Lcn0/a;->H:Lcn0/a;

    .line 515
    .line 516
    goto/16 :goto_2

    .line 517
    .line 518
    :sswitch_23
    const-string v5, "set-climate-plans"

    .line 519
    .line 520
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 521
    .line 522
    .line 523
    move-result p0

    .line 524
    if-nez p0, :cond_1f

    .line 525
    .line 526
    goto :goto_3

    .line 527
    :cond_1f
    sget-object p0, Lcn0/a;->v:Lcn0/a;

    .line 528
    .line 529
    goto/16 :goto_2

    .line 530
    .line 531
    :sswitch_24
    const-string v5, "start-honk"

    .line 532
    .line 533
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    move-result p0

    .line 537
    if-nez p0, :cond_20

    .line 538
    .line 539
    goto :goto_3

    .line 540
    :cond_20
    sget-object p0, Lcn0/a;->p:Lcn0/a;

    .line 541
    .line 542
    goto/16 :goto_2

    .line 543
    .line 544
    :sswitch_25
    const-string v5, "set-air-conditioning-without-external-power"

    .line 545
    .line 546
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 547
    .line 548
    .line 549
    move-result p0

    .line 550
    if-nez p0, :cond_21

    .line 551
    .line 552
    goto :goto_3

    .line 553
    :cond_21
    sget-object p0, Lcn0/a;->k:Lcn0/a;

    .line 554
    .line 555
    goto/16 :goto_2

    .line 556
    .line 557
    :sswitch_26
    const-string v5, "apply-backup"

    .line 558
    .line 559
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 560
    .line 561
    .line 562
    move-result p0

    .line 563
    if-nez p0, :cond_22

    .line 564
    .line 565
    goto :goto_3

    .line 566
    :cond_22
    sget-object p0, Lcn0/a;->L:Lcn0/a;

    .line 567
    .line 568
    goto/16 :goto_2

    .line 569
    .line 570
    :sswitch_27
    const-string v5, "stop-air-conditioning"

    .line 571
    .line 572
    invoke-virtual {p0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 573
    .line 574
    .line 575
    move-result p0

    .line 576
    if-nez p0, :cond_23

    .line 577
    .line 578
    :goto_3
    sget-object p0, Lcn0/a;->K:Lcn0/a;

    .line 579
    .line 580
    goto/16 :goto_2

    .line 581
    .line 582
    :cond_23
    sget-object p0, Lcn0/a;->e:Lcn0/a;

    .line 583
    .line 584
    goto/16 :goto_2

    .line 585
    .line 586
    :goto_4
    invoke-direct/range {v0 .. v5}, Lcn0/c;-><init>(Ljava/lang/String;Lcn0/b;Ljava/lang/String;Ljava/lang/String;Lcn0/a;)V

    .line 587
    .line 588
    .line 589
    return-object v0

    .line 590
    :cond_24
    :goto_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 591
    .line 592
    const-string v0, "Value "

    .line 593
    .line 594
    const-string v1, " is not supported"

    .line 595
    .line 596
    invoke-static {v0, v2, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 597
    .line 598
    .line 599
    move-result-object v0

    .line 600
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 601
    .line 602
    .line 603
    throw p0

    .line 604
    nop

    .line 605
    :sswitch_data_0
    .sparse-switch
        -0x6c5de231 -> :sswitch_3
        -0x2408abf9 -> :sswitch_2
        0x3f2d9e8 -> :sswitch_1
        0x45f28d68 -> :sswitch_0
    .end sparse-switch

    .line 606
    .line 607
    .line 608
    .line 609
    .line 610
    .line 611
    .line 612
    .line 613
    .line 614
    .line 615
    .line 616
    .line 617
    .line 618
    .line 619
    .line 620
    .line 621
    .line 622
    .line 623
    :sswitch_data_1
    .sparse-switch
        -0x7a04590b -> :sswitch_27
        -0x71fabaff -> :sswitch_26
        -0x6f0b25a0 -> :sswitch_25
        -0x608a4071 -> :sswitch_24
        -0x5719af69 -> :sswitch_23
        -0x481c4144 -> :sswitch_22
        -0x40189290 -> :sswitch_21
        -0x3c8b3502 -> :sswitch_20
        -0x3b751a1a -> :sswitch_1f
        -0x3abbfb3f -> :sswitch_1e
        -0x39e69eb5 -> :sswitch_1d
        -0x321820bc -> :sswitch_1c
        -0x2f6638c1 -> :sswitch_1b
        -0x2f290c23 -> :sswitch_1a
        -0x26f01084 -> :sswitch_19
        -0x208b3ec0 -> :sswitch_18
        -0x1337c4f5 -> :sswitch_17
        -0x95093fa -> :sswitch_16
        0x32c52b -> :sswitch_15
        0x6725ce0 -> :sswitch_14
        0x912b2fb -> :sswitch_13
        0xc8e2c61 -> :sswitch_12
        0x10b616a8 -> :sswitch_11
        0x1de996db -> :sswitch_10
        0x2f91fa2f -> :sswitch_f
        0x305e6c57 -> :sswitch_e
        0x36ea5aa1 -> :sswitch_d
        0x3aa9ebe0 -> :sswitch_c
        0x4857b3c2 -> :sswitch_b
        0x4aeb3695 -> :sswitch_a
        0x4f2476c5 -> :sswitch_9
        0x50aa2e18 -> :sswitch_8
        0x5f2958e6 -> :sswitch_7
        0x7646bfdc -> :sswitch_6
        0x7a13145e -> :sswitch_5
        0x7ddaf440 -> :sswitch_4
    .end sparse-switch
.end method
