.class public final synthetic La8/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;
.implements Lgr/e;
.implements Lno/nordicsemi/android/ble/t;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, La8/w;->d:I

    iput p1, p0, La8/w;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lb8/a;ILt7/k0;Lt7/k0;)V
    .locals 0

    .line 2
    const/4 p1, 0x3

    iput p1, p0, La8/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, La8/w;->e:I

    return-void
.end method


# virtual methods
.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Integer;

    .line 2
    .line 3
    iget p0, p0, La8/w;->e:I

    .line 4
    .line 5
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public d()Ljava/lang/String;
    .locals 6

    .line 1
    iget v0, p0, La8/w;->d:I

    .line 2
    .line 3
    const-string v1, "Unexpected value: "

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    const-string v4, "UNKNOWN ("

    .line 8
    .line 9
    const-string v5, ")"

    .line 10
    .line 11
    iget p0, p0, La8/w;->e:I

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    new-instance v0, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v1, "[Broadcast] Action received: android.bluetooth.device.action.BOND_STATE_CHANGED, bond state changed to: "

    .line 19
    .line 20
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sget-object v1, Lc01/a;->a:[C

    .line 24
    .line 25
    packed-switch p0, :pswitch_data_1

    .line 26
    .line 27
    .line 28
    invoke-static {v4, p0, v5}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    goto :goto_0

    .line 33
    :pswitch_0
    const-string v1, "BOND_BONDED"

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :pswitch_1
    const-string v1, "BOND_BONDING"

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :pswitch_2
    const-string v1, "BOND_NONE"

    .line 40
    .line 41
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, " ("

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    const-string v1, "characteristic.setWriteType("

    .line 63
    .line 64
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-static {p0}, Lc01/a;->e(I)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    :pswitch_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 83
    .line 84
    const-string v1, "Error (0x"

    .line 85
    .line 86
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v1, "): "

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const/16 v1, 0x22

    .line 102
    .line 103
    if-eq p0, v1, :cond_5

    .line 104
    .line 105
    const/16 v1, 0x29

    .line 106
    .line 107
    if-eq p0, v1, :cond_4

    .line 108
    .line 109
    const/16 v1, 0x93

    .line 110
    .line 111
    if-eq p0, v1, :cond_3

    .line 112
    .line 113
    const/16 v1, 0x101

    .line 114
    .line 115
    if-eq p0, v1, :cond_2

    .line 116
    .line 117
    const/16 v1, 0x3a

    .line 118
    .line 119
    if-eq p0, v1, :cond_1

    .line 120
    .line 121
    const/16 v1, 0x3b

    .line 122
    .line 123
    if-eq p0, v1, :cond_0

    .line 124
    .line 125
    packed-switch p0, :pswitch_data_2

    .line 126
    .line 127
    .line 128
    packed-switch p0, :pswitch_data_3

    .line 129
    .line 130
    .line 131
    packed-switch p0, :pswitch_data_4

    .line 132
    .line 133
    .line 134
    invoke-static {v4, p0, v5}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    goto/16 :goto_1

    .line 139
    .line 140
    :pswitch_5
    const-string p0, "GATT VALUE OUT OF RANGE"

    .line 141
    .line 142
    goto/16 :goto_1

    .line 143
    .line 144
    :pswitch_6
    const-string p0, "GATT PROCEDURE IN PROGRESS"

    .line 145
    .line 146
    goto/16 :goto_1

    .line 147
    .line 148
    :pswitch_7
    const-string p0, "GATT CCCD CFG ERROR"

    .line 149
    .line 150
    goto/16 :goto_1

    .line 151
    .line 152
    :pswitch_8
    const-string p0, "GATT CONGESTED"

    .line 153
    .line 154
    goto/16 :goto_1

    .line 155
    .line 156
    :pswitch_9
    const-string p0, "GATT NOT ENCRYPTED"

    .line 157
    .line 158
    goto/16 :goto_1

    .line 159
    .line 160
    :pswitch_a
    const-string p0, "GATT ENCRYPTED NO MITM"

    .line 161
    .line 162
    goto/16 :goto_1

    .line 163
    .line 164
    :pswitch_b
    const-string p0, "GATT SERVICE STARTED"

    .line 165
    .line 166
    goto/16 :goto_1

    .line 167
    .line 168
    :pswitch_c
    const-string p0, "GATT INVALID CFG"

    .line 169
    .line 170
    goto/16 :goto_1

    .line 171
    .line 172
    :pswitch_d
    const-string p0, "GATT MORE"

    .line 173
    .line 174
    goto/16 :goto_1

    .line 175
    .line 176
    :pswitch_e
    const-string p0, "GATT AUTH FAIL"

    .line 177
    .line 178
    goto/16 :goto_1

    .line 179
    .line 180
    :pswitch_f
    const-string p0, "GATT PENDING"

    .line 181
    .line 182
    goto/16 :goto_1

    .line 183
    .line 184
    :pswitch_10
    const-string p0, "GATT ILLEGAL PARAMETER"

    .line 185
    .line 186
    goto/16 :goto_1

    .line 187
    .line 188
    :pswitch_11
    const-string p0, "GATT CMD STARTED"

    .line 189
    .line 190
    goto/16 :goto_1

    .line 191
    .line 192
    :pswitch_12
    const-string p0, "GATT ERROR"

    .line 193
    .line 194
    goto/16 :goto_1

    .line 195
    .line 196
    :pswitch_13
    const-string p0, "GATT BUSY"

    .line 197
    .line 198
    goto/16 :goto_1

    .line 199
    .line 200
    :pswitch_14
    const-string p0, "GATT DB FULL"

    .line 201
    .line 202
    goto/16 :goto_1

    .line 203
    .line 204
    :pswitch_15
    const-string p0, "GATT WRONG STATE"

    .line 205
    .line 206
    goto :goto_1

    .line 207
    :pswitch_16
    const-string p0, "GATT INTERNAL ERROR"

    .line 208
    .line 209
    goto :goto_1

    .line 210
    :pswitch_17
    const-string p0, "GATT NO RESOURCES"

    .line 211
    .line 212
    goto :goto_1

    .line 213
    :pswitch_18
    const-string p0, "GATT INSUF RESOURCE"

    .line 214
    .line 215
    goto :goto_1

    .line 216
    :pswitch_19
    const-string p0, "GATT UNSUPPORT GRP TYPE"

    .line 217
    .line 218
    goto :goto_1

    .line 219
    :pswitch_1a
    const-string p0, "GATT INSUF ENCRYPTION"

    .line 220
    .line 221
    goto :goto_1

    .line 222
    :pswitch_1b
    const-string p0, "GATT ERR UNLIKELY"

    .line 223
    .line 224
    goto :goto_1

    .line 225
    :pswitch_1c
    const-string p0, "GATT INVALID ATTR LEN"

    .line 226
    .line 227
    goto :goto_1

    .line 228
    :pswitch_1d
    const-string p0, "GATT INSUF KEY SIZE"

    .line 229
    .line 230
    goto :goto_1

    .line 231
    :pswitch_1e
    const-string p0, "GATT NOT LONG"

    .line 232
    .line 233
    goto :goto_1

    .line 234
    :pswitch_1f
    const-string p0, "GATT NOT FOUND"

    .line 235
    .line 236
    goto :goto_1

    .line 237
    :pswitch_20
    const-string p0, "GATT PREPARE Q FULL"

    .line 238
    .line 239
    goto :goto_1

    .line 240
    :pswitch_21
    const-string p0, "GATT INSUF AUTHORIZATION"

    .line 241
    .line 242
    goto :goto_1

    .line 243
    :pswitch_22
    const-string p0, "GATT INVALID OFFSET"

    .line 244
    .line 245
    goto :goto_1

    .line 246
    :pswitch_23
    const-string p0, "GATT REQ NOT SUPPORTED"

    .line 247
    .line 248
    goto :goto_1

    .line 249
    :pswitch_24
    const-string p0, "GATT INSUF AUTHENTICATION"

    .line 250
    .line 251
    goto :goto_1

    .line 252
    :pswitch_25
    const-string p0, "GATT INVALID PDU"

    .line 253
    .line 254
    goto :goto_1

    .line 255
    :pswitch_26
    const-string p0, "GATT WRITE NOT PERMIT"

    .line 256
    .line 257
    goto :goto_1

    .line 258
    :pswitch_27
    const-string p0, "GATT READ NOT PERMIT"

    .line 259
    .line 260
    goto :goto_1

    .line 261
    :pswitch_28
    const-string p0, "GATT INVALID HANDLE"

    .line 262
    .line 263
    goto :goto_1

    .line 264
    :cond_0
    const-string p0, "GATT UNACCEPT CONN INTERVAL"

    .line 265
    .line 266
    goto :goto_1

    .line 267
    :cond_1
    const-string p0, "GATT CONTROLLER BUSY"

    .line 268
    .line 269
    goto :goto_1

    .line 270
    :cond_2
    const-string p0, "TOO MANY OPEN CONNECTIONS"

    .line 271
    .line 272
    goto :goto_1

    .line 273
    :cond_3
    const-string p0, "GATT TIMEOUT"

    .line 274
    .line 275
    goto :goto_1

    .line 276
    :cond_4
    const-string p0, "GATT PAIRING WITH UNIT KEY NOT SUPPORTED"

    .line 277
    .line 278
    goto :goto_1

    .line 279
    :cond_5
    const-string p0, "GATT CONN LMP TIMEOUT"

    .line 280
    .line 281
    :goto_1
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 282
    .line 283
    .line 284
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    return-object p0

    .line 289
    :pswitch_29
    if-eqz p0, :cond_8

    .line 290
    .line 291
    if-eq p0, v3, :cond_7

    .line 292
    .line 293
    if-ne p0, v2, :cond_6

    .line 294
    .line 295
    const-string p0, "LOW POWER"

    .line 296
    .line 297
    goto :goto_2

    .line 298
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 299
    .line 300
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 305
    .line 306
    .line 307
    throw v0

    .line 308
    :cond_7
    const-string p0, "HIGH"

    .line 309
    .line 310
    goto :goto_2

    .line 311
    :cond_8
    const-string p0, "BALANCED"

    .line 312
    .line 313
    :goto_2
    const-string v0, "gatt.requestConnectionPriority("

    .line 314
    .line 315
    invoke-static {v0, p0, v5}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object p0

    .line 319
    return-object p0

    .line 320
    :pswitch_2a
    if-eqz p0, :cond_b

    .line 321
    .line 322
    if-eq p0, v3, :cond_a

    .line 323
    .line 324
    if-ne p0, v2, :cond_9

    .line 325
    .line 326
    const-string p0, "LOW POWER (100\u2013125ms, 2, 5s)"

    .line 327
    .line 328
    goto :goto_3

    .line 329
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 330
    .line 331
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object p0

    .line 335
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    throw v0

    .line 339
    :cond_a
    const-string p0, "HIGH (11.25\u201315ms, 0, 5s)"

    .line 340
    .line 341
    goto :goto_3

    .line 342
    :cond_b
    const-string p0, "BALANCED (30\u201350ms, 0, 5s)"

    .line 343
    .line 344
    :goto_3
    const-string v0, "Requesting connection priority: "

    .line 345
    .line 346
    const-string v1, "..."

    .line 347
    .line 348
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    return-object p0

    .line 353
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_2a
        :pswitch_29
        :pswitch_4
        :pswitch_3
    .end packed-switch

    .line 354
    .line 355
    .line 356
    .line 357
    .line 358
    .line 359
    .line 360
    .line 361
    .line 362
    .line 363
    .line 364
    .line 365
    :pswitch_data_1
    .packed-switch 0xa
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 366
    .line 367
    .line 368
    .line 369
    .line 370
    .line 371
    .line 372
    .line 373
    .line 374
    .line 375
    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
    .end packed-switch

    .line 376
    .line 377
    .line 378
    .line 379
    .line 380
    .line 381
    .line 382
    .line 383
    .line 384
    .line 385
    .line 386
    .line 387
    .line 388
    .line 389
    .line 390
    .line 391
    .line 392
    .line 393
    .line 394
    .line 395
    .line 396
    .line 397
    .line 398
    .line 399
    .line 400
    .line 401
    .line 402
    .line 403
    .line 404
    .line 405
    .line 406
    .line 407
    .line 408
    .line 409
    .line 410
    .line 411
    .line 412
    .line 413
    :pswitch_data_3
    .packed-switch 0x80
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
    .end packed-switch

    .line 414
    .line 415
    .line 416
    .line 417
    .line 418
    .line 419
    .line 420
    .line 421
    .line 422
    .line 423
    .line 424
    .line 425
    .line 426
    .line 427
    .line 428
    .line 429
    .line 430
    .line 431
    .line 432
    .line 433
    .line 434
    .line 435
    .line 436
    .line 437
    .line 438
    .line 439
    .line 440
    .line 441
    .line 442
    .line 443
    .line 444
    .line 445
    .line 446
    .line 447
    .line 448
    .line 449
    :pswitch_data_4
    .packed-switch 0xfd
        :pswitch_7
        :pswitch_6
        :pswitch_5
    .end packed-switch
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, La8/w;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb8/j;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget p0, p0, La8/w;->e:I

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    if-ne p0, v0, :cond_0

    .line 15
    .line 16
    iput-boolean v0, p1, Lb8/j;->v:Z

    .line 17
    .line 18
    :cond_0
    iput p0, p1, Lb8/j;->l:I

    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_0
    iget p0, p0, La8/w;->e:I

    .line 22
    .line 23
    check-cast p1, Lt7/j0;

    .line 24
    .line 25
    invoke-interface {p1, p0}, Lt7/j0;->g(I)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_1
    iget p0, p0, La8/w;->e:I

    .line 30
    .line 31
    check-cast p1, Lt7/j0;

    .line 32
    .line 33
    invoke-interface {p1, p0}, Lt7/j0;->A(I)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
