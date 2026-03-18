.class public final Ltechnology/cariad/cat/genx/CoreGenXStatusKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "coreGenXStatus",
        "Ltechnology/cariad/cat/genx/CoreGenXStatus;",
        "",
        "getCoreGenXStatus",
        "(I)Ltechnology/cariad/cat/genx/CoreGenXStatus;",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getCoreGenXStatus(I)Ltechnology/cariad/cat/genx/CoreGenXStatus;
    .locals 2

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSuccess()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-ne p0, v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSuccess()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :cond_0
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadContext()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-ne p0, v1, :cond_1

    .line 27
    .line 28
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadContext()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_1
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAlloc()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-ne p0, v1, :cond_2

    .line 42
    .line 43
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAlloc()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_2
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getInternal()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-ne p0, v1, :cond_3

    .line 57
    .line 58
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getInternal()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongMessageType()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-ne p0, v1, :cond_4

    .line 72
    .line 73
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongMessageType()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :cond_4
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongChannel()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-ne p0, v1, :cond_5

    .line 87
    .line 88
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongChannel()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :cond_5
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMAC()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-ne p0, v1, :cond_6

    .line 102
    .line 103
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMAC()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :cond_6
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getDecryptionFailure()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-ne p0, v1, :cond_7

    .line 117
    .line 118
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getDecryptionFailure()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    return-object p0

    .line 123
    :cond_7
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEncryptionFailure()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-ne p0, v1, :cond_8

    .line 132
    .line 133
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEncryptionFailure()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0

    .line 138
    :cond_8
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadHeader()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    if-ne p0, v1, :cond_9

    .line 147
    .line 148
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadHeader()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    return-object p0

    .line 153
    :cond_9
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageVariant()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 158
    .line 159
    .line 160
    move-result v1

    .line 161
    if-ne p0, v1, :cond_a

    .line 162
    .line 163
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageVariant()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0

    .line 168
    :cond_a
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadFrameCounter()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    if-ne p0, v1, :cond_b

    .line 177
    .line 178
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadFrameCounter()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    return-object p0

    .line 183
    :cond_b
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadClient()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 188
    .line 189
    .line 190
    move-result v1

    .line 191
    if-ne p0, v1, :cond_c

    .line 192
    .line 193
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadClient()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    return-object p0

    .line 198
    :cond_c
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadConnection()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 203
    .line 204
    .line 205
    move-result v1

    .line 206
    if-ne p0, v1, :cond_d

    .line 207
    .line 208
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadConnection()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    return-object p0

    .line 213
    :cond_d
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSendFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 218
    .line 219
    .line 220
    move-result v1

    .line 221
    if-ne p0, v1, :cond_e

    .line 222
    .line 223
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSendFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    return-object p0

    .line 228
    :cond_e
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getConnectFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    if-ne p0, v1, :cond_f

    .line 237
    .line 238
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getConnectFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    return-object p0

    .line 243
    :cond_f
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAuthState()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 248
    .line 249
    .line 250
    move-result v1

    .line 251
    if-ne p0, v1, :cond_10

    .line 252
    .line 253
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAuthState()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 254
    .line 255
    .line 256
    move-result-object p0

    .line 257
    return-object p0

    .line 258
    :cond_10
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSession()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 259
    .line 260
    .line 261
    move-result-object v1

    .line 262
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 263
    .line 264
    .line 265
    move-result v1

    .line 266
    if-ne p0, v1, :cond_11

    .line 267
    .line 268
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSession()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    return-object p0

    .line 273
    :cond_11
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadNonce()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    if-ne p0, v1, :cond_12

    .line 282
    .line 283
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadNonce()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    return-object p0

    .line 288
    :cond_12
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAuthCode()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 293
    .line 294
    .line 295
    move-result v1

    .line 296
    if-ne p0, v1, :cond_13

    .line 297
    .line 298
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAuthCode()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    return-object p0

    .line 303
    :cond_13
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageSize()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 304
    .line 305
    .line 306
    move-result-object v1

    .line 307
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 308
    .line 309
    .line 310
    move-result v1

    .line 311
    if-ne p0, v1, :cond_14

    .line 312
    .line 313
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageSize()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    return-object p0

    .line 318
    :cond_14
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSignature()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 319
    .line 320
    .line 321
    move-result-object v1

    .line 322
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 323
    .line 324
    .line 325
    move-result v1

    .line 326
    if-ne p0, v1, :cond_15

    .line 327
    .line 328
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSignature()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    return-object p0

    .line 333
    :cond_15
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadDestination()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 338
    .line 339
    .line 340
    move-result v1

    .line 341
    if-ne p0, v1, :cond_16

    .line 342
    .line 343
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadDestination()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 344
    .line 345
    .line 346
    move-result-object p0

    .line 347
    return-object p0

    .line 348
    :cond_16
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageId()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 353
    .line 354
    .line 355
    move-result v1

    .line 356
    if-ne p0, v1, :cond_17

    .line 357
    .line 358
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageId()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 359
    .line 360
    .line 361
    move-result-object p0

    .line 362
    return-object p0

    .line 363
    :cond_17
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAuthenticationFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 368
    .line 369
    .line 370
    move-result v1

    .line 371
    if-ne p0, v1, :cond_18

    .line 372
    .line 373
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAuthenticationFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 374
    .line 375
    .line 376
    move-result-object p0

    .line 377
    return-object p0

    .line 378
    :cond_18
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getKeyUpdateFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 383
    .line 384
    .line 385
    move-result v1

    .line 386
    if-ne p0, v1, :cond_19

    .line 387
    .line 388
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getKeyUpdateFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 389
    .line 390
    .line 391
    move-result-object p0

    .line 392
    return-object p0

    .line 393
    :cond_19
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadConnectionState()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 398
    .line 399
    .line 400
    move-result v1

    .line 401
    if-ne p0, v1, :cond_1a

    .line 402
    .line 403
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadConnectionState()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 404
    .line 405
    .line 406
    move-result-object p0

    .line 407
    return-object p0

    .line 408
    :cond_1a
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getCryptoOperationFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 409
    .line 410
    .line 411
    move-result-object v1

    .line 412
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 413
    .line 414
    .line 415
    move-result v1

    .line 416
    if-ne p0, v1, :cond_1b

    .line 417
    .line 418
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getCryptoOperationFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 419
    .line 420
    .line 421
    move-result-object p0

    .line 422
    return-object p0

    .line 423
    :cond_1b
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getFcFrameDataTooSmall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 428
    .line 429
    .line 430
    move-result v1

    .line 431
    if-ne p0, v1, :cond_1c

    .line 432
    .line 433
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getFcFrameDataTooSmall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 434
    .line 435
    .line 436
    move-result-object p0

    .line 437
    return-object p0

    .line 438
    :cond_1c
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getFcFrameDataTooLarge()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 439
    .line 440
    .line 441
    move-result-object v1

    .line 442
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 443
    .line 444
    .line 445
    move-result v1

    .line 446
    if-ne p0, v1, :cond_1d

    .line 447
    .line 448
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getFcFrameDataTooLarge()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 449
    .line 450
    .line 451
    move-result-object p0

    .line 452
    return-object p0

    .line 453
    :cond_1d
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAmFrameDataTooSmall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 454
    .line 455
    .line 456
    move-result-object v1

    .line 457
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 458
    .line 459
    .line 460
    move-result v1

    .line 461
    if-ne p0, v1, :cond_1e

    .line 462
    .line 463
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAmFrameDataTooSmall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 464
    .line 465
    .line 466
    move-result-object p0

    .line 467
    return-object p0

    .line 468
    :cond_1e
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAmFrameDataTooLarge()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 469
    .line 470
    .line 471
    move-result-object v1

    .line 472
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 473
    .line 474
    .line 475
    move-result v1

    .line 476
    if-ne p0, v1, :cond_1f

    .line 477
    .line 478
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAmFrameDataTooLarge()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 479
    .line 480
    .line 481
    move-result-object p0

    .line 482
    return-object p0

    .line 483
    :cond_1f
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD1MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 484
    .line 485
    .line 486
    move-result-object v1

    .line 487
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 488
    .line 489
    .line 490
    move-result v1

    .line 491
    if-ne p0, v1, :cond_20

    .line 492
    .line 493
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD1MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 494
    .line 495
    .line 496
    move-result-object p0

    .line 497
    return-object p0

    .line 498
    :cond_20
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD2MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 499
    .line 500
    .line 501
    move-result-object v1

    .line 502
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 503
    .line 504
    .line 505
    move-result v1

    .line 506
    if-ne p0, v1, :cond_21

    .line 507
    .line 508
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD2MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 509
    .line 510
    .line 511
    move-result-object p0

    .line 512
    return-object p0

    .line 513
    :cond_21
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD3MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 514
    .line 515
    .line 516
    move-result-object v1

    .line 517
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 518
    .line 519
    .line 520
    move-result v1

    .line 521
    if-ne p0, v1, :cond_22

    .line 522
    .line 523
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD3MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 524
    .line 525
    .line 526
    move-result-object p0

    .line 527
    return-object p0

    .line 528
    :cond_22
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD4MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 529
    .line 530
    .line 531
    move-result-object v1

    .line 532
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 533
    .line 534
    .line 535
    move-result v1

    .line 536
    if-ne p0, v1, :cond_23

    .line 537
    .line 538
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getD4MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 539
    .line 540
    .line 541
    move-result-object p0

    .line 542
    return-object p0

    .line 543
    :cond_23
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getM1MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 544
    .line 545
    .line 546
    move-result-object v1

    .line 547
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 548
    .line 549
    .line 550
    move-result v1

    .line 551
    if-ne p0, v1, :cond_24

    .line 552
    .line 553
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getM1MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 554
    .line 555
    .line 556
    move-result-object p0

    .line 557
    return-object p0

    .line 558
    :cond_24
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getM2MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 559
    .line 560
    .line 561
    move-result-object v1

    .line 562
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 563
    .line 564
    .line 565
    move-result v1

    .line 566
    if-ne p0, v1, :cond_25

    .line 567
    .line 568
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getM2MessageTimedOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 569
    .line 570
    .line 571
    move-result-object p0

    .line 572
    return-object p0

    .line 573
    :cond_25
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSchedulingHandler()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 574
    .line 575
    .line 576
    move-result-object v1

    .line 577
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 578
    .line 579
    .line 580
    move-result v1

    .line 581
    if-ne p0, v1, :cond_26

    .line 582
    .line 583
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSchedulingHandler()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 584
    .line 585
    .line 586
    move-result-object p0

    .line 587
    return-object p0

    .line 588
    :cond_26
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAttPayloadSizeInvalid()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 589
    .line 590
    .line 591
    move-result-object v1

    .line 592
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 593
    .line 594
    .line 595
    move-result v1

    .line 596
    if-ne p0, v1, :cond_27

    .line 597
    .line 598
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAttPayloadSizeInvalid()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 599
    .line 600
    .line 601
    move-result-object p0

    .line 602
    return-object p0

    .line 603
    :cond_27
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getRequiredPermissionsMissing()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 604
    .line 605
    .line 606
    move-result-object v1

    .line 607
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 608
    .line 609
    .line 610
    move-result v1

    .line 611
    if-ne p0, v1, :cond_28

    .line 612
    .line 613
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getRequiredPermissionsMissing()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 614
    .line 615
    .line 616
    move-result-object p0

    .line 617
    return-object p0

    .line 618
    :cond_28
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientDisabled()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 619
    .line 620
    .line 621
    move-result-object v1

    .line 622
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 623
    .line 624
    .line 625
    move-result v1

    .line 626
    if-ne p0, v1, :cond_29

    .line 627
    .line 628
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientDisabled()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 629
    .line 630
    .line 631
    move-result-object p0

    .line 632
    return-object p0

    .line 633
    :cond_29
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnbalancedStopCall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 634
    .line 635
    .line 636
    move-result-object v1

    .line 637
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 638
    .line 639
    .line 640
    move-result v1

    .line 641
    if-ne p0, v1, :cond_2a

    .line 642
    .line 643
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnbalancedStopCall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 644
    .line 645
    .line 646
    move-result-object p0

    .line 647
    return-object p0

    .line 648
    :cond_2a
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getLamResponseTimeout()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 649
    .line 650
    .line 651
    move-result-object v1

    .line 652
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 653
    .line 654
    .line 655
    move-result v1

    .line 656
    if-ne p0, v1, :cond_2b

    .line 657
    .line 658
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getLamResponseTimeout()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 659
    .line 660
    .line 661
    move-result-object p0

    .line 662
    return-object p0

    .line 663
    :cond_2b
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientScanFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 664
    .line 665
    .line 666
    move-result-object v1

    .line 667
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 668
    .line 669
    .line 670
    move-result v1

    .line 671
    if-ne p0, v1, :cond_2c

    .line 672
    .line 673
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientScanFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 674
    .line 675
    .line 676
    move-result-object p0

    .line 677
    return-object p0

    .line 678
    :cond_2c
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getServiceDiscoveryDataTooSmall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 683
    .line 684
    .line 685
    move-result v1

    .line 686
    if-ne p0, v1, :cond_2d

    .line 687
    .line 688
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getServiceDiscoveryDataTooSmall()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 689
    .line 690
    .line 691
    move-result-object p0

    .line 692
    return-object p0

    .line 693
    :cond_2d
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getServiceDiscoveryInvalidData()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 694
    .line 695
    .line 696
    move-result-object v1

    .line 697
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 698
    .line 699
    .line 700
    move-result v1

    .line 701
    if-ne p0, v1, :cond_2e

    .line 702
    .line 703
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getServiceDiscoveryInvalidData()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 704
    .line 705
    .line 706
    move-result-object p0

    .line 707
    return-object p0

    .line 708
    :cond_2e
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getServiceDiscoveryTimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 709
    .line 710
    .line 711
    move-result-object v1

    .line 712
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 713
    .line 714
    .line 715
    move-result v1

    .line 716
    if-ne p0, v1, :cond_2f

    .line 717
    .line 718
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getServiceDiscoveryTimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 719
    .line 720
    .line 721
    move-result-object p0

    .line 722
    return-object p0

    .line 723
    :cond_2f
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMapping()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 724
    .line 725
    .line 726
    move-result-object v1

    .line 727
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 728
    .line 729
    .line 730
    move-result v1

    .line 731
    if-ne p0, v1, :cond_30

    .line 732
    .line 733
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMapping()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 734
    .line 735
    .line 736
    move-result-object p0

    .line 737
    return-object p0

    .line 738
    :cond_30
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM2TimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 739
    .line 740
    .line 741
    move-result-object v1

    .line 742
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 743
    .line 744
    .line 745
    move-result v1

    .line 746
    if-ne p0, v1, :cond_31

    .line 747
    .line 748
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM2TimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 749
    .line 750
    .line 751
    move-result-object p0

    .line 752
    return-object p0

    .line 753
    :cond_31
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSequenceNumber()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 754
    .line 755
    .line 756
    move-result-object v1

    .line 757
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 758
    .line 759
    .line 760
    move-result v1

    .line 761
    if-ne p0, v1, :cond_32

    .line 762
    .line 763
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadSequenceNumber()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 764
    .line 765
    .line 766
    move-result-object p0

    .line 767
    return-object p0

    .line 768
    :cond_32
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadPriority()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 769
    .line 770
    .line 771
    move-result-object v1

    .line 772
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 773
    .line 774
    .line 775
    move-result v1

    .line 776
    if-ne p0, v1, :cond_33

    .line 777
    .line 778
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadPriority()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 779
    .line 780
    .line 781
    move-result-object p0

    .line 782
    return-object p0

    .line 783
    :cond_33
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getMaximumSequenceSizeExceeded()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 784
    .line 785
    .line 786
    move-result-object v1

    .line 787
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 788
    .line 789
    .line 790
    move-result v1

    .line 791
    if-ne p0, v1, :cond_34

    .line 792
    .line 793
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getMaximumSequenceSizeExceeded()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 794
    .line 795
    .line 796
    move-result-object p0

    .line 797
    return-object p0

    .line 798
    :cond_34
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnknownClient()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 799
    .line 800
    .line 801
    move-result-object v1

    .line 802
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 803
    .line 804
    .line 805
    move-result v1

    .line 806
    if-ne p0, v1, :cond_35

    .line 807
    .line 808
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnknownClient()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 809
    .line 810
    .line 811
    move-result-object p0

    .line 812
    return-object p0

    .line 813
    :cond_35
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getLamTimeout()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 814
    .line 815
    .line 816
    move-result-object v1

    .line 817
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 818
    .line 819
    .line 820
    move-result v1

    .line 821
    if-ne p0, v1, :cond_36

    .line 822
    .line 823
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getLamTimeout()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 824
    .line 825
    .line 826
    move-result-object p0

    .line 827
    return-object p0

    .line 828
    :cond_36
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM1TimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 829
    .line 830
    .line 831
    move-result-object v1

    .line 832
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 833
    .line 834
    .line 835
    move-result v1

    .line 836
    if-ne p0, v1, :cond_37

    .line 837
    .line 838
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM1TimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 839
    .line 840
    .line 841
    move-result-object p0

    .line 842
    return-object p0

    .line 843
    :cond_37
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM1SHAMismatch()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 844
    .line 845
    .line 846
    move-result-object v1

    .line 847
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 848
    .line 849
    .line 850
    move-result v1

    .line 851
    if-ne p0, v1, :cond_38

    .line 852
    .line 853
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM1SHAMismatch()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 854
    .line 855
    .line 856
    move-result-object p0

    .line 857
    return-object p0

    .line 858
    :cond_38
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAdvertisementFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 859
    .line 860
    .line 861
    move-result-object v1

    .line 862
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 863
    .line 864
    .line 865
    move-result v1

    .line 866
    if-ne p0, v1, :cond_39

    .line 867
    .line 868
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAdvertisementFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 869
    .line 870
    .line 871
    move-result-object p0

    .line 872
    return-object p0

    .line 873
    :cond_39
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getCantSendOnKeyExchange()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 874
    .line 875
    .line 876
    move-result-object v1

    .line 877
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 878
    .line 879
    .line 880
    move-result v1

    .line 881
    if-ne p0, v1, :cond_3a

    .line 882
    .line 883
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getCantSendOnKeyExchange()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 884
    .line 885
    .line 886
    move-result-object p0

    .line 887
    return-object p0

    .line 888
    :cond_3a
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageData()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 889
    .line 890
    .line 891
    move-result-object v1

    .line 892
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 893
    .line 894
    .line 895
    move-result v1

    .line 896
    if-ne p0, v1, :cond_3b

    .line 897
    .line 898
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadMessageData()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 899
    .line 900
    .line 901
    move-result-object p0

    .line 902
    return-object p0

    .line 903
    :cond_3b
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getKeyExchangeCanceled()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 904
    .line 905
    .line 906
    move-result-object v1

    .line 907
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 908
    .line 909
    .line 910
    move-result v1

    .line 911
    if-ne p0, v1, :cond_3c

    .line 912
    .line 913
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getKeyExchangeCanceled()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 914
    .line 915
    .line 916
    move-result-object p0

    .line 917
    return-object p0

    .line 918
    :cond_3c
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM3TimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 919
    .line 920
    .line 921
    move-result-object v1

    .line 922
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 923
    .line 924
    .line 925
    move-result v1

    .line 926
    if-ne p0, v1, :cond_3d

    .line 927
    .line 928
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getQpM3TimeOut()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 929
    .line 930
    .line 931
    move-result-object p0

    .line 932
    return-object p0

    .line 933
    :cond_3d
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getKeyExchangeIsAlreadyGoingOn()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 934
    .line 935
    .line 936
    move-result-object v1

    .line 937
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 938
    .line 939
    .line 940
    move-result v1

    .line 941
    if-ne p0, v1, :cond_3e

    .line 942
    .line 943
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getKeyExchangeIsAlreadyGoingOn()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 944
    .line 945
    .line 946
    move-result-object p0

    .line 947
    return-object p0

    .line 948
    :cond_3e
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getARegularConnectionIsAlreadyGoingOn()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 949
    .line 950
    .line 951
    move-result-object v1

    .line 952
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 953
    .line 954
    .line 955
    move-result v1

    .line 956
    if-ne p0, v1, :cond_3f

    .line 957
    .line 958
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getARegularConnectionIsAlreadyGoingOn()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 959
    .line 960
    .line 961
    move-result-object p0

    .line 962
    return-object p0

    .line 963
    :cond_3f
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAccessoryControlRegularConnectionRequired()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 964
    .line 965
    .line 966
    move-result-object v1

    .line 967
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 968
    .line 969
    .line 970
    move-result v1

    .line 971
    if-ne p0, v1, :cond_40

    .line 972
    .line 973
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getAccessoryControlRegularConnectionRequired()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 974
    .line 975
    .line 976
    move-result-object p0

    .line 977
    return-object p0

    .line 978
    :cond_40
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getMustBeInKeyExchange()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 979
    .line 980
    .line 981
    move-result-object v1

    .line 982
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 983
    .line 984
    .line 985
    move-result v1

    .line 986
    if-ne p0, v1, :cond_41

    .line 987
    .line 988
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getMustBeInKeyExchange()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 989
    .line 990
    .line 991
    move-result-object p0

    .line 992
    return-object p0

    .line 993
    :cond_41
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadChannel()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 994
    .line 995
    .line 996
    move-result-object v1

    .line 997
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 998
    .line 999
    .line 1000
    move-result v1

    .line 1001
    if-ne p0, v1, :cond_42

    .line 1002
    .line 1003
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadChannel()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1004
    .line 1005
    .line 1006
    move-result-object p0

    .line 1007
    return-object p0

    .line 1008
    :cond_42
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBufferNotLargeEnough()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1009
    .line 1010
    .line 1011
    move-result-object v1

    .line 1012
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1013
    .line 1014
    .line 1015
    move-result v1

    .line 1016
    if-ne p0, v1, :cond_43

    .line 1017
    .line 1018
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBufferNotLargeEnough()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1019
    .line 1020
    .line 1021
    move-result-object p0

    .line 1022
    return-object p0

    .line 1023
    :cond_43
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getNeedToStartFirst()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v1

    .line 1027
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1028
    .line 1029
    .line 1030
    move-result v1

    .line 1031
    if-ne p0, v1, :cond_44

    .line 1032
    .line 1033
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getNeedToStartFirst()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1034
    .line 1035
    .line 1036
    move-result-object p0

    .line 1037
    return-object p0

    .line 1038
    :cond_44
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getNotFound()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v1

    .line 1042
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1043
    .line 1044
    .line 1045
    move-result v1

    .line 1046
    if-ne p0, v1, :cond_45

    .line 1047
    .line 1048
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getNotFound()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1049
    .line 1050
    .line 1051
    move-result-object p0

    .line 1052
    return-object p0

    .line 1053
    :cond_45
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getVehicleNotInPairingActive()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v1

    .line 1057
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1058
    .line 1059
    .line 1060
    move-result v1

    .line 1061
    if-ne p0, v1, :cond_46

    .line 1062
    .line 1063
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getVehicleNotInPairingActive()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1064
    .line 1065
    .line 1066
    move-result-object p0

    .line 1067
    return-object p0

    .line 1068
    :cond_46
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getConnectFailedAndPairingIsInvalid()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v1

    .line 1072
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1073
    .line 1074
    .line 1075
    move-result v1

    .line 1076
    if-ne p0, v1, :cond_47

    .line 1077
    .line 1078
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getConnectFailedAndPairingIsInvalid()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1079
    .line 1080
    .line 1081
    move-result-object p0

    .line 1082
    return-object p0

    .line 1083
    :cond_47
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongTypedFrameType()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v1

    .line 1087
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1088
    .line 1089
    .line 1090
    move-result v1

    .line 1091
    if-ne p0, v1, :cond_48

    .line 1092
    .line 1093
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongTypedFrameType()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1094
    .line 1095
    .line 1096
    move-result-object p0

    .line 1097
    return-object p0

    .line 1098
    :cond_48
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAntenna()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v1

    .line 1102
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1103
    .line 1104
    .line 1105
    move-result v1

    .line 1106
    if-ne p0, v1, :cond_49

    .line 1107
    .line 1108
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getBadAntenna()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1109
    .line 1110
    .line 1111
    move-result-object p0

    .line 1112
    return-object p0

    .line 1113
    :cond_49
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getVehicleAlreadyRegistered()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v1

    .line 1117
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1118
    .line 1119
    .line 1120
    move-result v1

    .line 1121
    if-ne p0, v1, :cond_4a

    .line 1122
    .line 1123
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getVehicleAlreadyRegistered()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1124
    .line 1125
    .line 1126
    move-result-object p0

    .line 1127
    return-object p0

    .line 1128
    :cond_4a
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getVehicleAntennaAlreadyPaired()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1129
    .line 1130
    .line 1131
    move-result-object v1

    .line 1132
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1133
    .line 1134
    .line 1135
    move-result v1

    .line 1136
    if-ne p0, v1, :cond_4b

    .line 1137
    .line 1138
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getVehicleAntennaAlreadyPaired()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1139
    .line 1140
    .line 1141
    move-result-object p0

    .line 1142
    return-object p0

    .line 1143
    :cond_4b
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientDisconnectedDuringKeyExchange()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v1

    .line 1147
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1148
    .line 1149
    .line 1150
    move-result v1

    .line 1151
    if-ne p0, v1, :cond_4c

    .line 1152
    .line 1153
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientDisconnectedDuringKeyExchange()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1154
    .line 1155
    .line 1156
    move-result-object p0

    .line 1157
    return-object p0

    .line 1158
    :cond_4c
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEkemTimeout()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v1

    .line 1162
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1163
    .line 1164
    .line 1165
    move-result v1

    .line 1166
    if-ne p0, v1, :cond_4d

    .line 1167
    .line 1168
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEkemTimeout()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1169
    .line 1170
    .line 1171
    move-result-object p0

    .line 1172
    return-object p0

    .line 1173
    :cond_4d
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEkemFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1174
    .line 1175
    .line 1176
    move-result-object v1

    .line 1177
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1178
    .line 1179
    .line 1180
    move-result v1

    .line 1181
    if-ne p0, v1, :cond_4e

    .line 1182
    .line 1183
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEkemFailed()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1184
    .line 1185
    .line 1186
    move-result-object p0

    .line 1187
    return-object p0

    .line 1188
    :cond_4e
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnsupportedEncryptionKeyType()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v1

    .line 1192
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1193
    .line 1194
    .line 1195
    move-result v1

    .line 1196
    if-ne p0, v1, :cond_4f

    .line 1197
    .line 1198
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnsupportedEncryptionKeyType()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1199
    .line 1200
    .line 1201
    move-result-object p0

    .line 1202
    return-object p0

    .line 1203
    :cond_4f
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnsupportedDeviceUUID()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v1

    .line 1207
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1208
    .line 1209
    .line 1210
    move-result v1

    .line 1211
    if-ne p0, v1, :cond_50

    .line 1212
    .line 1213
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getUnsupportedDeviceUUID()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1214
    .line 1215
    .line 1216
    move-result-object p0

    .line 1217
    return-object p0

    .line 1218
    :cond_50
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEncryptedKeyExchangeNotPossible()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1219
    .line 1220
    .line 1221
    move-result-object v1

    .line 1222
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 1223
    .line 1224
    .line 1225
    move-result v1

    .line 1226
    if-ne p0, v1, :cond_51

    .line 1227
    .line 1228
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getEncryptedKeyExchangeNotPossible()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1229
    .line 1230
    .line 1231
    move-result-object p0

    .line 1232
    return-object p0

    .line 1233
    :cond_51
    new-instance v0, Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 1234
    .line 1235
    const-string v1, "Unknown"

    .line 1236
    .line 1237
    invoke-direct {v0, v1, p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;-><init>(Ljava/lang/String;I)V

    .line 1238
    .line 1239
    .line 1240
    return-object v0
.end method
