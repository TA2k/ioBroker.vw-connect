.class public final Lx41/t0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/util/Set;

.field public final synthetic g:Lx41/u0;

.field public final synthetic h:Ltechnology/cariad/cat/genx/Vehicle;


# direct methods
.method public constructor <init>(Ljava/util/Set;Lx41/u0;Ltechnology/cariad/cat/genx/Vehicle;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx41/t0;->f:Ljava/util/Set;

    .line 2
    .line 3
    iput-object p2, p0, Lx41/t0;->g:Lx41/u0;

    .line 4
    .line 5
    iput-object p3, p0, Lx41/t0;->h:Ltechnology/cariad/cat/genx/Vehicle;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lx41/t0;

    .line 2
    .line 3
    iget-object v1, p0, Lx41/t0;->g:Lx41/u0;

    .line 4
    .line 5
    iget-object v2, p0, Lx41/t0;->h:Ltechnology/cariad/cat/genx/Vehicle;

    .line 6
    .line 7
    iget-object p0, p0, Lx41/t0;->f:Ljava/util/Set;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lx41/t0;-><init>(Ljava/util/Set;Lx41/u0;Ltechnology/cariad/cat/genx/Vehicle;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lx41/t0;->e:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lx41/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lx41/t0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lx41/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lx41/t0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lx41/t0;->d:I

    .line 10
    .line 11
    const/4 v4, 0x3

    .line 12
    const/4 v5, 0x2

    .line 13
    const/4 v6, 0x1

    .line 14
    if-eqz v3, :cond_2

    .line 15
    .line 16
    if-eq v3, v6, :cond_1

    .line 17
    .line 18
    if-eq v3, v5, :cond_1

    .line 19
    .line 20
    if-ne v3, v4, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw v0

    .line 31
    :cond_1
    :goto_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    goto/16 :goto_4

    .line 35
    .line 36
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    instance-of v3, v1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;

    .line 40
    .line 41
    const-string v7, "getName(...)"

    .line 42
    .line 43
    sget-object v10, Lt51/g;->a:Lt51/g;

    .line 44
    .line 45
    iget-object v15, v0, Lx41/t0;->g:Lx41/u0;

    .line 46
    .line 47
    const/4 v8, 0x0

    .line 48
    if-eqz v3, :cond_6

    .line 49
    .line 50
    move-object v3, v1

    .line 51
    check-cast v3, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;

    .line 52
    .line 53
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    invoke-virtual {v4}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    invoke-virtual {v4}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 74
    .line 75
    .line 76
    move-result-object v9

    .line 77
    invoke-virtual {v9}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    .line 78
    .line 79
    .line 80
    move-result v9

    .line 81
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 82
    .line 83
    .line 84
    move-result-object v11

    .line 85
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    iget-object v12, v0, Lx41/t0;->f:Ljava/util/Set;

    .line 90
    .line 91
    check-cast v12, Ljava/lang/Iterable;

    .line 92
    .line 93
    instance-of v13, v12, Ljava/util/Collection;

    .line 94
    .line 95
    if-eqz v13, :cond_3

    .line 96
    .line 97
    move-object v13, v12

    .line 98
    check-cast v13, Ljava/util/Collection;

    .line 99
    .line 100
    invoke-interface {v13}, Ljava/util/Collection;->isEmpty()Z

    .line 101
    .line 102
    .line 103
    move-result v13

    .line 104
    if-eqz v13, :cond_3

    .line 105
    .line 106
    goto/16 :goto_2

    .line 107
    .line 108
    :cond_3
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v12

    .line 112
    :goto_1
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v13

    .line 116
    if-eqz v13, :cond_5

    .line 117
    .line 118
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v13

    .line 122
    check-cast v13, Lx41/n;

    .line 123
    .line 124
    invoke-interface {v13}, Lx41/n;->getVin()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v14

    .line 128
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v14

    .line 132
    if-eqz v14, :cond_4

    .line 133
    .line 134
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaUpdated;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    .line 135
    .line 136
    .line 137
    move-result-object v14

    .line 138
    invoke-static {v13, v14}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 139
    .line 140
    .line 141
    move-result v13

    .line 142
    if-eqz v13, :cond_4

    .line 143
    .line 144
    move v13, v11

    .line 145
    new-instance v11, Lx41/s0;

    .line 146
    .line 147
    const/4 v3, 0x0

    .line 148
    invoke-direct {v11, v1, v3}, Lx41/s0;-><init>(Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;I)V

    .line 149
    .line 150
    .line 151
    move-object v1, v8

    .line 152
    new-instance v8, Lt51/j;

    .line 153
    .line 154
    move v3, v13

    .line 155
    invoke-static {v15}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v13

    .line 159
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v14

    .line 163
    move v7, v9

    .line 164
    const-string v9, "Car2PhonePairing"

    .line 165
    .line 166
    const/4 v12, 0x0

    .line 167
    move/from16 v16, v7

    .line 168
    .line 169
    move-object v7, v1

    .line 170
    move/from16 v1, v16

    .line 171
    .line 172
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 176
    .line 177
    .line 178
    sget-object v8, Lx41/j;->Companion:Lx41/i;

    .line 179
    .line 180
    new-instance v9, Lx41/f;

    .line 181
    .line 182
    int-to-short v1, v1

    .line 183
    int-to-short v3, v3

    .line 184
    invoke-direct {v9, v5, v1, v3}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 188
    .line 189
    .line 190
    invoke-static {v4, v9}, Lx41/i;->a(Ljava/lang/String;Lx41/f;)Lx41/j;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    iput-object v7, v0, Lx41/t0;->e:Ljava/lang/Object;

    .line 195
    .line 196
    iput v6, v0, Lx41/t0;->d:I

    .line 197
    .line 198
    invoke-virtual {v15, v1, v0}, Lx41/u0;->a(Lx41/n;Lrx0/c;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-ne v0, v2, :cond_8

    .line 203
    .line 204
    goto/16 :goto_3

    .line 205
    .line 206
    :cond_4
    move v13, v9

    .line 207
    move-object v9, v8

    .line 208
    move v8, v13

    .line 209
    move v13, v11

    .line 210
    move-object v11, v9

    .line 211
    move v9, v8

    .line 212
    move-object v8, v11

    .line 213
    move v11, v13

    .line 214
    goto :goto_1

    .line 215
    :cond_5
    :goto_2
    new-instance v11, Lx41/s0;

    .line 216
    .line 217
    const/4 v0, 0x1

    .line 218
    invoke-direct {v11, v1, v0}, Lx41/s0;-><init>(Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;I)V

    .line 219
    .line 220
    .line 221
    new-instance v8, Lt51/j;

    .line 222
    .line 223
    invoke-static {v15}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v13

    .line 227
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v14

    .line 231
    const-string v9, "Car2PhonePairing"

    .line 232
    .line 233
    const/4 v12, 0x0

    .line 234
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_4

    .line 241
    .line 242
    :cond_6
    move-object v9, v8

    .line 243
    instance-of v3, v1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;

    .line 244
    .line 245
    if-eqz v3, :cond_7

    .line 246
    .line 247
    new-instance v11, Lx41/s0;

    .line 248
    .line 249
    const/4 v3, 0x2

    .line 250
    invoke-direct {v11, v1, v3}, Lx41/s0;-><init>(Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;I)V

    .line 251
    .line 252
    .line 253
    new-instance v8, Lt51/j;

    .line 254
    .line 255
    invoke-static {v15}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v13

    .line 259
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v14

    .line 263
    move-object v7, v9

    .line 264
    const-string v9, "Car2PhonePairing"

    .line 265
    .line 266
    const/4 v12, 0x0

    .line 267
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 271
    .line 272
    .line 273
    check-cast v1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;

    .line 274
    .line 275
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 276
    .line 277
    .line 278
    move-result-object v3

    .line 279
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 288
    .line 289
    .line 290
    move-result-object v4

    .line 291
    invoke-virtual {v4}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getRemoteCredentials()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 292
    .line 293
    .line 294
    move-result-object v4

    .line 295
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 296
    .line 297
    .line 298
    move-result-object v6

    .line 299
    invoke-virtual {v6}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMajor-Mh2AYeg()S

    .line 300
    .line 301
    .line 302
    move-result v6

    .line 303
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 304
    .line 305
    .line 306
    move-result-object v1

    .line 307
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getBeaconMinor-Mh2AYeg()S

    .line 308
    .line 309
    .line 310
    move-result v1

    .line 311
    sget-object v8, Lx41/j;->Companion:Lx41/i;

    .line 312
    .line 313
    new-instance v9, Lx41/f;

    .line 314
    .line 315
    int-to-short v6, v6

    .line 316
    int-to-short v1, v1

    .line 317
    invoke-direct {v9, v4, v6, v1}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 318
    .line 319
    .line 320
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 321
    .line 322
    .line 323
    invoke-static {v3, v9}, Lx41/i;->a(Ljava/lang/String;Lx41/f;)Lx41/j;

    .line 324
    .line 325
    .line 326
    move-result-object v1

    .line 327
    iput-object v7, v0, Lx41/t0;->e:Ljava/lang/Object;

    .line 328
    .line 329
    iput v5, v0, Lx41/t0;->d:I

    .line 330
    .line 331
    invoke-virtual {v15, v1, v0}, Lx41/u0;->a(Lx41/n;Lrx0/c;)Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    if-ne v0, v2, :cond_8

    .line 336
    .line 337
    goto :goto_3

    .line 338
    :cond_7
    move-object v7, v9

    .line 339
    instance-of v3, v1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;

    .line 340
    .line 341
    if-eqz v3, :cond_9

    .line 342
    .line 343
    iget-object v3, v0, Lx41/t0;->h:Ltechnology/cariad/cat/genx/Vehicle;

    .line 344
    .line 345
    invoke-interface {v3}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v3

    .line 349
    check-cast v1, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;

    .line 350
    .line 351
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaRemoved;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    .line 352
    .line 353
    .line 354
    move-result-object v1

    .line 355
    iput-object v7, v0, Lx41/t0;->e:Ljava/lang/Object;

    .line 356
    .line 357
    iput v4, v0, Lx41/t0;->d:I

    .line 358
    .line 359
    invoke-virtual {v15, v3, v1, v0}, Lx41/u0;->k(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Lrx0/c;)Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    if-ne v0, v2, :cond_8

    .line 364
    .line 365
    :goto_3
    return-object v2

    .line 366
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 367
    .line 368
    return-object v0

    .line 369
    :cond_9
    new-instance v0, La8/r0;

    .line 370
    .line 371
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 372
    .line 373
    .line 374
    throw v0
.end method
