.class public final synthetic Lc41/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lh2/o3;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lc41/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc41/b;->g:Ljava/lang/Object;

    iput-object p3, p0, Lc41/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lg61/q;Lay0/a;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x7

    iput v0, p0, Lc41/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Lc41/b;->g:Ljava/lang/Object;

    iput-object p3, p0, Lc41/b;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 3
    iput p4, p0, Lc41/b;->d:I

    iput-object p1, p0, Lc41/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc41/b;->f:Ljava/lang/Object;

    iput-object p3, p0, Lc41/b;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Lay0/k;Lr60/j;)V
    .locals 1

    .line 5
    const/16 v0, 0x17

    iput v0, p0, Lc41/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Lc41/b;->e:Ljava/lang/Object;

    iput-object p3, p0, Lc41/b;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ll2/t;Lm2/a;Ll2/e2;Ll2/a1;)V
    .locals 0

    .line 4
    const/16 p4, 0xf

    iput p4, p0, Lc41/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc41/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc41/b;->f:Ljava/lang/Object;

    iput-object p3, p0, Lc41/b;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc41/b;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x6

    .line 8
    const/4 v5, 0x3

    .line 9
    const/4 v6, 0x0

    .line 10
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v8, v0, Lc41/b;->g:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v9, v0, Lc41/b;->f:Ljava/lang/Object;

    .line 15
    .line 16
    iget-object v0, v0, Lc41/b;->e:Ljava/lang/Object;

    .line 17
    .line 18
    packed-switch v1, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    check-cast v0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 22
    .line 23
    check-cast v9, Landroid/bluetooth/BluetoothDevice;

    .line 24
    .line 25
    check-cast v8, Ljava/util/UUID;

    .line 26
    .line 27
    invoke-static {v0, v9, v8}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->L0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;Ljava/util/UUID;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    return-object v0

    .line 32
    :pswitch_0
    check-cast v0, Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 33
    .line 34
    check-cast v9, Ltechnology/cariad/cat/genx/Channel;

    .line 35
    .line 36
    check-cast v8, [B

    .line 37
    .line 38
    invoke-static {v0, v9, v8}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->M0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;[B)Llx0/b0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    return-object v0

    .line 43
    :pswitch_1
    check-cast v0, [B

    .line 44
    .line 45
    check-cast v9, Ltechnology/cariad/cat/genx/Channel;

    .line 46
    .line 47
    check-cast v8, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 48
    .line 49
    invoke-static {v0, v9, v8}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->q0([BLtechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    return-object v0

    .line 54
    :pswitch_2
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;

    .line 55
    .line 56
    check-cast v9, Ltechnology/cariad/cat/genx/GenXError;

    .line 57
    .line 58
    check-cast v8, Ltechnology/cariad/cat/genx/TransportType;

    .line 59
    .line 60
    invoke-static {v0, v9, v8}, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;->d(Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;Ltechnology/cariad/cat/genx/GenXError;Ltechnology/cariad/cat/genx/TransportType;)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    return-object v0

    .line 69
    :pswitch_3
    check-cast v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 70
    .line 71
    check-cast v9, Lvy0/b0;

    .line 72
    .line 73
    check-cast v8, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 74
    .line 75
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getInterval()I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getLatency()I

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getTimeout()I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getLinkParameterStatus()B

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    const-string v5, ", latency: "

    .line 92
    .line 93
    const-string v6, ", timeout: "

    .line 94
    .line 95
    const-string v10, "[interval: "

    .line 96
    .line 97
    invoke-static {v1, v2, v10, v5, v6}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string v2, ", linkParameterStatus: "

    .line 105
    .line 106
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    const-string v0, "]"

    .line 113
    .line 114
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    new-instance v1, Lt61/g;

    .line 122
    .line 123
    invoke-direct {v1, v4, v8, v0}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    invoke-static {v9, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 127
    .line 128
    .line 129
    return-object v7

    .line 130
    :pswitch_4
    check-cast v0, [B

    .line 131
    .line 132
    check-cast v9, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 133
    .line 134
    check-cast v8, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 135
    .line 136
    invoke-static {v0, v9, v8}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->b([BLtechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    return-object v0

    .line 141
    :pswitch_5
    check-cast v9, Ll2/b1;

    .line 142
    .line 143
    check-cast v0, Lay0/k;

    .line 144
    .line 145
    check-cast v8, Lr60/j;

    .line 146
    .line 147
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 148
    .line 149
    invoke-interface {v9, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    iget-object v1, v8, Lr60/j;->a:Ljava/lang/String;

    .line 153
    .line 154
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    return-object v7

    .line 158
    :pswitch_6
    check-cast v0, Lca/d;

    .line 159
    .line 160
    check-cast v9, Ljava/lang/String;

    .line 161
    .line 162
    check-cast v8, Lq51/e;

    .line 163
    .line 164
    invoke-virtual {v0, v9, v8}, Lca/d;->c(Ljava/lang/String;Lq51/e;)Lkp/r8;

    .line 165
    .line 166
    .line 167
    return-object v7

    .line 168
    :pswitch_7
    check-cast v0, Ljavax/crypto/SecretKey;

    .line 169
    .line 170
    check-cast v9, Lq51/b;

    .line 171
    .line 172
    check-cast v8, Ljava/lang/String;

    .line 173
    .line 174
    if-eqz v0, :cond_1

    .line 175
    .line 176
    iget-object v0, v9, Lq51/b;->a:Ljava/security/KeyStore;

    .line 177
    .line 178
    const-string v1, "<this>"

    .line 179
    .line 180
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    :try_start_0
    invoke-virtual {v0, v8}, Ljava/security/KeyStore;->containsAlias(Ljava/lang/String;)Z

    .line 184
    .line 185
    .line 186
    move-result v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 187
    if-eqz v1, :cond_0

    .line 188
    .line 189
    :try_start_1
    invoke-virtual {v0, v8}, Ljava/security/KeyStore;->deleteEntry(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    new-instance v0, Lg91/b;

    .line 193
    .line 194
    invoke-direct {v0, v7}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/security/KeyStoreException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :catch_0
    move-exception v0

    .line 199
    goto :goto_1

    .line 200
    :catch_1
    move-exception v0

    .line 201
    :try_start_2
    new-instance v1, Lg91/a;

    .line 202
    .line 203
    new-instance v2, Lq51/g;

    .line 204
    .line 205
    new-instance v3, Ljava/lang/StringBuilder;

    .line 206
    .line 207
    const-string v4, "Item for "

    .line 208
    .line 209
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v3, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    const-string v4, " could not be removed."

    .line 216
    .line 217
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    invoke-static {v3}, Lkp/y5;->d(Ljava/lang/String;)Le91/b;

    .line 225
    .line 226
    .line 227
    move-result-object v3

    .line 228
    new-instance v4, Le91/c;

    .line 229
    .line 230
    const-string v5, "keychainKey"

    .line 231
    .line 232
    invoke-direct {v4, v5}, Le91/c;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v3, v4, v8}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    sget-object v4, Le91/c;->c:Le91/c;

    .line 239
    .line 240
    invoke-virtual {v3, v4, v0}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    invoke-direct {v2, v3}, Lq51/p;-><init>(Le91/b;)V

    .line 244
    .line 245
    .line 246
    invoke-direct {v1, v2}, Lg91/a;-><init>(Lq51/p;)V

    .line 247
    .line 248
    .line 249
    :goto_0
    move-object v0, v1

    .line 250
    goto :goto_2

    .line 251
    :cond_0
    new-instance v0, Lg91/b;

    .line 252
    .line 253
    invoke-direct {v0, v7}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 254
    .line 255
    .line 256
    goto :goto_2

    .line 257
    :goto_1
    new-instance v1, Lg91/a;

    .line 258
    .line 259
    new-instance v2, Lq51/m;

    .line 260
    .line 261
    invoke-static {v0}, Lkp/y5;->e(Ljava/lang/Exception;)Le91/b;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    invoke-direct {v2, v0}, Lq51/p;-><init>(Le91/b;)V

    .line 266
    .line 267
    .line 268
    invoke-direct {v1, v2}, Lg91/a;-><init>(Lq51/p;)V

    .line 269
    .line 270
    .line 271
    goto :goto_0

    .line 272
    :goto_2
    instance-of v1, v0, Lg91/a;

    .line 273
    .line 274
    if-eqz v1, :cond_1

    .line 275
    .line 276
    sget-object v1, Lw51/c;->a:Lw51/b;

    .line 277
    .line 278
    check-cast v0, Lg91/a;

    .line 279
    .line 280
    new-instance v1, Lac0/a;

    .line 281
    .line 282
    const/16 v2, 0x1c

    .line 283
    .line 284
    invoke-direct {v1, v8, v2}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 285
    .line 286
    .line 287
    const-string v2, "moduleName"

    .line 288
    .line 289
    sget-object v3, Lq51/r;->a:Lw51/b;

    .line 290
    .line 291
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    sget-object v2, Lw51/e;->e:Lw51/e;

    .line 295
    .line 296
    new-instance v4, Ld90/w;

    .line 297
    .line 298
    const/16 v5, 0x10

    .line 299
    .line 300
    invoke-direct {v4, v5, v0, v1}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    invoke-static {}, Lw51/c;->d()Z

    .line 304
    .line 305
    .line 306
    move-result v1

    .line 307
    if-eqz v1, :cond_1

    .line 308
    .line 309
    invoke-static {v0}, Lf91/b;->e(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    const-string v1, "technology.cariad.cat.utility.extensions.LExtensionsKt"

    .line 314
    .line 315
    invoke-static {v1, v2}, Lw51/c;->c(Ljava/lang/String;Lw51/e;)Lw51/a;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    invoke-static {v3, v1, v0, v4}, Lw51/c;->g(Lw51/b;Lw51/a;Ljava/lang/Throwable;Lay0/a;)V

    .line 320
    .line 321
    .line 322
    :cond_1
    return-object v7

    .line 323
    :pswitch_8
    check-cast v0, Lq1/e;

    .line 324
    .line 325
    check-cast v9, Lv3/f1;

    .line 326
    .line 327
    check-cast v8, La4/b;

    .line 328
    .line 329
    invoke-static {v0, v9, v8}, Lq1/e;->X0(Lq1/e;Lv3/f1;La4/b;)Ld3/c;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    if-eqz v1, :cond_3

    .line 334
    .line 335
    iget-object v0, v0, Lq1/e;->r:Lg1/y;

    .line 336
    .line 337
    iget-wide v2, v0, Lg1/y;->z:J

    .line 338
    .line 339
    const-wide/16 v4, 0x0

    .line 340
    .line 341
    invoke-static {v2, v3, v4, v5}, Lt4/l;->a(JJ)Z

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    if-eqz v2, :cond_2

    .line 346
    .line 347
    const-string v2, "Expected BringIntoViewRequester to not be used before parents are placed."

    .line 348
    .line 349
    invoke-static {v2}, Lj1/b;->c(Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    :cond_2
    iget-wide v2, v0, Lg1/y;->z:J

    .line 353
    .line 354
    invoke-virtual {v0, v1, v2, v3}, Lg1/y;->b1(Ld3/c;J)J

    .line 355
    .line 356
    .line 357
    move-result-wide v2

    .line 358
    const-wide v4, -0x7fffffff80000000L    # -1.0609978955E-314

    .line 359
    .line 360
    .line 361
    .line 362
    .line 363
    xor-long/2addr v2, v4

    .line 364
    invoke-virtual {v1, v2, v3}, Ld3/c;->i(J)Ld3/c;

    .line 365
    .line 366
    .line 367
    move-result-object v6

    .line 368
    :cond_3
    return-object v6

    .line 369
    :pswitch_9
    check-cast v0, Ll2/b1;

    .line 370
    .line 371
    check-cast v9, Ll2/b1;

    .line 372
    .line 373
    check-cast v8, Lay0/a;

    .line 374
    .line 375
    new-instance v1, Lp1/l;

    .line 376
    .line 377
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v0

    .line 381
    check-cast v0, Lay0/p;

    .line 382
    .line 383
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v2

    .line 387
    check-cast v2, Lay0/k;

    .line 388
    .line 389
    invoke-interface {v8}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    move-result-object v3

    .line 393
    check-cast v3, Ljava/lang/Number;

    .line 394
    .line 395
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 396
    .line 397
    .line 398
    move-result v3

    .line 399
    invoke-direct {v1, v0, v2, v3}, Lp1/l;-><init>(Lay0/p;Lay0/k;I)V

    .line 400
    .line 401
    .line 402
    return-object v1

    .line 403
    :pswitch_a
    check-cast v0, Ll2/a;

    .line 404
    .line 405
    check-cast v9, Ll2/i2;

    .line 406
    .line 407
    check-cast v8, Lm2/k0;

    .line 408
    .line 409
    if-eqz v0, :cond_4

    .line 410
    .line 411
    invoke-virtual {v9, v0}, Ll2/i2;->c(Ll2/a;)I

    .line 412
    .line 413
    .line 414
    move-result v0

    .line 415
    iget v1, v9, Ll2/i2;->t:I

    .line 416
    .line 417
    sub-int/2addr v0, v1

    .line 418
    invoke-virtual {v9, v0}, Ll2/i2;->a(I)V

    .line 419
    .line 420
    .line 421
    :cond_4
    iget v0, v9, Ll2/i2;->t:I

    .line 422
    .line 423
    invoke-static {v9, v6, v0, v6}, Llp/sc;->a(Ll2/i2;Ljava/lang/Integer;ILjava/lang/Integer;)Ljava/util/List;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    invoke-static {v0}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object v1

    .line 431
    check-cast v1, Lw2/a;

    .line 432
    .line 433
    if-eqz v1, :cond_5

    .line 434
    .line 435
    iget-object v1, v1, Lw2/a;->a:Ljava/lang/Integer;

    .line 436
    .line 437
    goto :goto_3

    .line 438
    :cond_5
    move-object v1, v6

    .line 439
    :goto_3
    invoke-interface {v8, v1}, Lm2/k0;->m(Ljava/lang/Integer;)Ljava/util/List;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    if-eqz v1, :cond_7

    .line 444
    .line 445
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 446
    .line 447
    .line 448
    move-result v4

    .line 449
    if-eqz v4, :cond_6

    .line 450
    .line 451
    goto :goto_4

    .line 452
    :cond_6
    invoke-static {v2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    move-result-object v4

    .line 456
    check-cast v4, Lw2/a;

    .line 457
    .line 458
    check-cast v2, Ljava/lang/Iterable;

    .line 459
    .line 460
    invoke-static {v2, v3}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 461
    .line 462
    .line 463
    move-result-object v2

    .line 464
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 465
    .line 466
    .line 467
    new-instance v3, Lw2/a;

    .line 468
    .line 469
    invoke-direct {v3, v6, v1}, Lw2/a;-><init>(Llp/uc;Ljava/lang/Integer;)V

    .line 470
    .line 471
    .line 472
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 473
    .line 474
    .line 475
    move-result-object v1

    .line 476
    check-cast v1, Ljava/util/Collection;

    .line 477
    .line 478
    check-cast v2, Ljava/lang/Iterable;

    .line 479
    .line 480
    invoke-static {v2, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 481
    .line 482
    .line 483
    move-result-object v2

    .line 484
    :cond_7
    :goto_4
    check-cast v0, Ljava/util/Collection;

    .line 485
    .line 486
    check-cast v2, Ljava/lang/Iterable;

    .line 487
    .line 488
    invoke-static {v2, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    return-object v0

    .line 493
    :pswitch_b
    check-cast v0, Ll2/h0;

    .line 494
    .line 495
    check-cast v9, Lm1/t;

    .line 496
    .line 497
    check-cast v8, Landroidx/compose/foundation/lazy/a;

    .line 498
    .line 499
    invoke-virtual {v0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    check-cast v0, Lm1/f;

    .line 504
    .line 505
    new-instance v1, Lbb/g0;

    .line 506
    .line 507
    iget-object v2, v9, Lm1/t;->e:Lm1/o;

    .line 508
    .line 509
    iget-object v2, v2, Lm1/o;->f:Lo1/g0;

    .line 510
    .line 511
    invoke-virtual {v2}, Lo1/g0;->getValue()Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object v2

    .line 515
    check-cast v2, Lgy0/j;

    .line 516
    .line 517
    invoke-direct {v1, v2, v0}, Lbb/g0;-><init>(Lgy0/j;Lo1/y;)V

    .line 518
    .line 519
    .line 520
    new-instance v2, Lm1/h;

    .line 521
    .line 522
    invoke-direct {v2, v9, v0, v8, v1}, Lm1/h;-><init>(Lm1/t;Lm1/f;Landroidx/compose/foundation/lazy/a;Lbb/g0;)V

    .line 523
    .line 524
    .line 525
    return-object v2

    .line 526
    :pswitch_c
    check-cast v8, Lhu/q;

    .line 527
    .line 528
    new-instance v1, Ljava/lang/StringBuilder;

    .line 529
    .line 530
    const-string v2, "Attempting to assign conflicting values \'"

    .line 531
    .line 532
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 536
    .line 537
    .line 538
    const-string v0, "\' and \'"

    .line 539
    .line 540
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 541
    .line 542
    .line 543
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 544
    .line 545
    .line 546
    const-string v0, "\' to field \'"

    .line 547
    .line 548
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 549
    .line 550
    .line 551
    iget-object v0, v8, Lhu/q;->e:Ljava/lang/Object;

    .line 552
    .line 553
    check-cast v0, Ljz0/m;

    .line 554
    .line 555
    iget-object v0, v0, Ljz0/m;->c:Ljava/lang/String;

    .line 556
    .line 557
    const/16 v2, 0x27

    .line 558
    .line 559
    invoke-static {v1, v0, v2}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 560
    .line 561
    .line 562
    move-result-object v0

    .line 563
    return-object v0

    .line 564
    :pswitch_d
    move-object v1, v0

    .line 565
    check-cast v1, Ll2/t;

    .line 566
    .line 567
    check-cast v9, Lm2/a;

    .line 568
    .line 569
    check-cast v8, Ll2/e2;

    .line 570
    .line 571
    iget-object v3, v1, Ll2/t;->M:Lm2/b;

    .line 572
    .line 573
    iget-object v4, v3, Lm2/b;->b:Lm2/a;

    .line 574
    .line 575
    :try_start_3
    iput-object v9, v3, Lm2/b;->b:Lm2/a;

    .line 576
    .line 577
    iget-object v5, v1, Ll2/t;->G:Ll2/e2;

    .line 578
    .line 579
    iget-object v7, v1, Ll2/t;->o:[I

    .line 580
    .line 581
    iget-object v9, v1, Ll2/t;->v:Landroidx/collection/b0;

    .line 582
    .line 583
    iput-object v6, v1, Ll2/t;->o:[I

    .line 584
    .line 585
    iput-object v6, v1, Ll2/t;->v:Landroidx/collection/b0;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 586
    .line 587
    :try_start_4
    iput-object v8, v1, Ll2/t;->G:Ll2/e2;

    .line 588
    .line 589
    iget-boolean v8, v3, Lm2/b;->e:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 590
    .line 591
    :try_start_5
    iput-boolean v2, v3, Lm2/b;->e:Z

    .line 592
    .line 593
    throw v6
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 594
    :catchall_0
    move-exception v0

    .line 595
    :try_start_6
    iput-boolean v8, v3, Lm2/b;->e:Z

    .line 596
    .line 597
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 598
    :catchall_1
    move-exception v0

    .line 599
    :try_start_7
    iput-object v5, v1, Ll2/t;->G:Ll2/e2;

    .line 600
    .line 601
    iput-object v7, v1, Ll2/t;->o:[I

    .line 602
    .line 603
    iput-object v9, v1, Ll2/t;->v:Landroidx/collection/b0;

    .line 604
    .line 605
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 606
    :catchall_2
    move-exception v0

    .line 607
    iput-object v4, v3, Lm2/b;->b:Lm2/a;

    .line 608
    .line 609
    throw v0

    .line 610
    :pswitch_e
    check-cast v0, Lkj0/c;

    .line 611
    .line 612
    check-cast v9, Lkj0/b;

    .line 613
    .line 614
    check-cast v8, Landroid/os/Bundle;

    .line 615
    .line 616
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 617
    .line 618
    .line 619
    move-result-object v0

    .line 620
    invoke-interface {v9}, Lkj0/b;->getName()Ljava/lang/String;

    .line 621
    .line 622
    .line 623
    move-result-object v1

    .line 624
    new-instance v2, Ljava/lang/StringBuilder;

    .line 625
    .line 626
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 627
    .line 628
    .line 629
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 630
    .line 631
    .line 632
    const-string v0, ": name="

    .line 633
    .line 634
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 635
    .line 636
    .line 637
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 638
    .line 639
    .line 640
    const-string v0, ", params="

    .line 641
    .line 642
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 643
    .line 644
    .line 645
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 646
    .line 647
    .line 648
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 649
    .line 650
    .line 651
    move-result-object v0

    .line 652
    return-object v0

    .line 653
    :pswitch_f
    check-cast v0, Lne0/c;

    .line 654
    .line 655
    check-cast v9, Ljava/lang/String;

    .line 656
    .line 657
    check-cast v8, Ljava/lang/Throwable;

    .line 658
    .line 659
    iget-object v1, v0, Lne0/c;->c:Lne0/a;

    .line 660
    .line 661
    const-string v2, "\n"

    .line 662
    .line 663
    if-eqz v1, :cond_8

    .line 664
    .line 665
    iget-object v1, v1, Lne0/a;->d:Ljava/lang/String;

    .line 666
    .line 667
    if-eqz v1, :cond_8

    .line 668
    .line 669
    const-string v3, "RequestId: "

    .line 670
    .line 671
    invoke-static {v3, v1, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 672
    .line 673
    .line 674
    move-result-object v1

    .line 675
    if-nez v1, :cond_9

    .line 676
    .line 677
    :cond_8
    const-string v1, ""

    .line 678
    .line 679
    :cond_9
    iget-wide v3, v0, Lne0/c;->d:J

    .line 680
    .line 681
    invoke-static {v8}, Loa0/b;->b(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 682
    .line 683
    .line 684
    move-result-object v0

    .line 685
    new-instance v5, Ljava/lang/StringBuilder;

    .line 686
    .line 687
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 688
    .line 689
    .line 690
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 691
    .line 692
    .line 693
    const-string v1, "App name: "

    .line 694
    .line 695
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 696
    .line 697
    .line 698
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 699
    .line 700
    .line 701
    const-string v1, "\nTimestamp: "

    .line 702
    .line 703
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 704
    .line 705
    .line 706
    invoke-virtual {v5, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 707
    .line 708
    .line 709
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 710
    .line 711
    .line 712
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 713
    .line 714
    .line 715
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 716
    .line 717
    .line 718
    move-result-object v0

    .line 719
    return-object v0

    .line 720
    :pswitch_10
    check-cast v0, Lxy0/x;

    .line 721
    .line 722
    check-cast v9, Lxo/g;

    .line 723
    .line 724
    check-cast v8, Lj51/b;

    .line 725
    .line 726
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 727
    .line 728
    invoke-static {v0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 729
    .line 730
    .line 731
    move-result-object v2

    .line 732
    new-instance v3, Lj00/a;

    .line 733
    .line 734
    const/16 v5, 0x8

    .line 735
    .line 736
    invoke-direct {v3, v5}, Lj00/a;-><init>(I)V

    .line 737
    .line 738
    .line 739
    invoke-static {v1, v2, v3, v4}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 740
    .line 741
    .line 742
    :try_start_8
    const-string v2, "RKE_STATUS_LISTENER_TYPE"

    .line 743
    .line 744
    invoke-static {v8, v2}, Llp/xf;->c(Ljava/lang/Object;Ljava/lang/String;)Llo/k;

    .line 745
    .line 746
    .line 747
    move-result-object v2

    .line 748
    const v3, 0x8897    # 4.8999E-41f

    .line 749
    .line 750
    .line 751
    invoke-virtual {v9, v2, v3}, Lko/i;->d(Llo/k;I)Laq/t;

    .line 752
    .line 753
    .line 754
    invoke-static {v0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 755
    .line 756
    .line 757
    move-result-object v2

    .line 758
    new-instance v3, Lj00/a;

    .line 759
    .line 760
    const/16 v5, 0x9

    .line 761
    .line 762
    invoke-direct {v3, v5}, Lj00/a;-><init>(I)V

    .line 763
    .line 764
    .line 765
    invoke-static {v1, v2, v3, v4}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_2

    .line 766
    .line 767
    .line 768
    goto :goto_5

    .line 769
    :catch_2
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 770
    .line 771
    invoke-static {v0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 772
    .line 773
    .line 774
    iget-object v0, v1, Lx51/b;->d:La61/a;

    .line 775
    .line 776
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 777
    .line 778
    .line 779
    :goto_5
    return-object v7

    .line 780
    :pswitch_11
    check-cast v0, Lxy0/x;

    .line 781
    .line 782
    check-cast v9, Lxo/g;

    .line 783
    .line 784
    check-cast v8, Lj51/a;

    .line 785
    .line 786
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 787
    .line 788
    invoke-static {v0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 789
    .line 790
    .line 791
    move-result-object v2

    .line 792
    new-instance v3, Lj00/a;

    .line 793
    .line 794
    const/4 v5, 0x4

    .line 795
    invoke-direct {v3, v5}, Lj00/a;-><init>(I)V

    .line 796
    .line 797
    .line 798
    invoke-static {v1, v2, v3, v4}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 799
    .line 800
    .line 801
    :try_start_9
    const-string v2, "CONNECTION_STATUS_LISTENER_TYPE"

    .line 802
    .line 803
    invoke-static {v8, v2}, Llp/xf;->c(Ljava/lang/Object;Ljava/lang/String;)Llo/k;

    .line 804
    .line 805
    .line 806
    move-result-object v2

    .line 807
    const v3, 0x8898    # 4.9E-41f

    .line 808
    .line 809
    .line 810
    invoke-virtual {v9, v2, v3}, Lko/i;->d(Llo/k;I)Laq/t;

    .line 811
    .line 812
    .line 813
    invoke-static {v0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 814
    .line 815
    .line 816
    move-result-object v2

    .line 817
    new-instance v3, Lj00/a;

    .line 818
    .line 819
    const/4 v5, 0x5

    .line 820
    invoke-direct {v3, v5}, Lj00/a;-><init>(I)V

    .line 821
    .line 822
    .line 823
    invoke-static {v1, v2, v3, v4}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_3

    .line 824
    .line 825
    .line 826
    goto :goto_6

    .line 827
    :catch_3
    sget-object v1, Lx51/c;->o1:Lx51/b;

    .line 828
    .line 829
    invoke-static {v0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 830
    .line 831
    .line 832
    iget-object v0, v1, Lx51/b;->d:La61/a;

    .line 833
    .line 834
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 835
    .line 836
    .line 837
    :goto_6
    return-object v7

    .line 838
    :pswitch_12
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 839
    .line 840
    check-cast v9, Landroid/net/ConnectivityManager;

    .line 841
    .line 842
    check-cast v8, Ldm0/j;

    .line 843
    .line 844
    iget-boolean v0, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 845
    .line 846
    if-eqz v0, :cond_a

    .line 847
    .line 848
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 849
    .line 850
    .line 851
    move-result-object v0

    .line 852
    sget-object v1, Lib/j;->a:Ljava/lang/String;

    .line 853
    .line 854
    const-string v2, "NetworkRequestConstraintController unregister callback"

    .line 855
    .line 856
    invoke-virtual {v0, v1, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 857
    .line 858
    .line 859
    invoke-virtual {v9, v8}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 860
    .line 861
    .line 862
    :cond_a
    return-object v7

    .line 863
    :pswitch_13
    check-cast v0, Lh2/yb;

    .line 864
    .line 865
    check-cast v9, Lvy0/b0;

    .line 866
    .line 867
    check-cast v8, Ll2/b1;

    .line 868
    .line 869
    invoke-virtual {v0}, Lh2/yb;->b()Z

    .line 870
    .line 871
    .line 872
    move-result v1

    .line 873
    if-eqz v1, :cond_b

    .line 874
    .line 875
    new-instance v1, La10/a;

    .line 876
    .line 877
    const/16 v2, 0x12

    .line 878
    .line 879
    invoke-direct {v1, v0, v6, v2}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 880
    .line 881
    .line 882
    invoke-static {v9, v6, v6, v1, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 883
    .line 884
    .line 885
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 886
    .line 887
    invoke-interface {v8, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 888
    .line 889
    .line 890
    :cond_b
    return-object v7

    .line 891
    :pswitch_14
    check-cast v0, Lvy0/b0;

    .line 892
    .line 893
    check-cast v9, Lg70/i;

    .line 894
    .line 895
    check-cast v8, Lay0/a;

    .line 896
    .line 897
    sget-object v1, Lge0/b;->c:Lcz0/d;

    .line 898
    .line 899
    new-instance v2, Lh40/w3;

    .line 900
    .line 901
    const/16 v3, 0xe

    .line 902
    .line 903
    invoke-direct {v2, v3, v9, v8, v6}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 904
    .line 905
    .line 906
    const/4 v3, 0x2

    .line 907
    invoke-static {v0, v1, v6, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 908
    .line 909
    .line 910
    return-object v7

    .line 911
    :pswitch_15
    check-cast v9, Lg61/q;

    .line 912
    .line 913
    check-cast v8, Lay0/a;

    .line 914
    .line 915
    check-cast v0, Lay0/k;

    .line 916
    .line 917
    if-eqz v9, :cond_c

    .line 918
    .line 919
    invoke-interface {v9, v8}, Lg61/q;->startWithCompose-IoAF18A(Lay0/a;)Ljava/lang/Object;

    .line 920
    .line 921
    .line 922
    move-result-object v1

    .line 923
    new-instance v2, Llx0/o;

    .line 924
    .line 925
    invoke-direct {v2, v1}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 926
    .line 927
    .line 928
    goto :goto_7

    .line 929
    :cond_c
    move-object v2, v6

    .line 930
    :goto_7
    if-eqz v2, :cond_e

    .line 931
    .line 932
    iget-object v1, v2, Llx0/o;->d:Ljava/lang/Object;

    .line 933
    .line 934
    instance-of v4, v1, Llx0/n;

    .line 935
    .line 936
    if-eqz v4, :cond_d

    .line 937
    .line 938
    goto :goto_8

    .line 939
    :cond_d
    move-object v6, v1

    .line 940
    :goto_8
    check-cast v6, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 941
    .line 942
    :cond_e
    if-eqz v2, :cond_f

    .line 943
    .line 944
    iget-object v1, v2, Llx0/o;->d:Ljava/lang/Object;

    .line 945
    .line 946
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 947
    .line 948
    .line 949
    move-result-object v11

    .line 950
    if-eqz v11, :cond_f

    .line 951
    .line 952
    new-instance v10, Lne0/c;

    .line 953
    .line 954
    const/4 v14, 0x0

    .line 955
    const/16 v15, 0x1e

    .line 956
    .line 957
    const/4 v12, 0x0

    .line 958
    const/4 v13, 0x0

    .line 959
    invoke-direct/range {v10 .. v15}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 960
    .line 961
    .line 962
    new-instance v1, La60/a;

    .line 963
    .line 964
    invoke-direct {v1, v10, v3}, La60/a;-><init>(Lne0/c;I)V

    .line 965
    .line 966
    .line 967
    sget-object v2, Lk1/t;->a:Lk1/t;

    .line 968
    .line 969
    invoke-static {v2, v1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 970
    .line 971
    .line 972
    invoke-interface {v9}, Lg61/q;->stop()V

    .line 973
    .line 974
    .line 975
    :cond_f
    if-eqz v6, :cond_10

    .line 976
    .line 977
    invoke-interface {v0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 978
    .line 979
    .line 980
    :cond_10
    return-object v7

    .line 981
    :pswitch_16
    check-cast v0, Lh2/r8;

    .line 982
    .line 983
    check-cast v9, Lvy0/b0;

    .line 984
    .line 985
    check-cast v8, Lh2/r8;

    .line 986
    .line 987
    iget-object v0, v0, Lh2/r8;->e:Li2/p;

    .line 988
    .line 989
    iget-object v0, v0, Li2/p;->d:Lay0/k;

    .line 990
    .line 991
    sget-object v1, Lh2/s8;->e:Lh2/s8;

    .line 992
    .line 993
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 994
    .line 995
    .line 996
    move-result-object v0

    .line 997
    check-cast v0, Ljava/lang/Boolean;

    .line 998
    .line 999
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1000
    .line 1001
    .line 1002
    move-result v0

    .line 1003
    if-eqz v0, :cond_11

    .line 1004
    .line 1005
    new-instance v0, Lh2/i0;

    .line 1006
    .line 1007
    const/16 v1, 0xc

    .line 1008
    .line 1009
    invoke-direct {v0, v8, v6, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 1010
    .line 1011
    .line 1012
    invoke-static {v9, v6, v6, v0, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1013
    .line 1014
    .line 1015
    :cond_11
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1016
    .line 1017
    return-object v0

    .line 1018
    :pswitch_17
    check-cast v0, Ld01/l;

    .line 1019
    .line 1020
    check-cast v9, Ld01/w;

    .line 1021
    .line 1022
    check-cast v8, Ld01/a;

    .line 1023
    .line 1024
    iget-object v0, v0, Ld01/l;->b:Lkp/g;

    .line 1025
    .line 1026
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1027
    .line 1028
    .line 1029
    invoke-virtual {v9}, Ld01/w;->a()Ljava/util/List;

    .line 1030
    .line 1031
    .line 1032
    move-result-object v1

    .line 1033
    iget-object v2, v8, Ld01/a;->h:Ld01/a0;

    .line 1034
    .line 1035
    iget-object v2, v2, Ld01/a0;->d:Ljava/lang/String;

    .line 1036
    .line 1037
    invoke-virtual {v0, v2, v1}, Lkp/g;->c(Ljava/lang/String;Ljava/util/List;)Ljava/util/List;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v0

    .line 1041
    return-object v0

    .line 1042
    :pswitch_18
    check-cast v0, Lg1/y;

    .line 1043
    .line 1044
    check-cast v9, Lg1/l3;

    .line 1045
    .line 1046
    check-cast v8, Lg1/u;

    .line 1047
    .line 1048
    iget-object v1, v0, Lg1/y;->v:Lg1/r;

    .line 1049
    .line 1050
    :goto_9
    iget-object v4, v1, Lg1/r;->a:Ln2/b;

    .line 1051
    .line 1052
    iget v5, v4, Ln2/b;->f:I

    .line 1053
    .line 1054
    if-eqz v5, :cond_14

    .line 1055
    .line 1056
    if-eqz v5, :cond_13

    .line 1057
    .line 1058
    add-int/lit8 v5, v5, -0x1

    .line 1059
    .line 1060
    iget-object v4, v4, Ln2/b;->d:[Ljava/lang/Object;

    .line 1061
    .line 1062
    aget-object v4, v4, v5

    .line 1063
    .line 1064
    check-cast v4, Lg1/x;

    .line 1065
    .line 1066
    iget-object v4, v4, Lg1/x;->a:Lq1/d;

    .line 1067
    .line 1068
    invoke-virtual {v4}, Lq1/d;->invoke()Ljava/lang/Object;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v4

    .line 1072
    check-cast v4, Ld3/c;

    .line 1073
    .line 1074
    if-nez v4, :cond_12

    .line 1075
    .line 1076
    move v4, v3

    .line 1077
    goto :goto_a

    .line 1078
    :cond_12
    iget-wide v5, v0, Lg1/y;->z:J

    .line 1079
    .line 1080
    invoke-virtual {v0, v4, v5, v6}, Lg1/y;->Z0(Ld3/c;J)Z

    .line 1081
    .line 1082
    .line 1083
    move-result v4

    .line 1084
    :goto_a
    if-eqz v4, :cond_14

    .line 1085
    .line 1086
    iget-object v4, v1, Lg1/r;->a:Ln2/b;

    .line 1087
    .line 1088
    iget v5, v4, Ln2/b;->f:I

    .line 1089
    .line 1090
    sub-int/2addr v5, v3

    .line 1091
    invoke-virtual {v4, v5}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 1092
    .line 1093
    .line 1094
    move-result-object v4

    .line 1095
    check-cast v4, Lg1/x;

    .line 1096
    .line 1097
    iget-object v4, v4, Lg1/x;->b:Lvy0/l;

    .line 1098
    .line 1099
    invoke-virtual {v4, v7}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 1100
    .line 1101
    .line 1102
    goto :goto_9

    .line 1103
    :cond_13
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 1104
    .line 1105
    const-string v1, "MutableVector is empty."

    .line 1106
    .line 1107
    invoke-direct {v0, v1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 1108
    .line 1109
    .line 1110
    throw v0

    .line 1111
    :cond_14
    iget-boolean v1, v0, Lg1/y;->x:Z

    .line 1112
    .line 1113
    if-eqz v1, :cond_16

    .line 1114
    .line 1115
    invoke-virtual {v0}, Lg1/y;->Y0()Ld3/c;

    .line 1116
    .line 1117
    .line 1118
    move-result-object v1

    .line 1119
    if-eqz v1, :cond_15

    .line 1120
    .line 1121
    iget-wide v4, v0, Lg1/y;->z:J

    .line 1122
    .line 1123
    invoke-virtual {v0, v1, v4, v5}, Lg1/y;->Z0(Ld3/c;J)Z

    .line 1124
    .line 1125
    .line 1126
    move-result v1

    .line 1127
    if-ne v1, v3, :cond_15

    .line 1128
    .line 1129
    goto :goto_b

    .line 1130
    :cond_15
    move v3, v2

    .line 1131
    :goto_b
    if-eqz v3, :cond_16

    .line 1132
    .line 1133
    iput-boolean v2, v0, Lg1/y;->x:Z

    .line 1134
    .line 1135
    :cond_16
    invoke-static {v0, v8}, Lg1/y;->X0(Lg1/y;Lg1/u;)F

    .line 1136
    .line 1137
    .line 1138
    move-result v0

    .line 1139
    iput v0, v9, Lg1/l3;->e:F

    .line 1140
    .line 1141
    return-object v7

    .line 1142
    :pswitch_19
    move-object v2, v0

    .line 1143
    check-cast v2, Lkw/p;

    .line 1144
    .line 1145
    move-object v3, v9

    .line 1146
    check-cast v3, Lkw/p;

    .line 1147
    .line 1148
    move-object v4, v8

    .line 1149
    check-cast v4, Lkw/p;

    .line 1150
    .line 1151
    new-instance v1, Lew/j;

    .line 1152
    .line 1153
    const-string v0, "initialZoom"

    .line 1154
    .line 1155
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1156
    .line 1157
    .line 1158
    const-string v0, "minZoom"

    .line 1159
    .line 1160
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1161
    .line 1162
    .line 1163
    const-string v0, "maxZoom"

    .line 1164
    .line 1165
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1166
    .line 1167
    .line 1168
    const/4 v5, 0x0

    .line 1169
    const/4 v6, 0x0

    .line 1170
    invoke-direct/range {v1 .. v6}, Lew/j;-><init>(Lkw/p;Lkw/p;Lkw/p;FZ)V

    .line 1171
    .line 1172
    .line 1173
    return-object v1

    .line 1174
    :pswitch_1a
    check-cast v0, Lvy0/b0;

    .line 1175
    .line 1176
    check-cast v9, Le1/n1;

    .line 1177
    .line 1178
    check-cast v8, Ldv0/e;

    .line 1179
    .line 1180
    new-instance v1, Le60/m;

    .line 1181
    .line 1182
    invoke-direct {v1, v5, v9, v8, v6}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1183
    .line 1184
    .line 1185
    invoke-static {v0, v6, v6, v1, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1186
    .line 1187
    .line 1188
    return-object v7

    .line 1189
    :pswitch_1b
    check-cast v0, Lc81/d;

    .line 1190
    .line 1191
    check-cast v9, Lc81/e;

    .line 1192
    .line 1193
    check-cast v8, Lc81/f;

    .line 1194
    .line 1195
    iput-object v9, v0, Lc81/d;->i:Lc81/e;

    .line 1196
    .line 1197
    iput-object v8, v0, Lc81/d;->j:Lc81/f;

    .line 1198
    .line 1199
    new-instance v10, Lt71/a;

    .line 1200
    .line 1201
    sget-object v11, Ln71/c;->d:Ln71/c;

    .line 1202
    .line 1203
    sget-object v12, Ls71/p;->d:Ls71/p;

    .line 1204
    .line 1205
    sget-object v13, Ls71/m;->d:Ls71/m;

    .line 1206
    .line 1207
    sget-object v14, Lu71/b;->g:Lu71/b;

    .line 1208
    .line 1209
    sget-object v15, Ls71/l;->d:Ls71/l;

    .line 1210
    .line 1211
    sget-object v16, Lt71/e;->d:Lt71/e;

    .line 1212
    .line 1213
    invoke-direct/range {v10 .. v16}, Lt71/a;-><init>(Ln71/c;Ls71/q;Ls71/m;Lu71/b;Ls71/l;Lt71/e;)V

    .line 1214
    .line 1215
    .line 1216
    iput-object v10, v0, Lc81/d;->e:Lt71/a;

    .line 1217
    .line 1218
    iget-object v1, v0, Lc81/d;->d:Lt71/b;

    .line 1219
    .line 1220
    invoke-virtual {v10, v1}, Lt71/a;->b(Lt71/b;)V

    .line 1221
    .line 1222
    .line 1223
    iget-object v1, v0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 1224
    .line 1225
    iget-object v2, v0, Lc81/d;->a:Ll71/w;

    .line 1226
    .line 1227
    iget-object v0, v0, Lc81/d;->k:Lc81/c;

    .line 1228
    .line 1229
    invoke-virtual {v1, v2, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->start(Ll71/w;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine$StateCallback;)V

    .line 1230
    .line 1231
    .line 1232
    return-object v7

    .line 1233
    :pswitch_1c
    check-cast v0, Lay0/k;

    .line 1234
    .line 1235
    check-cast v8, Lh2/o3;

    .line 1236
    .line 1237
    check-cast v9, Lay0/k;

    .line 1238
    .line 1239
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 1240
    .line 1241
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1242
    .line 1243
    .line 1244
    invoke-virtual {v8}, Lh2/o3;->g()Ljava/lang/Long;

    .line 1245
    .line 1246
    .line 1247
    move-result-object v0

    .line 1248
    if-eqz v0, :cond_17

    .line 1249
    .line 1250
    invoke-interface {v9, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1251
    .line 1252
    .line 1253
    :cond_17
    return-object v7

    .line 1254
    nop

    .line 1255
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
