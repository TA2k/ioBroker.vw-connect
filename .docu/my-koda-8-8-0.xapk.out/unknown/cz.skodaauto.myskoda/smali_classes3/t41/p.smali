.class public final synthetic Lt41/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/altbeacon/beacon/RangeNotifier;


# instance fields
.field public final synthetic a:Lt41/z;


# direct methods
.method public synthetic constructor <init>(Lt41/z;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt41/p;->a:Lt41/z;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final didRangeBeaconsInRegion(Ljava/util/Collection;Lorg/altbeacon/beacon/Region;)V
    .locals 12

    .line 1
    iget-object p0, p0, Lt41/p;->a:Lt41/z;

    .line 2
    .line 3
    iget-object v0, p0, Lt41/z;->j:Ljava/util/Set;

    .line 4
    .line 5
    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_a

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    goto/16 :goto_5

    .line 18
    .line 19
    :cond_0
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p2}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    check-cast p1, Ljava/lang/Iterable;

    .line 27
    .line 28
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/4 v1, 0x0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    move-object v2, v0

    .line 44
    check-cast v2, Lorg/altbeacon/beacon/Beacon;

    .line 45
    .line 46
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Beacon;->getId1()Lorg/altbeacon/beacon/Identifier;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iget-object v4, p2, Lt41/b;->d:Ljava/util/UUID;

    .line 51
    .line 52
    invoke-static {v4}, Lorg/altbeacon/beacon/Identifier;->fromUuid(Ljava/util/UUID;)Lorg/altbeacon/beacon/Identifier;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const-string v5, "fromUuid(...)"

    .line 57
    .line 58
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    if-eqz v3, :cond_1

    .line 66
    .line 67
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Beacon;->getId2()Lorg/altbeacon/beacon/Identifier;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    iget-short v4, p2, Lt41/b;->e:S

    .line 72
    .line 73
    const v5, 0xffff

    .line 74
    .line 75
    .line 76
    and-int/2addr v4, v5

    .line 77
    invoke-static {v4}, Lorg/altbeacon/beacon/Identifier;->fromInt(I)Lorg/altbeacon/beacon/Identifier;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    const-string v6, "fromInt(...)"

    .line 82
    .line 83
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-eqz v3, :cond_1

    .line 91
    .line 92
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Beacon;->getId3()Lorg/altbeacon/beacon/Identifier;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    iget-short v3, p2, Lt41/b;->f:S

    .line 97
    .line 98
    and-int/2addr v3, v5

    .line 99
    invoke-static {v3}, Lorg/altbeacon/beacon/Identifier;->fromInt(I)Lorg/altbeacon/beacon/Identifier;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    if-eqz v2, :cond_1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_2
    move-object v0, v1

    .line 114
    :goto_0
    check-cast v0, Lorg/altbeacon/beacon/Beacon;

    .line 115
    .line 116
    if-eqz v0, :cond_a

    .line 117
    .line 118
    iget-object p1, p0, Lt41/z;->m:Ljava/util/LinkedHashMap;

    .line 119
    .line 120
    invoke-virtual {v0}, Lorg/altbeacon/beacon/Beacon;->getDistance()D

    .line 121
    .line 122
    .line 123
    move-result-wide v2

    .line 124
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 125
    .line 126
    .line 127
    move-result-object v4

    .line 128
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(D)D

    .line 129
    .line 130
    .line 131
    move-result-wide v2

    .line 132
    const-wide v5, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    cmpg-double v2, v2, v5

    .line 138
    .line 139
    if-gtz v2, :cond_3

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_3
    move-object v4, v1

    .line 143
    :goto_1
    const-string v2, "getName(...)"

    .line 144
    .line 145
    sget-object v7, Lt51/d;->a:Lt51/d;

    .line 146
    .line 147
    if-eqz v4, :cond_9

    .line 148
    .line 149
    invoke-virtual {v4}, Ljava/lang/Double;->doubleValue()D

    .line 150
    .line 151
    .line 152
    move-result-wide v5

    .line 153
    invoke-static {v5, v6, p2}, Lt41/z;->d(DLt41/b;)Lt41/g;

    .line 154
    .line 155
    .line 156
    move-result-object v3

    .line 157
    new-instance v8, Lt41/q;

    .line 158
    .line 159
    invoke-direct {v8, v0, v5, v6, v3}, Lt41/q;-><init>(Lorg/altbeacon/beacon/Beacon;DLt41/g;)V

    .line 160
    .line 161
    .line 162
    new-instance v5, Lt51/j;

    .line 163
    .line 164
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v10

    .line 168
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v11

    .line 172
    const-string v6, "BeaconScanner"

    .line 173
    .line 174
    const/4 v9, 0x0

    .line 175
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {p1, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v5

    .line 185
    check-cast v5, Ljava/lang/Double;

    .line 186
    .line 187
    if-eqz v5, :cond_4

    .line 188
    .line 189
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 190
    .line 191
    .line 192
    move-result-wide v5

    .line 193
    invoke-static {v5, v6, p2}, Lt41/z;->d(DLt41/b;)Lt41/g;

    .line 194
    .line 195
    .line 196
    move-result-object v5

    .line 197
    goto :goto_2

    .line 198
    :cond_4
    move-object v5, v1

    .line 199
    :goto_2
    invoke-virtual {v3, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    if-nez v5, :cond_9

    .line 204
    .line 205
    instance-of v5, v3, Lt41/f;

    .line 206
    .line 207
    if-eqz v5, :cond_5

    .line 208
    .line 209
    invoke-interface {p1, p2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    goto :goto_3

    .line 213
    :cond_5
    invoke-interface {p1, p2, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    :goto_3
    iget-object p1, p0, Lt41/z;->g:Lyy0/c2;

    .line 217
    .line 218
    :cond_6
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    move-object v5, v4

    .line 223
    check-cast v5, Ljava/util/Set;

    .line 224
    .line 225
    check-cast v5, Ljava/lang/Iterable;

    .line 226
    .line 227
    new-instance v6, Ljava/util/ArrayList;

    .line 228
    .line 229
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 230
    .line 231
    .line 232
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 233
    .line 234
    .line 235
    move-result-object v5

    .line 236
    :cond_7
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 237
    .line 238
    .line 239
    move-result v8

    .line 240
    if-eqz v8, :cond_8

    .line 241
    .line 242
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v8

    .line 246
    move-object v9, v8

    .line 247
    check-cast v9, Lt41/g;

    .line 248
    .line 249
    invoke-virtual {v9}, Lt41/g;->a()Lt41/b;

    .line 250
    .line 251
    .line 252
    move-result-object v9

    .line 253
    invoke-virtual {v3}, Lt41/g;->a()Lt41/b;

    .line 254
    .line 255
    .line 256
    move-result-object v10

    .line 257
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v9

    .line 261
    if-nez v9, :cond_7

    .line 262
    .line 263
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    goto :goto_4

    .line 267
    :cond_8
    invoke-static {v6, v3}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    invoke-static {v5}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 272
    .line 273
    .line 274
    move-result-object v5

    .line 275
    invoke-virtual {p1, v4, v5}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v4

    .line 279
    if-eqz v4, :cond_6

    .line 280
    .line 281
    :cond_9
    new-instance p1, Lt41/a0;

    .line 282
    .line 283
    invoke-virtual {v0}, Lorg/altbeacon/beacon/Beacon;->getRssi()I

    .line 284
    .line 285
    .line 286
    move-result v3

    .line 287
    invoke-virtual {v0}, Lorg/altbeacon/beacon/Beacon;->getTxPower()I

    .line 288
    .line 289
    .line 290
    move-result v4

    .line 291
    invoke-direct {p1, p2, v3, v4}, Lt41/a0;-><init>(Lt41/b;II)V

    .line 292
    .line 293
    .line 294
    iget-object v3, p0, Lt41/z;->n:Ljava/util/LinkedHashMap;

    .line 295
    .line 296
    invoke-virtual {v3, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v4

    .line 300
    invoke-virtual {p1, v4}, Lt41/a0;->equals(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v4

    .line 304
    if-nez v4, :cond_a

    .line 305
    .line 306
    new-instance v8, Lo51/c;

    .line 307
    .line 308
    const/16 v4, 0x19

    .line 309
    .line 310
    invoke-direct {v8, v4, v0, p1}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    new-instance v5, Lt51/j;

    .line 314
    .line 315
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object v10

    .line 319
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v11

    .line 323
    const-string v6, "BeaconScanner"

    .line 324
    .line 325
    const/4 v9, 0x0

    .line 326
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 330
    .line 331
    .line 332
    invoke-interface {v3, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    new-instance p2, Lr60/t;

    .line 336
    .line 337
    const/16 v0, 0xf

    .line 338
    .line 339
    invoke-direct {p2, v0, p0, p1, v1}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 340
    .line 341
    .line 342
    const/4 p1, 0x3

    .line 343
    invoke-static {p0, v1, v1, p2, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 344
    .line 345
    .line 346
    :cond_a
    :goto_5
    return-void
.end method
