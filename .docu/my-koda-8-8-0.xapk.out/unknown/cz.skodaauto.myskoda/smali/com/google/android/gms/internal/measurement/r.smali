.class public final Lcom/google/android/gms/internal/measurement/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lcom/google/android/gms/internal/measurement/o;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string p1, "StringValue cannot be null."

    .line 12
    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Lcom/google/android/gms/internal/measurement/r;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Lcom/google/android/gms/internal/measurement/r;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/q;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Lcom/google/android/gms/internal/measurement/q;-><init>(Lcom/google/android/gms/internal/measurement/r;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final j()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    xor-int/lit8 p0, p0, 0x1

    .line 8
    .line 9
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final m()Ljava/util/Iterator;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/q;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lcom/google/android/gms/internal/measurement/q;-><init>(Lcom/google/android/gms/internal/measurement/r;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final n()Ljava/lang/Double;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    :try_start_0
    invoke-static {p0}, Ljava/lang/Double;->valueOf(Ljava/lang/String;)Ljava/lang/Double;

    .line 10
    .line 11
    .line 12
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    return-object p0

    .line 14
    :catch_0
    const-wide/high16 v0, 0x7ff8000000000000L    # Double.NaN

    .line 15
    .line 16
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :cond_0
    const-wide/16 v0, 0x0

    .line 22
    .line 23
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method public final o(Ljava/lang/String;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;)Lcom/google/android/gms/internal/measurement/o;
    .locals 27

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    const-string v4, "charAt"

    .line 4
    .line 5
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v5

    .line 9
    const-string v6, "trim"

    .line 10
    .line 11
    const-string v7, "concat"

    .line 12
    .line 13
    const-string v8, "toLocaleUpperCase"

    .line 14
    .line 15
    const-string v9, "toString"

    .line 16
    .line 17
    const-string v10, "toLocaleLowerCase"

    .line 18
    .line 19
    const-string v11, "toLowerCase"

    .line 20
    .line 21
    const-string v12, "substring"

    .line 22
    .line 23
    const-string v13, "split"

    .line 24
    .line 25
    const-string v14, "slice"

    .line 26
    .line 27
    const-string v15, "search"

    .line 28
    .line 29
    move/from16 v16, v5

    .line 30
    .line 31
    const-string v5, "replace"

    .line 32
    .line 33
    move-object/from16 v17, v4

    .line 34
    .line 35
    const-string v4, "match"

    .line 36
    .line 37
    const-string v2, "lastIndexOf"

    .line 38
    .line 39
    const-string v3, "indexOf"

    .line 40
    .line 41
    const-string v0, "hasOwnProperty"

    .line 42
    .line 43
    move-object/from16 v18, v6

    .line 44
    .line 45
    const-string v6, "toUpperCase"

    .line 46
    .line 47
    if-nez v16, :cond_1

    .line 48
    .line 49
    invoke-virtual {v7, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v16

    .line 53
    if-nez v16, :cond_1

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v16

    .line 59
    if-nez v16, :cond_1

    .line 60
    .line 61
    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v16

    .line 65
    if-nez v16, :cond_1

    .line 66
    .line 67
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v16

    .line 71
    if-nez v16, :cond_1

    .line 72
    .line 73
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v16

    .line 77
    if-nez v16, :cond_1

    .line 78
    .line 79
    invoke-virtual {v5, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v16

    .line 83
    if-nez v16, :cond_1

    .line 84
    .line 85
    invoke-virtual {v15, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v16

    .line 89
    if-nez v16, :cond_1

    .line 90
    .line 91
    invoke-virtual {v14, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v16

    .line 95
    if-nez v16, :cond_1

    .line 96
    .line 97
    invoke-virtual {v13, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v16

    .line 101
    if-nez v16, :cond_1

    .line 102
    .line 103
    invoke-virtual {v12, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v16

    .line 107
    if-nez v16, :cond_1

    .line 108
    .line 109
    invoke-virtual {v11, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v16

    .line 113
    if-nez v16, :cond_1

    .line 114
    .line 115
    invoke-virtual {v10, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v16

    .line 119
    if-nez v16, :cond_1

    .line 120
    .line 121
    invoke-virtual {v9, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v16

    .line 125
    if-nez v16, :cond_1

    .line 126
    .line 127
    invoke-virtual {v6, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v16

    .line 131
    if-nez v16, :cond_1

    .line 132
    .line 133
    invoke-virtual {v8, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v16

    .line 137
    if-nez v16, :cond_1

    .line 138
    .line 139
    move-object/from16 v16, v0

    .line 140
    .line 141
    move-object/from16 v0, v18

    .line 142
    .line 143
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v18

    .line 147
    if-eqz v18, :cond_0

    .line 148
    .line 149
    goto :goto_0

    .line 150
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 151
    .line 152
    const-string v2, " is not a String function"

    .line 153
    .line 154
    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw v0

    .line 162
    :cond_1
    move-object/from16 v16, v0

    .line 163
    .line 164
    move-object/from16 v0, v18

    .line 165
    .line 166
    :goto_0
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 167
    .line 168
    .line 169
    move-result v18

    .line 170
    const-string v19, "undefined"

    .line 171
    .line 172
    move-object/from16 v20, v9

    .line 173
    .line 174
    move-object/from16 v21, v10

    .line 175
    .line 176
    const-wide/16 v22, 0x0

    .line 177
    .line 178
    move-object/from16 v10, p0

    .line 179
    .line 180
    iget-object v9, v10, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 181
    .line 182
    move-object/from16 v25, v7

    .line 183
    .line 184
    const/4 v7, 0x0

    .line 185
    sparse-switch v18, :sswitch_data_0

    .line 186
    .line 187
    .line 188
    goto/16 :goto_14

    .line 189
    .line 190
    :sswitch_0
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    if-eqz v0, :cond_22

    .line 195
    .line 196
    move-object/from16 v11, p3

    .line 197
    .line 198
    const/4 v0, 0x2

    .line 199
    invoke-static {v0, v3, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    if-gtz v0, :cond_2

    .line 207
    .line 208
    move-object/from16 v3, p2

    .line 209
    .line 210
    :goto_1
    move-object/from16 v0, v19

    .line 211
    .line 212
    goto :goto_2

    .line 213
    :cond_2
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 218
    .line 219
    move-object/from16 v3, p2

    .line 220
    .line 221
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 224
    .line 225
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v19

    .line 233
    goto :goto_1

    .line 234
    :goto_2
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 235
    .line 236
    .line 237
    move-result v1

    .line 238
    const/4 v2, 0x2

    .line 239
    if-ge v1, v2, :cond_3

    .line 240
    .line 241
    move-wide/from16 v1, v22

    .line 242
    .line 243
    goto :goto_3

    .line 244
    :cond_3
    const/4 v1, 0x1

    .line 245
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 250
    .line 251
    iget-object v2, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 254
    .line 255
    invoke-virtual {v2, v3, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 264
    .line 265
    .line 266
    move-result-wide v1

    .line 267
    :goto_3
    invoke-static {v1, v2}, Ljp/wd;->i(D)D

    .line 268
    .line 269
    .line 270
    move-result-wide v1

    .line 271
    double-to-int v1, v1

    .line 272
    new-instance v2, Lcom/google/android/gms/internal/measurement/h;

    .line 273
    .line 274
    invoke-virtual {v9, v0, v1}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    .line 275
    .line 276
    .line 277
    move-result v0

    .line 278
    int-to-double v0, v0

    .line 279
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    invoke-direct {v2, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 284
    .line 285
    .line 286
    return-object v2

    .line 287
    :sswitch_1
    move-object/from16 v3, p2

    .line 288
    .line 289
    move-object/from16 v11, p3

    .line 290
    .line 291
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 292
    .line 293
    .line 294
    move-result v0

    .line 295
    if-eqz v0, :cond_22

    .line 296
    .line 297
    const/4 v0, 0x2

    .line 298
    invoke-static {v0, v5, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 302
    .line 303
    .line 304
    move-result v0

    .line 305
    sget-object v1, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 306
    .line 307
    if-nez v0, :cond_4

    .line 308
    .line 309
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 314
    .line 315
    iget-object v2, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 318
    .line 319
    invoke-virtual {v2, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object v19

    .line 327
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 328
    .line 329
    .line 330
    move-result v0

    .line 331
    const/4 v2, 0x1

    .line 332
    if-le v0, v2, :cond_4

    .line 333
    .line 334
    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 339
    .line 340
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 343
    .line 344
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 345
    .line 346
    .line 347
    move-result-object v1

    .line 348
    :cond_4
    move-object/from16 v0, v19

    .line 349
    .line 350
    invoke-virtual {v9, v0}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 351
    .line 352
    .line 353
    move-result v2

    .line 354
    if-ltz v2, :cond_1c

    .line 355
    .line 356
    instance-of v4, v1, Lcom/google/android/gms/internal/measurement/i;

    .line 357
    .line 358
    if-eqz v4, :cond_5

    .line 359
    .line 360
    check-cast v1, Lcom/google/android/gms/internal/measurement/i;

    .line 361
    .line 362
    new-instance v4, Lcom/google/android/gms/internal/measurement/r;

    .line 363
    .line 364
    invoke-direct {v4, v0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    int-to-double v5, v2

    .line 368
    new-instance v8, Lcom/google/android/gms/internal/measurement/h;

    .line 369
    .line 370
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 371
    .line 372
    .line 373
    move-result-object v5

    .line 374
    invoke-direct {v8, v5}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 375
    .line 376
    .line 377
    const/4 v5, 0x3

    .line 378
    new-array v5, v5, [Lcom/google/android/gms/internal/measurement/o;

    .line 379
    .line 380
    aput-object v4, v5, v7

    .line 381
    .line 382
    const/16 v26, 0x1

    .line 383
    .line 384
    aput-object v8, v5, v26

    .line 385
    .line 386
    const/16 v24, 0x2

    .line 387
    .line 388
    aput-object v10, v5, v24

    .line 389
    .line 390
    invoke-static {v5}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 391
    .line 392
    .line 393
    move-result-object v4

    .line 394
    invoke-virtual {v1, v3, v4}, Lcom/google/android/gms/internal/measurement/i;->a(Lcom/google/firebase/messaging/w;Ljava/util/List;)Lcom/google/android/gms/internal/measurement/o;

    .line 395
    .line 396
    .line 397
    move-result-object v1

    .line 398
    :cond_5
    new-instance v3, Lcom/google/android/gms/internal/measurement/r;

    .line 399
    .line 400
    invoke-virtual {v9, v7, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 409
    .line 410
    .line 411
    move-result v0

    .line 412
    add-int/2addr v0, v2

    .line 413
    invoke-virtual {v9, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    invoke-static {v4}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v2

    .line 421
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 422
    .line 423
    .line 424
    move-result v2

    .line 425
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 426
    .line 427
    .line 428
    move-result-object v5

    .line 429
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 430
    .line 431
    .line 432
    move-result v5

    .line 433
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 434
    .line 435
    .line 436
    move-result-object v6

    .line 437
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 438
    .line 439
    .line 440
    move-result v6

    .line 441
    new-instance v7, Ljava/lang/StringBuilder;

    .line 442
    .line 443
    add-int/2addr v2, v5

    .line 444
    add-int/2addr v2, v6

    .line 445
    invoke-direct {v7, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 446
    .line 447
    .line 448
    invoke-static {v7, v4, v1, v0}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 449
    .line 450
    .line 451
    move-result-object v0

    .line 452
    invoke-direct {v3, v0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 453
    .line 454
    .line 455
    return-object v3

    .line 456
    :sswitch_2
    move-object/from16 v3, p2

    .line 457
    .line 458
    move-object/from16 v11, p3

    .line 459
    .line 460
    invoke-virtual {v1, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    if-eqz v0, :cond_22

    .line 465
    .line 466
    const/4 v0, 0x2

    .line 467
    invoke-static {v0, v12, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 468
    .line 469
    .line 470
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 471
    .line 472
    .line 473
    move-result v0

    .line 474
    if-nez v0, :cond_6

    .line 475
    .line 476
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 481
    .line 482
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 483
    .line 484
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 485
    .line 486
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 491
    .line 492
    .line 493
    move-result-object v0

    .line 494
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 495
    .line 496
    .line 497
    move-result-wide v0

    .line 498
    invoke-static {v0, v1}, Ljp/wd;->i(D)D

    .line 499
    .line 500
    .line 501
    move-result-wide v0

    .line 502
    double-to-int v0, v0

    .line 503
    goto :goto_4

    .line 504
    :cond_6
    move v0, v7

    .line 505
    :goto_4
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 506
    .line 507
    .line 508
    move-result v1

    .line 509
    const/4 v2, 0x1

    .line 510
    if-le v1, v2, :cond_7

    .line 511
    .line 512
    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v1

    .line 516
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 517
    .line 518
    iget-object v2, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 519
    .line 520
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 521
    .line 522
    invoke-virtual {v2, v3, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 523
    .line 524
    .line 525
    move-result-object v1

    .line 526
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 527
    .line 528
    .line 529
    move-result-object v1

    .line 530
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 531
    .line 532
    .line 533
    move-result-wide v1

    .line 534
    invoke-static {v1, v2}, Ljp/wd;->i(D)D

    .line 535
    .line 536
    .line 537
    move-result-wide v1

    .line 538
    double-to-int v1, v1

    .line 539
    goto :goto_5

    .line 540
    :cond_7
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 541
    .line 542
    .line 543
    move-result v1

    .line 544
    :goto_5
    invoke-static {v0, v7}, Ljava/lang/Math;->max(II)I

    .line 545
    .line 546
    .line 547
    move-result v0

    .line 548
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 549
    .line 550
    .line 551
    move-result v2

    .line 552
    invoke-static {v0, v2}, Ljava/lang/Math;->min(II)I

    .line 553
    .line 554
    .line 555
    move-result v0

    .line 556
    invoke-static {v1, v7}, Ljava/lang/Math;->max(II)I

    .line 557
    .line 558
    .line 559
    move-result v1

    .line 560
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 561
    .line 562
    .line 563
    move-result v2

    .line 564
    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    .line 565
    .line 566
    .line 567
    move-result v1

    .line 568
    new-instance v2, Lcom/google/android/gms/internal/measurement/r;

    .line 569
    .line 570
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 571
    .line 572
    .line 573
    move-result v3

    .line 574
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 575
    .line 576
    .line 577
    move-result v0

    .line 578
    invoke-virtual {v9, v3, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 579
    .line 580
    .line 581
    move-result-object v0

    .line 582
    invoke-direct {v2, v0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 583
    .line 584
    .line 585
    return-object v2

    .line 586
    :sswitch_3
    move-object/from16 v3, p2

    .line 587
    .line 588
    move-object/from16 v11, p3

    .line 589
    .line 590
    invoke-virtual {v1, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 591
    .line 592
    .line 593
    move-result v0

    .line 594
    if-eqz v0, :cond_22

    .line 595
    .line 596
    const/4 v0, 0x2

    .line 597
    invoke-static {v0, v13, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 598
    .line 599
    .line 600
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 601
    .line 602
    .line 603
    move-result v0

    .line 604
    if-nez v0, :cond_8

    .line 605
    .line 606
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 607
    .line 608
    const/4 v2, 0x1

    .line 609
    new-array v1, v2, [Lcom/google/android/gms/internal/measurement/o;

    .line 610
    .line 611
    aput-object v10, v1, v7

    .line 612
    .line 613
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 614
    .line 615
    .line 616
    move-result-object v1

    .line 617
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/e;-><init>(Ljava/util/List;)V

    .line 618
    .line 619
    .line 620
    return-object v0

    .line 621
    :cond_8
    new-instance v0, Ljava/util/ArrayList;

    .line 622
    .line 623
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 624
    .line 625
    .line 626
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 627
    .line 628
    .line 629
    move-result v1

    .line 630
    if-eqz v1, :cond_9

    .line 631
    .line 632
    invoke-virtual {v0, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 633
    .line 634
    .line 635
    goto/16 :goto_8

    .line 636
    .line 637
    :cond_9
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 638
    .line 639
    .line 640
    move-result-object v1

    .line 641
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 642
    .line 643
    iget-object v2, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 644
    .line 645
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 646
    .line 647
    invoke-virtual {v2, v3, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 648
    .line 649
    .line 650
    move-result-object v1

    .line 651
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 652
    .line 653
    .line 654
    move-result-object v1

    .line 655
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 656
    .line 657
    .line 658
    move-result v2

    .line 659
    const/4 v4, 0x1

    .line 660
    if-le v2, v4, :cond_a

    .line 661
    .line 662
    invoke-virtual {v11, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 663
    .line 664
    .line 665
    move-result-object v2

    .line 666
    check-cast v2, Lcom/google/android/gms/internal/measurement/o;

    .line 667
    .line 668
    iget-object v4, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 669
    .line 670
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 671
    .line 672
    invoke-virtual {v4, v3, v2}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 673
    .line 674
    .line 675
    move-result-object v2

    .line 676
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 677
    .line 678
    .line 679
    move-result-object v2

    .line 680
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 681
    .line 682
    .line 683
    move-result-wide v2

    .line 684
    invoke-static {v2, v3}, Ljp/wd;->h(D)I

    .line 685
    .line 686
    .line 687
    move-result v2

    .line 688
    int-to-long v2, v2

    .line 689
    const-wide v4, 0xffffffffL

    .line 690
    .line 691
    .line 692
    .line 693
    .line 694
    and-long/2addr v2, v4

    .line 695
    goto :goto_6

    .line 696
    :cond_a
    const-wide/32 v2, 0x7fffffff

    .line 697
    .line 698
    .line 699
    :goto_6
    const-wide/16 v4, 0x0

    .line 700
    .line 701
    cmp-long v4, v2, v4

    .line 702
    .line 703
    if-nez v4, :cond_b

    .line 704
    .line 705
    new-instance v0, Lcom/google/android/gms/internal/measurement/e;

    .line 706
    .line 707
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/e;-><init>()V

    .line 708
    .line 709
    .line 710
    return-object v0

    .line 711
    :cond_b
    invoke-static {v1}, Ljava/util/regex/Pattern;->quote(Ljava/lang/String;)Ljava/lang/String;

    .line 712
    .line 713
    .line 714
    move-result-object v4

    .line 715
    long-to-int v5, v2

    .line 716
    const/16 v26, 0x1

    .line 717
    .line 718
    add-int/lit8 v5, v5, 0x1

    .line 719
    .line 720
    invoke-virtual {v9, v4, v5}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 721
    .line 722
    .line 723
    move-result-object v4

    .line 724
    array-length v5, v4

    .line 725
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 726
    .line 727
    .line 728
    move-result v1

    .line 729
    if-eqz v1, :cond_c

    .line 730
    .line 731
    if-lez v5, :cond_c

    .line 732
    .line 733
    aget-object v1, v4, v7

    .line 734
    .line 735
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 736
    .line 737
    .line 738
    move-result v7

    .line 739
    add-int/lit8 v1, v5, -0x1

    .line 740
    .line 741
    aget-object v6, v4, v1

    .line 742
    .line 743
    invoke-virtual {v6}, Ljava/lang/String;->isEmpty()Z

    .line 744
    .line 745
    .line 746
    move-result v6

    .line 747
    if-nez v6, :cond_d

    .line 748
    .line 749
    :cond_c
    move v1, v5

    .line 750
    :cond_d
    int-to-long v5, v5

    .line 751
    cmp-long v2, v5, v2

    .line 752
    .line 753
    if-lez v2, :cond_e

    .line 754
    .line 755
    add-int/lit8 v1, v1, -0x1

    .line 756
    .line 757
    :cond_e
    :goto_7
    if-ge v7, v1, :cond_f

    .line 758
    .line 759
    new-instance v2, Lcom/google/android/gms/internal/measurement/r;

    .line 760
    .line 761
    aget-object v3, v4, v7

    .line 762
    .line 763
    invoke-direct {v2, v3}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 764
    .line 765
    .line 766
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 767
    .line 768
    .line 769
    add-int/lit8 v7, v7, 0x1

    .line 770
    .line 771
    goto :goto_7

    .line 772
    :cond_f
    :goto_8
    new-instance v1, Lcom/google/android/gms/internal/measurement/e;

    .line 773
    .line 774
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/e;-><init>(Ljava/util/List;)V

    .line 775
    .line 776
    .line 777
    return-object v1

    .line 778
    :sswitch_4
    move-object/from16 v3, p2

    .line 779
    .line 780
    move-object/from16 v11, p3

    .line 781
    .line 782
    invoke-virtual {v1, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 783
    .line 784
    .line 785
    move-result v0

    .line 786
    if-eqz v0, :cond_22

    .line 787
    .line 788
    const/4 v0, 0x2

    .line 789
    invoke-static {v0, v14, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 790
    .line 791
    .line 792
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 793
    .line 794
    .line 795
    move-result v0

    .line 796
    if-nez v0, :cond_10

    .line 797
    .line 798
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 799
    .line 800
    .line 801
    move-result-object v0

    .line 802
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 803
    .line 804
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 805
    .line 806
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 807
    .line 808
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 809
    .line 810
    .line 811
    move-result-object v0

    .line 812
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 813
    .line 814
    .line 815
    move-result-object v0

    .line 816
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 817
    .line 818
    .line 819
    move-result-wide v0

    .line 820
    goto :goto_9

    .line 821
    :cond_10
    move-wide/from16 v0, v22

    .line 822
    .line 823
    :goto_9
    invoke-static {v0, v1}, Ljp/wd;->i(D)D

    .line 824
    .line 825
    .line 826
    move-result-wide v0

    .line 827
    cmpg-double v2, v0, v22

    .line 828
    .line 829
    if-gez v2, :cond_11

    .line 830
    .line 831
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 832
    .line 833
    .line 834
    move-result v2

    .line 835
    int-to-double v4, v2

    .line 836
    add-double/2addr v4, v0

    .line 837
    move-wide/from16 v0, v22

    .line 838
    .line 839
    invoke-static {v4, v5, v0, v1}, Ljava/lang/Math;->max(DD)D

    .line 840
    .line 841
    .line 842
    move-result-wide v4

    .line 843
    goto :goto_a

    .line 844
    :cond_11
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 845
    .line 846
    .line 847
    move-result v2

    .line 848
    int-to-double v4, v2

    .line 849
    invoke-static {v0, v1, v4, v5}, Ljava/lang/Math;->min(DD)D

    .line 850
    .line 851
    .line 852
    move-result-wide v4

    .line 853
    :goto_a
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 854
    .line 855
    .line 856
    move-result v0

    .line 857
    const/4 v2, 0x1

    .line 858
    if-le v0, v2, :cond_12

    .line 859
    .line 860
    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 861
    .line 862
    .line 863
    move-result-object v0

    .line 864
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 865
    .line 866
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 867
    .line 868
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 869
    .line 870
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 871
    .line 872
    .line 873
    move-result-object v0

    .line 874
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 875
    .line 876
    .line 877
    move-result-object v0

    .line 878
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 879
    .line 880
    .line 881
    move-result-wide v0

    .line 882
    goto :goto_b

    .line 883
    :cond_12
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 884
    .line 885
    .line 886
    move-result v0

    .line 887
    int-to-double v0, v0

    .line 888
    :goto_b
    invoke-static {v0, v1}, Ljp/wd;->i(D)D

    .line 889
    .line 890
    .line 891
    move-result-wide v0

    .line 892
    const-wide/16 v2, 0x0

    .line 893
    .line 894
    cmpg-double v6, v0, v2

    .line 895
    .line 896
    if-gez v6, :cond_13

    .line 897
    .line 898
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 899
    .line 900
    .line 901
    move-result v6

    .line 902
    int-to-double v10, v6

    .line 903
    add-double/2addr v10, v0

    .line 904
    invoke-static {v10, v11, v2, v3}, Ljava/lang/Math;->max(DD)D

    .line 905
    .line 906
    .line 907
    move-result-wide v0

    .line 908
    goto :goto_c

    .line 909
    :cond_13
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 910
    .line 911
    .line 912
    move-result v2

    .line 913
    int-to-double v2, v2

    .line 914
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(DD)D

    .line 915
    .line 916
    .line 917
    move-result-wide v0

    .line 918
    :goto_c
    double-to-int v2, v4

    .line 919
    double-to-int v0, v0

    .line 920
    sub-int/2addr v0, v2

    .line 921
    invoke-static {v7, v0}, Ljava/lang/Math;->max(II)I

    .line 922
    .line 923
    .line 924
    move-result v0

    .line 925
    add-int/2addr v0, v2

    .line 926
    new-instance v1, Lcom/google/android/gms/internal/measurement/r;

    .line 927
    .line 928
    invoke-virtual {v9, v2, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 929
    .line 930
    .line 931
    move-result-object v0

    .line 932
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 933
    .line 934
    .line 935
    return-object v1

    .line 936
    :sswitch_5
    move-object/from16 v3, p2

    .line 937
    .line 938
    move-object/from16 v11, p3

    .line 939
    .line 940
    invoke-virtual {v1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 941
    .line 942
    .line 943
    move-result v0

    .line 944
    if-eqz v0, :cond_22

    .line 945
    .line 946
    const/4 v2, 0x1

    .line 947
    invoke-static {v2, v4, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 948
    .line 949
    .line 950
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 951
    .line 952
    .line 953
    move-result v0

    .line 954
    if-gtz v0, :cond_14

    .line 955
    .line 956
    const-string v0, ""

    .line 957
    .line 958
    goto :goto_d

    .line 959
    :cond_14
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 960
    .line 961
    .line 962
    move-result-object v0

    .line 963
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 964
    .line 965
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 966
    .line 967
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 968
    .line 969
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 970
    .line 971
    .line 972
    move-result-object v0

    .line 973
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 974
    .line 975
    .line 976
    move-result-object v0

    .line 977
    :goto_d
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 978
    .line 979
    .line 980
    move-result-object v0

    .line 981
    invoke-virtual {v0, v9}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 982
    .line 983
    .line 984
    move-result-object v0

    .line 985
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->find()Z

    .line 986
    .line 987
    .line 988
    move-result v1

    .line 989
    if-eqz v1, :cond_15

    .line 990
    .line 991
    new-instance v1, Lcom/google/android/gms/internal/measurement/e;

    .line 992
    .line 993
    new-instance v2, Lcom/google/android/gms/internal/measurement/r;

    .line 994
    .line 995
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->group()Ljava/lang/String;

    .line 996
    .line 997
    .line 998
    move-result-object v0

    .line 999
    invoke-direct {v2, v0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1000
    .line 1001
    .line 1002
    const/4 v4, 0x1

    .line 1003
    new-array v0, v4, [Lcom/google/android/gms/internal/measurement/o;

    .line 1004
    .line 1005
    aput-object v2, v0, v7

    .line 1006
    .line 1007
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v0

    .line 1011
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/e;-><init>(Ljava/util/List;)V

    .line 1012
    .line 1013
    .line 1014
    return-object v1

    .line 1015
    :cond_15
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->n0:Lcom/google/android/gms/internal/measurement/m;

    .line 1016
    .line 1017
    return-object v0

    .line 1018
    :sswitch_6
    move-object/from16 v11, p3

    .line 1019
    .line 1020
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1021
    .line 1022
    .line 1023
    move-result v0

    .line 1024
    if-eqz v0, :cond_22

    .line 1025
    .line 1026
    invoke-static {v7, v6, v11}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1027
    .line 1028
    .line 1029
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1030
    .line 1031
    invoke-virtual {v9}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v1

    .line 1035
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1036
    .line 1037
    .line 1038
    return-object v0

    .line 1039
    :sswitch_7
    move-object/from16 v11, p3

    .line 1040
    .line 1041
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1042
    .line 1043
    .line 1044
    move-result v0

    .line 1045
    if-eqz v0, :cond_22

    .line 1046
    .line 1047
    invoke-static {v7, v6, v11}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1048
    .line 1049
    .line 1050
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1051
    .line 1052
    sget-object v1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 1053
    .line 1054
    invoke-virtual {v9, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v1

    .line 1058
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1059
    .line 1060
    .line 1061
    return-object v0

    .line 1062
    :sswitch_8
    move-object/from16 v3, p2

    .line 1063
    .line 1064
    move-object/from16 v11, p3

    .line 1065
    .line 1066
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1067
    .line 1068
    .line 1069
    move-result v0

    .line 1070
    if-eqz v0, :cond_22

    .line 1071
    .line 1072
    const/4 v0, 0x2

    .line 1073
    invoke-static {v0, v2, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 1074
    .line 1075
    .line 1076
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1077
    .line 1078
    .line 1079
    move-result v0

    .line 1080
    if-gtz v0, :cond_16

    .line 1081
    .line 1082
    :goto_e
    move-object/from16 v0, v19

    .line 1083
    .line 1084
    goto :goto_f

    .line 1085
    :cond_16
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1086
    .line 1087
    .line 1088
    move-result-object v0

    .line 1089
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1090
    .line 1091
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1092
    .line 1093
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1094
    .line 1095
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v0

    .line 1099
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v19

    .line 1103
    goto :goto_e

    .line 1104
    :goto_f
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1105
    .line 1106
    .line 1107
    move-result v1

    .line 1108
    const/4 v2, 0x2

    .line 1109
    if-ge v1, v2, :cond_17

    .line 1110
    .line 1111
    const-wide/high16 v1, 0x7ff8000000000000L    # Double.NaN

    .line 1112
    .line 1113
    goto :goto_10

    .line 1114
    :cond_17
    const/4 v2, 0x1

    .line 1115
    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1116
    .line 1117
    .line 1118
    move-result-object v1

    .line 1119
    check-cast v1, Lcom/google/android/gms/internal/measurement/o;

    .line 1120
    .line 1121
    iget-object v2, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1122
    .line 1123
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 1124
    .line 1125
    invoke-virtual {v2, v3, v1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1126
    .line 1127
    .line 1128
    move-result-object v1

    .line 1129
    invoke-interface {v1}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v1

    .line 1133
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 1134
    .line 1135
    .line 1136
    move-result-wide v1

    .line 1137
    :goto_10
    invoke-static {v1, v2}, Ljava/lang/Double;->isNaN(D)Z

    .line 1138
    .line 1139
    .line 1140
    move-result v3

    .line 1141
    if-eqz v3, :cond_18

    .line 1142
    .line 1143
    const-wide/high16 v1, 0x7ff0000000000000L    # Double.POSITIVE_INFINITY

    .line 1144
    .line 1145
    goto :goto_11

    .line 1146
    :cond_18
    invoke-static {v1, v2}, Ljp/wd;->i(D)D

    .line 1147
    .line 1148
    .line 1149
    move-result-wide v1

    .line 1150
    :goto_11
    double-to-int v1, v1

    .line 1151
    new-instance v2, Lcom/google/android/gms/internal/measurement/h;

    .line 1152
    .line 1153
    invoke-virtual {v9, v0, v1}, Ljava/lang/String;->lastIndexOf(Ljava/lang/String;I)I

    .line 1154
    .line 1155
    .line 1156
    move-result v0

    .line 1157
    int-to-double v0, v0

    .line 1158
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v0

    .line 1162
    invoke-direct {v2, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1163
    .line 1164
    .line 1165
    return-object v2

    .line 1166
    :sswitch_9
    move-object/from16 v11, p3

    .line 1167
    .line 1168
    invoke-virtual {v1, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1169
    .line 1170
    .line 1171
    move-result v0

    .line 1172
    if-eqz v0, :cond_22

    .line 1173
    .line 1174
    invoke-static {v7, v8, v11}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1175
    .line 1176
    .line 1177
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1178
    .line 1179
    invoke-virtual {v9}, Ljava/lang/String;->toUpperCase()Ljava/lang/String;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v1

    .line 1183
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1184
    .line 1185
    .line 1186
    return-object v0

    .line 1187
    :sswitch_a
    move-object/from16 v3, p2

    .line 1188
    .line 1189
    move-object/from16 v11, p3

    .line 1190
    .line 1191
    invoke-virtual {v1, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1192
    .line 1193
    .line 1194
    move-result v0

    .line 1195
    if-eqz v0, :cond_22

    .line 1196
    .line 1197
    const/4 v2, 0x1

    .line 1198
    invoke-static {v2, v15, v11}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 1199
    .line 1200
    .line 1201
    invoke-virtual {v11}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1202
    .line 1203
    .line 1204
    move-result v0

    .line 1205
    if-nez v0, :cond_19

    .line 1206
    .line 1207
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v0

    .line 1211
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1212
    .line 1213
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1214
    .line 1215
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1216
    .line 1217
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1218
    .line 1219
    .line 1220
    move-result-object v0

    .line 1221
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v19

    .line 1225
    :cond_19
    invoke-static/range {v19 .. v19}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v0

    .line 1229
    invoke-virtual {v0, v9}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 1230
    .line 1231
    .line 1232
    move-result-object v0

    .line 1233
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->find()Z

    .line 1234
    .line 1235
    .line 1236
    move-result v1

    .line 1237
    if-eqz v1, :cond_1a

    .line 1238
    .line 1239
    new-instance v1, Lcom/google/android/gms/internal/measurement/h;

    .line 1240
    .line 1241
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->start()I

    .line 1242
    .line 1243
    .line 1244
    move-result v0

    .line 1245
    int-to-double v2, v0

    .line 1246
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1247
    .line 1248
    .line 1249
    move-result-object v0

    .line 1250
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1251
    .line 1252
    .line 1253
    return-object v1

    .line 1254
    :cond_1a
    new-instance v0, Lcom/google/android/gms/internal/measurement/h;

    .line 1255
    .line 1256
    const-wide/high16 v1, -0x4010000000000000L    # -1.0

    .line 1257
    .line 1258
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v1

    .line 1262
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 1263
    .line 1264
    .line 1265
    return-object v0

    .line 1266
    :sswitch_b
    move-object/from16 v0, p3

    .line 1267
    .line 1268
    invoke-virtual {v1, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1269
    .line 1270
    .line 1271
    move-result v1

    .line 1272
    if-eqz v1, :cond_22

    .line 1273
    .line 1274
    invoke-static {v7, v11, v0}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1275
    .line 1276
    .line 1277
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1278
    .line 1279
    sget-object v1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 1280
    .line 1281
    invoke-virtual {v9, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v1

    .line 1285
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1286
    .line 1287
    .line 1288
    return-object v0

    .line 1289
    :sswitch_c
    move-object/from16 v3, p2

    .line 1290
    .line 1291
    move-object/from16 v0, p3

    .line 1292
    .line 1293
    move-object/from16 v2, v25

    .line 1294
    .line 1295
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1296
    .line 1297
    .line 1298
    move-result v1

    .line 1299
    if-eqz v1, :cond_22

    .line 1300
    .line 1301
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1302
    .line 1303
    .line 1304
    move-result v1

    .line 1305
    if-nez v1, :cond_1c

    .line 1306
    .line 1307
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1308
    .line 1309
    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1310
    .line 1311
    .line 1312
    :goto_12
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 1313
    .line 1314
    .line 1315
    move-result v2

    .line 1316
    if-ge v7, v2, :cond_1b

    .line 1317
    .line 1318
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v2

    .line 1322
    check-cast v2, Lcom/google/android/gms/internal/measurement/o;

    .line 1323
    .line 1324
    iget-object v4, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1325
    .line 1326
    check-cast v4, Lcom/google/android/gms/internal/measurement/u;

    .line 1327
    .line 1328
    invoke-virtual {v4, v3, v2}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1329
    .line 1330
    .line 1331
    move-result-object v2

    .line 1332
    invoke-interface {v2}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 1333
    .line 1334
    .line 1335
    move-result-object v2

    .line 1336
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1337
    .line 1338
    .line 1339
    add-int/lit8 v7, v7, 0x1

    .line 1340
    .line 1341
    goto :goto_12

    .line 1342
    :cond_1b
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1343
    .line 1344
    .line 1345
    move-result-object v0

    .line 1346
    new-instance v1, Lcom/google/android/gms/internal/measurement/r;

    .line 1347
    .line 1348
    invoke-direct {v1, v0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1349
    .line 1350
    .line 1351
    return-object v1

    .line 1352
    :cond_1c
    return-object v10

    .line 1353
    :sswitch_d
    move-object/from16 v3, p2

    .line 1354
    .line 1355
    move-object/from16 v0, p3

    .line 1356
    .line 1357
    move-object/from16 v2, v17

    .line 1358
    .line 1359
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1360
    .line 1361
    .line 1362
    move-result v1

    .line 1363
    if-eqz v1, :cond_22

    .line 1364
    .line 1365
    const/4 v4, 0x1

    .line 1366
    invoke-static {v4, v2, v0}, Ljp/wd;->d(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 1367
    .line 1368
    .line 1369
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1370
    .line 1371
    .line 1372
    move-result v1

    .line 1373
    if-nez v1, :cond_1d

    .line 1374
    .line 1375
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v0

    .line 1379
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1380
    .line 1381
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1382
    .line 1383
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1384
    .line 1385
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1386
    .line 1387
    .line 1388
    move-result-object v0

    .line 1389
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v0

    .line 1393
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 1394
    .line 1395
    .line 1396
    move-result-wide v0

    .line 1397
    invoke-static {v0, v1}, Ljp/wd;->i(D)D

    .line 1398
    .line 1399
    .line 1400
    move-result-wide v0

    .line 1401
    double-to-int v7, v0

    .line 1402
    :cond_1d
    if-ltz v7, :cond_1f

    .line 1403
    .line 1404
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 1405
    .line 1406
    .line 1407
    move-result v0

    .line 1408
    if-lt v7, v0, :cond_1e

    .line 1409
    .line 1410
    goto :goto_13

    .line 1411
    :cond_1e
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1412
    .line 1413
    invoke-virtual {v9, v7}, Ljava/lang/String;->charAt(I)C

    .line 1414
    .line 1415
    .line 1416
    move-result v1

    .line 1417
    invoke-static {v1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 1418
    .line 1419
    .line 1420
    move-result-object v1

    .line 1421
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1422
    .line 1423
    .line 1424
    return-object v0

    .line 1425
    :cond_1f
    :goto_13
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->t0:Lcom/google/android/gms/internal/measurement/r;

    .line 1426
    .line 1427
    return-object v0

    .line 1428
    :sswitch_e
    move-object/from16 v0, p3

    .line 1429
    .line 1430
    move-object/from16 v2, v21

    .line 1431
    .line 1432
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1433
    .line 1434
    .line 1435
    move-result v1

    .line 1436
    if-eqz v1, :cond_22

    .line 1437
    .line 1438
    invoke-static {v7, v2, v0}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1439
    .line 1440
    .line 1441
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 1442
    .line 1443
    invoke-virtual {v9}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    .line 1444
    .line 1445
    .line 1446
    move-result-object v1

    .line 1447
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 1448
    .line 1449
    .line 1450
    return-object v0

    .line 1451
    :sswitch_f
    move-object/from16 v0, p3

    .line 1452
    .line 1453
    move-object/from16 v2, v20

    .line 1454
    .line 1455
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1456
    .line 1457
    .line 1458
    move-result v1

    .line 1459
    if-eqz v1, :cond_22

    .line 1460
    .line 1461
    invoke-static {v7, v2, v0}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1462
    .line 1463
    .line 1464
    return-object v10

    .line 1465
    :sswitch_10
    move-object/from16 v3, p2

    .line 1466
    .line 1467
    move-object/from16 v0, p3

    .line 1468
    .line 1469
    move-object/from16 v2, v16

    .line 1470
    .line 1471
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1472
    .line 1473
    .line 1474
    move-result v1

    .line 1475
    if-eqz v1, :cond_22

    .line 1476
    .line 1477
    const/4 v4, 0x1

    .line 1478
    invoke-static {v4, v2, v0}, Ljp/wd;->b(ILjava/lang/String;Ljava/util/List;)V

    .line 1479
    .line 1480
    .line 1481
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1482
    .line 1483
    .line 1484
    move-result-object v0

    .line 1485
    check-cast v0, Lcom/google/android/gms/internal/measurement/o;

    .line 1486
    .line 1487
    iget-object v1, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 1488
    .line 1489
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 1490
    .line 1491
    invoke-virtual {v1, v3, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 1492
    .line 1493
    .line 1494
    move-result-object v0

    .line 1495
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->j()Ljava/lang/String;

    .line 1496
    .line 1497
    .line 1498
    move-result-object v1

    .line 1499
    const-string v2, "length"

    .line 1500
    .line 1501
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1502
    .line 1503
    .line 1504
    move-result v1

    .line 1505
    sget-object v2, Lcom/google/android/gms/internal/measurement/o;->r0:Lcom/google/android/gms/internal/measurement/f;

    .line 1506
    .line 1507
    if-eqz v1, :cond_20

    .line 1508
    .line 1509
    return-object v2

    .line 1510
    :cond_20
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/o;->n()Ljava/lang/Double;

    .line 1511
    .line 1512
    .line 1513
    move-result-object v0

    .line 1514
    invoke-virtual {v0}, Ljava/lang/Double;->doubleValue()D

    .line 1515
    .line 1516
    .line 1517
    move-result-wide v0

    .line 1518
    invoke-static {v0, v1}, Ljava/lang/Math;->floor(D)D

    .line 1519
    .line 1520
    .line 1521
    move-result-wide v3

    .line 1522
    cmpl-double v3, v0, v3

    .line 1523
    .line 1524
    if-nez v3, :cond_21

    .line 1525
    .line 1526
    double-to-int v0, v0

    .line 1527
    if-ltz v0, :cond_21

    .line 1528
    .line 1529
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 1530
    .line 1531
    .line 1532
    move-result v1

    .line 1533
    if-ge v0, v1, :cond_21

    .line 1534
    .line 1535
    return-object v2

    .line 1536
    :cond_21
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->s0:Lcom/google/android/gms/internal/measurement/f;

    .line 1537
    .line 1538
    return-object v0

    .line 1539
    :cond_22
    :goto_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1540
    .line 1541
    const-string v1, "Command not supported"

    .line 1542
    .line 1543
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1544
    .line 1545
    .line 1546
    throw v0

    .line 1547
    :sswitch_data_0
    .sparse-switch
        -0x6aaca37f -> :sswitch_10
        -0x69e9ad94 -> :sswitch_f
        -0x57513364 -> :sswitch_e
        -0x5128e1d7 -> :sswitch_d
        -0x50c088ec -> :sswitch_c
        -0x43ce226a -> :sswitch_b
        -0x36059a58 -> :sswitch_a
        -0x2b53be43 -> :sswitch_9
        -0x1bdda92d -> :sswitch_8
        -0x17d0ad49 -> :sswitch_7
        0x367422 -> :sswitch_6
        0x62dd9c5 -> :sswitch_5
        0x6873d92 -> :sswitch_4
        0x6891b1a -> :sswitch_3
        0x1f9f6e51 -> :sswitch_2
        0x413cb2b4 -> :sswitch_1
        0x73d44649 -> :sswitch_0
    .end sparse-switch
.end method

.method public final p()Lcom/google/android/gms/internal/measurement/o;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/r;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lcom/google/android/gms/internal/measurement/r;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/r;->d:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/lit8 v1, v1, 0x2

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const-string v1, "\""

    .line 15
    .line 16
    invoke-static {v0, v1, p0, v1}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
