.class public final Lz31/e;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ljava/lang/String;

.field public final g:Lay0/k;

.field public final h:Lk31/i0;

.field public final i:Li31/b;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lay0/k;Lk31/i0;Lk31/o;)V
    .locals 12

    .line 1
    new-instance v0, Lz31/g;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const-string v6, ""

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v7, 0x0

    .line 12
    invoke-direct/range {v0 .. v7}, Lz31/g;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/Integer;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lq41/b;-><init>(Lq41/a;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lz31/e;->f:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p2, p0, Lz31/e;->g:Lay0/k;

    .line 21
    .line 22
    iput-object p3, p0, Lz31/e;->h:Lk31/i0;

    .line 23
    .line 24
    invoke-virtual/range {p4 .. p4}, Lk31/o;->invoke()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    check-cast p1, Li31/b;

    .line 29
    .line 30
    iput-object p1, p0, Lz31/e;->i:Li31/b;

    .line 31
    .line 32
    iget-object p1, p0, Lq41/b;->d:Lyy0/c2;

    .line 33
    .line 34
    :cond_0
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    move-object v3, p2

    .line 39
    check-cast v3, Lz31/g;

    .line 40
    .line 41
    iget-object v0, p0, Lz31/e;->i:Li31/b;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    iget-object v0, v0, Li31/b;->c:Ljava/lang/Long;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 51
    .line 52
    .line 53
    move-result-wide v4

    .line 54
    const-string v0, "dd MMMM yyyy, HH:mm"

    .line 55
    .line 56
    invoke-static {v4, v5, v0}, Lcom/google/android/gms/internal/measurement/i5;->b(JLjava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    const-string v4, " hrs"

    .line 61
    .line 62
    invoke-virtual {v0, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    move-object v4, v0

    .line 67
    goto :goto_0

    .line 68
    :cond_1
    move-object v4, v1

    .line 69
    :goto_0
    const/4 v0, 0x3

    .line 70
    new-array v0, v0, [Ljava/util/List;

    .line 71
    .line 72
    iget-object v5, p0, Lz31/e;->i:Li31/b;

    .line 73
    .line 74
    const/16 v6, 0xa

    .line 75
    .line 76
    if-eqz v5, :cond_4

    .line 77
    .line 78
    iget-object v5, v5, Li31/b;->b:Li31/b0;

    .line 79
    .line 80
    iget-object v5, v5, Li31/b0;->a:Ljava/util/List;

    .line 81
    .line 82
    if-eqz v5, :cond_4

    .line 83
    .line 84
    check-cast v5, Ljava/lang/Iterable;

    .line 85
    .line 86
    new-instance v7, Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 89
    .line 90
    .line 91
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    :cond_2
    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v8

    .line 99
    if-eqz v8, :cond_3

    .line 100
    .line 101
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    move-object v9, v8

    .line 106
    check-cast v9, Li31/a0;

    .line 107
    .line 108
    iget-boolean v9, v9, Li31/a0;->b:Z

    .line 109
    .line 110
    if-eqz v9, :cond_2

    .line 111
    .line 112
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_3
    new-instance v5, Ljava/util/ArrayList;

    .line 117
    .line 118
    invoke-static {v7, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 119
    .line 120
    .line 121
    move-result v8

    .line 122
    invoke-direct {v5, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 126
    .line 127
    .line 128
    move-result-object v7

    .line 129
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 130
    .line 131
    .line 132
    move-result v8

    .line 133
    if-eqz v8, :cond_5

    .line 134
    .line 135
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    check-cast v8, Li31/a0;

    .line 140
    .line 141
    new-instance v9, Lz31/f;

    .line 142
    .line 143
    iget-object v8, v8, Li31/a0;->a:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v8, Li31/g0;

    .line 146
    .line 147
    iget-object v8, v8, Li31/g0;->b:Ljava/lang/String;

    .line 148
    .line 149
    invoke-direct {v9, v8}, Lz31/f;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_4
    move-object v5, v1

    .line 157
    :cond_5
    if-nez v5, :cond_6

    .line 158
    .line 159
    move-object v5, v2

    .line 160
    :cond_6
    const/4 v7, 0x0

    .line 161
    aput-object v5, v0, v7

    .line 162
    .line 163
    iget-object v5, p0, Lz31/e;->i:Li31/b;

    .line 164
    .line 165
    if-eqz v5, :cond_9

    .line 166
    .line 167
    iget-object v5, v5, Li31/b;->b:Li31/b0;

    .line 168
    .line 169
    iget-object v5, v5, Li31/b0;->b:Ljava/util/List;

    .line 170
    .line 171
    if-eqz v5, :cond_9

    .line 172
    .line 173
    check-cast v5, Ljava/lang/Iterable;

    .line 174
    .line 175
    new-instance v7, Ljava/util/ArrayList;

    .line 176
    .line 177
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 178
    .line 179
    .line 180
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    :cond_7
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 185
    .line 186
    .line 187
    move-result v8

    .line 188
    if-eqz v8, :cond_8

    .line 189
    .line 190
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v8

    .line 194
    move-object v9, v8

    .line 195
    check-cast v9, Li31/a0;

    .line 196
    .line 197
    iget-boolean v9, v9, Li31/a0;->b:Z

    .line 198
    .line 199
    if-eqz v9, :cond_7

    .line 200
    .line 201
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_8
    new-instance v5, Ljava/util/ArrayList;

    .line 206
    .line 207
    invoke-static {v7, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 208
    .line 209
    .line 210
    move-result v8

    .line 211
    invoke-direct {v5, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 219
    .line 220
    .line 221
    move-result v8

    .line 222
    if-eqz v8, :cond_a

    .line 223
    .line 224
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v8

    .line 228
    check-cast v8, Li31/a0;

    .line 229
    .line 230
    new-instance v9, Lz31/f;

    .line 231
    .line 232
    iget-object v8, v8, Li31/a0;->a:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast v8, Li31/z;

    .line 235
    .line 236
    iget-object v8, v8, Li31/z;->c:Ljava/lang/String;

    .line 237
    .line 238
    invoke-direct {v9, v8}, Lz31/f;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_9
    move-object v5, v1

    .line 246
    :cond_a
    if-nez v5, :cond_b

    .line 247
    .line 248
    move-object v5, v2

    .line 249
    :cond_b
    const/4 v7, 0x1

    .line 250
    aput-object v5, v0, v7

    .line 251
    .line 252
    iget-object v5, p0, Lz31/e;->i:Li31/b;

    .line 253
    .line 254
    if-eqz v5, :cond_e

    .line 255
    .line 256
    iget-object v5, v5, Li31/b;->b:Li31/b0;

    .line 257
    .line 258
    iget-object v5, v5, Li31/b0;->d:Ljava/util/List;

    .line 259
    .line 260
    if-eqz v5, :cond_e

    .line 261
    .line 262
    check-cast v5, Ljava/lang/Iterable;

    .line 263
    .line 264
    new-instance v7, Ljava/util/ArrayList;

    .line 265
    .line 266
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 267
    .line 268
    .line 269
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 270
    .line 271
    .line 272
    move-result-object v5

    .line 273
    :cond_c
    :goto_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 274
    .line 275
    .line 276
    move-result v8

    .line 277
    if-eqz v8, :cond_d

    .line 278
    .line 279
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v8

    .line 283
    move-object v9, v8

    .line 284
    check-cast v9, Li31/a0;

    .line 285
    .line 286
    iget-boolean v9, v9, Li31/a0;->b:Z

    .line 287
    .line 288
    if-eqz v9, :cond_c

    .line 289
    .line 290
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 291
    .line 292
    .line 293
    goto :goto_5

    .line 294
    :cond_d
    new-instance v5, Ljava/util/ArrayList;

    .line 295
    .line 296
    invoke-static {v7, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 297
    .line 298
    .line 299
    move-result v6

    .line 300
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 304
    .line 305
    .line 306
    move-result-object v6

    .line 307
    :goto_6
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 308
    .line 309
    .line 310
    move-result v7

    .line 311
    if-eqz v7, :cond_f

    .line 312
    .line 313
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v7

    .line 317
    check-cast v7, Li31/a0;

    .line 318
    .line 319
    new-instance v8, Lz31/f;

    .line 320
    .line 321
    iget-object v7, v7, Li31/a0;->a:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast v7, Li31/v;

    .line 324
    .line 325
    iget-object v7, v7, Li31/v;->b:Ljava/lang/String;

    .line 326
    .line 327
    invoke-direct {v8, v7}, Lz31/f;-><init>(Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 331
    .line 332
    .line 333
    goto :goto_6

    .line 334
    :cond_e
    move-object v5, v1

    .line 335
    :cond_f
    if-nez v5, :cond_10

    .line 336
    .line 337
    move-object v5, v2

    .line 338
    :cond_10
    const/4 v6, 0x2

    .line 339
    aput-object v5, v0, v6

    .line 340
    .line 341
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    check-cast v0, Ljava/lang/Iterable;

    .line 346
    .line 347
    invoke-static {v0}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 348
    .line 349
    .line 350
    move-result-object v5

    .line 351
    iget-object v0, p0, Lz31/e;->i:Li31/b;

    .line 352
    .line 353
    if-eqz v0, :cond_11

    .line 354
    .line 355
    iget-object v1, v0, Li31/b;->e:Ljava/lang/String;

    .line 356
    .line 357
    :cond_11
    move-object v6, v1

    .line 358
    iget-object v9, p0, Lz31/e;->f:Ljava/lang/String;

    .line 359
    .line 360
    const/4 v10, 0x0

    .line 361
    const/16 v11, 0x58

    .line 362
    .line 363
    const/4 v7, 0x0

    .line 364
    const/4 v8, 0x0

    .line 365
    invoke-static/range {v3 .. v11}, Lz31/g;->a(Lz31/g;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/Integer;I)Lz31/g;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    invoke-virtual {p1, p2, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result p2

    .line 373
    if-eqz p2, :cond_0

    .line 374
    .line 375
    return-void
.end method
