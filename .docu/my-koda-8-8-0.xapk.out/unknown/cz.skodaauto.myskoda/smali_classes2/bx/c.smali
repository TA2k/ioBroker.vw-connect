.class public final Lbx/c;
.super Lcom/squareup/moshi/JsonAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhy0/g;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/util/ArrayList;

.field public final d:Lcom/squareup/moshi/JsonReader$Options;


# direct methods
.method public constructor <init>(Lhy0/g;Ljava/util/ArrayList;Ljava/util/ArrayList;Lcom/squareup/moshi/JsonReader$Options;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/squareup/moshi/JsonAdapter;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbx/c;->a:Lhy0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lbx/c;->b:Ljava/util/ArrayList;

    .line 7
    .line 8
    iput-object p3, p0, Lbx/c;->c:Ljava/util/ArrayList;

    .line 9
    .line 10
    iput-object p4, p0, Lbx/c;->d:Lcom/squareup/moshi/JsonReader$Options;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
    .locals 12

    .line 1
    const-string v0, "reader"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbx/c;->a:Lhy0/g;

    .line 7
    .line 8
    invoke-interface {v0}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    iget-object v2, p0, Lbx/c;->b:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    new-array v4, v3, [Ljava/lang/Object;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    move v6, v5

    .line 26
    :goto_0
    sget-object v7, Lbx/e;->a:Ljava/lang/Object;

    .line 27
    .line 28
    if-ge v6, v3, :cond_0

    .line 29
    .line 30
    aput-object v7, v4, v6

    .line 31
    .line 32
    add-int/lit8 v6, v6, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->b()V

    .line 36
    .line 37
    .line 38
    :cond_1
    :goto_1
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->h()Z

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    const-string v8, "\' (JSON name \'"

    .line 43
    .line 44
    if-eqz v6, :cond_5

    .line 45
    .line 46
    iget-object v6, p0, Lbx/c;->d:Lcom/squareup/moshi/JsonReader$Options;

    .line 47
    .line 48
    invoke-virtual {p1, v6}, Lcom/squareup/moshi/JsonReader;->e0(Lcom/squareup/moshi/JsonReader$Options;)I

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    const/4 v9, -0x1

    .line 53
    if-ne v6, v9, :cond_2

    .line 54
    .line 55
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->k0()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->l0()V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    iget-object v9, p0, Lbx/c;->c:Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    check-cast v6, Lbx/a;

    .line 69
    .line 70
    iget v9, v6, Lbx/a;->e:I

    .line 71
    .line 72
    iget-object v10, v6, Lbx/a;->c:Lhy0/w;

    .line 73
    .line 74
    aget-object v11, v4, v9

    .line 75
    .line 76
    if-ne v11, v7, :cond_4

    .line 77
    .line 78
    iget-object v11, v6, Lbx/a;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 79
    .line 80
    invoke-virtual {v11, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v11

    .line 84
    aput-object v11, v4, v9

    .line 85
    .line 86
    if-nez v11, :cond_1

    .line 87
    .line 88
    invoke-interface {v10}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 89
    .line 90
    .line 91
    move-result-object v9

    .line 92
    invoke-interface {v9}, Lhy0/a0;->isMarkedNullable()Z

    .line 93
    .line 94
    .line 95
    move-result v9

    .line 96
    if-nez v9, :cond_1

    .line 97
    .line 98
    invoke-interface {v10}, Lhy0/c;->getName()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    iget-object v0, v6, Lbx/a;->a:Ljava/lang/String;

    .line 103
    .line 104
    sget-object v1, Lax/b;->a:Ljava/util/Set;

    .line 105
    .line 106
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    const-string v2, "Non-null value \'"

    .line 115
    .line 116
    if-eqz v1, :cond_3

    .line 117
    .line 118
    const-string v0, "\' was null at "

    .line 119
    .line 120
    invoke-static {v2, p0, v0, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    goto :goto_2

    .line 125
    :cond_3
    const-string v1, "\') was null at "

    .line 126
    .line 127
    invoke-static {v2, p0, v8, v0, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    :goto_2
    new-instance p1, Lcom/squareup/moshi/JsonDataException;

    .line 139
    .line 140
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw p1

    .line 144
    :cond_4
    new-instance p0, Lcom/squareup/moshi/JsonDataException;

    .line 145
    .line 146
    new-instance v0, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    const-string v1, "Multiple values for \'"

    .line 149
    .line 150
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    invoke-interface {v10}, Lhy0/c;->getName()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    const-string v1, "\' at "

    .line 161
    .line 162
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :cond_5
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->f()V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 184
    .line 185
    .line 186
    move-result p0

    .line 187
    if-ne p0, v1, :cond_6

    .line 188
    .line 189
    const/4 p0, 0x1

    .line 190
    goto :goto_3

    .line 191
    :cond_6
    move p0, v5

    .line 192
    :goto_3
    move v6, v5

    .line 193
    :goto_4
    if-ge v6, v1, :cond_c

    .line 194
    .line 195
    aget-object v9, v4, v6

    .line 196
    .line 197
    if-ne v9, v7, :cond_b

    .line 198
    .line 199
    invoke-interface {v0}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 200
    .line 201
    .line 202
    move-result-object v9

    .line 203
    invoke-interface {v9, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v9

    .line 207
    check-cast v9, Lhy0/q;

    .line 208
    .line 209
    invoke-interface {v9}, Lhy0/q;->isOptional()Z

    .line 210
    .line 211
    .line 212
    move-result v9

    .line 213
    if-eqz v9, :cond_7

    .line 214
    .line 215
    move p0, v5

    .line 216
    goto :goto_6

    .line 217
    :cond_7
    invoke-interface {v0}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 218
    .line 219
    .line 220
    move-result-object v9

    .line 221
    invoke-interface {v9, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v9

    .line 225
    check-cast v9, Lhy0/q;

    .line 226
    .line 227
    invoke-interface {v9}, Lhy0/q;->getType()Lhy0/a0;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    invoke-interface {v9}, Lhy0/a0;->isMarkedNullable()Z

    .line 232
    .line 233
    .line 234
    move-result v9

    .line 235
    const/4 v10, 0x0

    .line 236
    if-eqz v9, :cond_8

    .line 237
    .line 238
    aput-object v10, v4, v6

    .line 239
    .line 240
    goto :goto_6

    .line 241
    :cond_8
    invoke-interface {v0}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    invoke-interface {p0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object p0

    .line 249
    check-cast p0, Lhy0/q;

    .line 250
    .line 251
    invoke-interface {p0}, Lhy0/q;->getName()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    check-cast v0, Lbx/a;

    .line 260
    .line 261
    if-eqz v0, :cond_9

    .line 262
    .line 263
    iget-object v10, v0, Lbx/a;->a:Ljava/lang/String;

    .line 264
    .line 265
    :cond_9
    sget-object v0, Lax/b;->a:Ljava/util/Set;

    .line 266
    .line 267
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object p1

    .line 271
    invoke-virtual {v10, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v0

    .line 275
    const-string v1, "Required value \'"

    .line 276
    .line 277
    if-eqz v0, :cond_a

    .line 278
    .line 279
    const-string v0, "\' missing at "

    .line 280
    .line 281
    invoke-static {v1, p0, v0, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    goto :goto_5

    .line 286
    :cond_a
    const-string v0, "\') missing at "

    .line 287
    .line 288
    invoke-static {v1, p0, v8, v10, v0}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object p0

    .line 299
    :goto_5
    new-instance p1, Lcom/squareup/moshi/JsonDataException;

    .line 300
    .line 301
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    throw p1

    .line 305
    :cond_b
    :goto_6
    add-int/lit8 v6, v6, 0x1

    .line 306
    .line 307
    goto :goto_4

    .line 308
    :cond_c
    if-eqz p0, :cond_d

    .line 309
    .line 310
    invoke-static {v4, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    invoke-interface {v0, p0}, Lhy0/c;->call([Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object p0

    .line 318
    goto :goto_7

    .line 319
    :cond_d
    new-instance p0, Lbx/b;

    .line 320
    .line 321
    invoke-interface {v0}, Lhy0/c;->getParameters()Ljava/util/List;

    .line 322
    .line 323
    .line 324
    move-result-object p1

    .line 325
    invoke-direct {p0, p1, v4}, Lbx/b;-><init>(Ljava/util/List;[Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    invoke-interface {v0, p0}, Lhy0/c;->callBy(Ljava/util/Map;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    :goto_7
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 333
    .line 334
    .line 335
    move-result p1

    .line 336
    :goto_8
    if-ge v1, p1, :cond_f

    .line 337
    .line 338
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v0

    .line 342
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 343
    .line 344
    .line 345
    check-cast v0, Lbx/a;

    .line 346
    .line 347
    aget-object v3, v4, v1

    .line 348
    .line 349
    if-eq v3, v7, :cond_e

    .line 350
    .line 351
    iget-object v0, v0, Lbx/a;->c:Lhy0/w;

    .line 352
    .line 353
    check-cast v0, Lhy0/l;

    .line 354
    .line 355
    invoke-interface {v0, p0, v3}, Lhy0/l;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    :cond_e
    add-int/lit8 v1, v1, 0x1

    .line 359
    .line 360
    goto :goto_8

    .line 361
    :cond_f
    return-object p0
.end method

.method public final e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    .locals 2

    .line 1
    const-string v0, "writer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p2, :cond_2

    .line 7
    .line 8
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->b()Lcom/squareup/moshi/JsonWriter;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lbx/c;->b:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lbx/a;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    iget-object v1, v0, Lbx/a;->a:Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {p1, v1}, Lcom/squareup/moshi/JsonWriter;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 34
    .line 35
    .line 36
    iget-object v1, v0, Lbx/a;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 37
    .line 38
    iget-object v0, v0, Lbx/a;->c:Lhy0/w;

    .line 39
    .line 40
    invoke-interface {v0, p2}, Lhy0/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v1, p1, v0}, Lcom/squareup/moshi/JsonAdapter;->e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->g()Lcom/squareup/moshi/JsonWriter;

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 53
    .line 54
    const-string p1, "value == null"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "KotlinJsonAdapter("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lbx/c;->a:Lhy0/g;

    .line 9
    .line 10
    invoke-interface {p0}, Lhy0/c;->getReturnType()Lhy0/a0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const/16 p0, 0x29

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
