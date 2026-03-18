.class public abstract Lvo/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Landroid/content/Context;

.field public static b:Ljava/lang/Boolean;


# direct methods
.method public static final a(Ljava/time/OffsetDateTime;)J
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {v0, p0}, Ljava/time/Duration;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)Ljava/time/Duration;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "between(...)"

    .line 15
    .line 16
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/time/Duration;->getSeconds()J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 24
    .line 25
    invoke-static {v0, v1, v2}, Lmy0/h;->t(JLmy0/e;)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    invoke-virtual {p0}, Ljava/time/Duration;->getNano()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    sget-object v2, Lmy0/e;->e:Lmy0/e;

    .line 34
    .line 35
    invoke-static {p0, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 36
    .line 37
    .line 38
    move-result-wide v2

    .line 39
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->k(JJ)J

    .line 40
    .line 41
    .line 42
    move-result-wide v0

    .line 43
    return-wide v0
.end method

.method public static final b(Ljava/util/List;)Llz0/n;
    .locals 3

    .line 1
    new-instance v0, Llz0/n;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    invoke-direct {v0, v1, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    invoke-interface {p0, v2}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    :goto_0
    invoke-interface {p0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Llz0/n;

    .line 33
    .line 34
    invoke-static {v2, v0}, Lvo/a;->c(Llz0/n;Llz0/n;)Llz0/n;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-static {v0, v1}, Lvo/a;->d(Llz0/n;Ljava/util/List;)Llz0/n;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method

.method public static final c(Llz0/n;Llz0/n;)Llz0/n;
    .locals 3

    .line 1
    iget-object v0, p0, Llz0/n;->b:Ljava/util/List;

    .line 2
    .line 3
    iget-object v1, p0, Llz0/n;->a:Ljava/util/List;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    new-instance p0, Llz0/n;

    .line 12
    .line 13
    check-cast v1, Ljava/util/Collection;

    .line 14
    .line 15
    iget-object v0, p1, Llz0/n;->a:Ljava/util/List;

    .line 16
    .line 17
    check-cast v0, Ljava/lang/Iterable;

    .line 18
    .line 19
    invoke-static {v0, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget-object p1, p1, Llz0/n;->b:Ljava/util/List;

    .line 24
    .line 25
    invoke-direct {p0, v0, p1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    iget-object p0, p0, Llz0/n;->b:Ljava/util/List;

    .line 30
    .line 31
    check-cast p0, Ljava/lang/Iterable;

    .line 32
    .line 33
    new-instance v0, Ljava/util/ArrayList;

    .line 34
    .line 35
    const/16 v2, 0xa

    .line 36
    .line 37
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_1

    .line 53
    .line 54
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Llz0/n;

    .line 59
    .line 60
    invoke-static {v2, p1}, Lvo/a;->c(Llz0/n;Llz0/n;)Llz0/n;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    new-instance p0, Llz0/n;

    .line 69
    .line 70
    invoke-direct {p0, v1, v0}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 71
    .line 72
    .line 73
    return-object p0
.end method

.method public static final d(Llz0/n;Ljava/util/List;)Llz0/n;
    .locals 8

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/Collection;

    .line 7
    .line 8
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iget-object v1, p0, Llz0/n;->a:Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const/4 v2, 0x0

    .line 19
    move-object v3, v2

    .line 20
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_4

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    check-cast v4, Llz0/m;

    .line 31
    .line 32
    instance-of v5, v4, Llz0/g;

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    if-eqz v3, :cond_0

    .line 37
    .line 38
    check-cast v4, Llz0/g;

    .line 39
    .line 40
    iget-object v4, v4, Llz0/g;->a:Ljava/util/List;

    .line 41
    .line 42
    check-cast v4, Ljava/util/Collection;

    .line 43
    .line 44
    invoke-interface {v3, v4}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    check-cast v4, Llz0/g;

    .line 49
    .line 50
    iget-object v3, v4, Llz0/g;->a:Ljava/util/List;

    .line 51
    .line 52
    check-cast v3, Ljava/util/Collection;

    .line 53
    .line 54
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    goto :goto_0

    .line 59
    :cond_1
    instance-of v5, v4, Llz0/t;

    .line 60
    .line 61
    if-eqz v5, :cond_2

    .line 62
    .line 63
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    if-eqz v3, :cond_3

    .line 68
    .line 69
    new-instance v5, Llz0/g;

    .line 70
    .line 71
    invoke-direct {v5, v3}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-object v3, v2

    .line 78
    :cond_3
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_4
    iget-object p0, p0, Llz0/n;->b:Ljava/util/List;

    .line 83
    .line 84
    check-cast p0, Ljava/lang/Iterable;

    .line 85
    .line 86
    new-instance v1, Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 89
    .line 90
    .line 91
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_7

    .line 100
    .line 101
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Llz0/n;

    .line 106
    .line 107
    invoke-static {v2, p1}, Lvo/a;->d(Llz0/n;Ljava/util/List;)Llz0/n;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    iget-object v4, v2, Llz0/n;->a:Ljava/util/List;

    .line 112
    .line 113
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-eqz v4, :cond_6

    .line 118
    .line 119
    iget-object v4, v2, Llz0/n;->b:Ljava/util/List;

    .line 120
    .line 121
    check-cast v4, Ljava/util/Collection;

    .line 122
    .line 123
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    if-eqz v5, :cond_5

    .line 128
    .line 129
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    :cond_5
    check-cast v4, Ljava/util/List;

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_6
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    :goto_2
    check-cast v4, Ljava/lang/Iterable;

    .line 141
    .line 142
    invoke-static {v4, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_7
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    if-eqz p0, :cond_8

    .line 151
    .line 152
    new-instance p0, Llz0/n;

    .line 153
    .line 154
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 155
    .line 156
    invoke-direct {p0, p1, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 157
    .line 158
    .line 159
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    :cond_8
    check-cast v1, Ljava/util/List;

    .line 164
    .line 165
    if-nez v3, :cond_9

    .line 166
    .line 167
    new-instance p0, Llz0/n;

    .line 168
    .line 169
    invoke-direct {p0, v0, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 170
    .line 171
    .line 172
    return-object p0

    .line 173
    :cond_9
    move-object p0, v1

    .line 174
    check-cast p0, Ljava/lang/Iterable;

    .line 175
    .line 176
    instance-of p1, p0, Ljava/util/Collection;

    .line 177
    .line 178
    if-eqz p1, :cond_a

    .line 179
    .line 180
    move-object p1, p0

    .line 181
    check-cast p1, Ljava/util/Collection;

    .line 182
    .line 183
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 184
    .line 185
    .line 186
    move-result p1

    .line 187
    if-eqz p1, :cond_a

    .line 188
    .line 189
    goto/16 :goto_5

    .line 190
    .line 191
    :cond_a
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    :cond_b
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    if-eqz v2, :cond_f

    .line 200
    .line 201
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    check-cast v2, Llz0/n;

    .line 206
    .line 207
    iget-object v2, v2, Llz0/n;->a:Ljava/util/List;

    .line 208
    .line 209
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v2

    .line 213
    check-cast v2, Llz0/m;

    .line 214
    .line 215
    if-eqz v2, :cond_b

    .line 216
    .line 217
    instance-of v2, v2, Llz0/g;

    .line 218
    .line 219
    const/4 v4, 0x1

    .line 220
    if-ne v2, v4, :cond_b

    .line 221
    .line 222
    new-instance p1, Ljava/util/ArrayList;

    .line 223
    .line 224
    const/16 v1, 0xa

    .line 225
    .line 226
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 227
    .line 228
    .line 229
    move-result v1

    .line 230
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 231
    .line 232
    .line 233
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    if-eqz v1, :cond_e

    .line 242
    .line 243
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    check-cast v1, Llz0/n;

    .line 248
    .line 249
    iget-object v2, v1, Llz0/n;->a:Ljava/util/List;

    .line 250
    .line 251
    iget-object v1, v1, Llz0/n;->b:Ljava/util/List;

    .line 252
    .line 253
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v5

    .line 257
    check-cast v5, Llz0/m;

    .line 258
    .line 259
    instance-of v6, v5, Llz0/g;

    .line 260
    .line 261
    if-eqz v6, :cond_c

    .line 262
    .line 263
    new-instance v6, Llz0/n;

    .line 264
    .line 265
    new-instance v7, Llz0/g;

    .line 266
    .line 267
    check-cast v5, Llz0/g;

    .line 268
    .line 269
    iget-object v5, v5, Llz0/g;->a:Ljava/util/List;

    .line 270
    .line 271
    check-cast v5, Ljava/lang/Iterable;

    .line 272
    .line 273
    invoke-static {v5, v3}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    invoke-direct {v7, v5}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 278
    .line 279
    .line 280
    invoke-static {v7}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 281
    .line 282
    .line 283
    move-result-object v5

    .line 284
    check-cast v5, Ljava/util/Collection;

    .line 285
    .line 286
    check-cast v2, Ljava/lang/Iterable;

    .line 287
    .line 288
    invoke-static {v2, v4}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    check-cast v2, Ljava/lang/Iterable;

    .line 293
    .line 294
    invoke-static {v2, v5}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    invoke-direct {v6, v2, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 299
    .line 300
    .line 301
    goto :goto_4

    .line 302
    :cond_c
    if-nez v5, :cond_d

    .line 303
    .line 304
    new-instance v6, Llz0/n;

    .line 305
    .line 306
    new-instance v2, Llz0/g;

    .line 307
    .line 308
    invoke-direct {v2, v3}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 309
    .line 310
    .line 311
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 312
    .line 313
    .line 314
    move-result-object v2

    .line 315
    invoke-direct {v6, v2, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 316
    .line 317
    .line 318
    goto :goto_4

    .line 319
    :cond_d
    new-instance v6, Llz0/n;

    .line 320
    .line 321
    new-instance v5, Llz0/g;

    .line 322
    .line 323
    invoke-direct {v5, v3}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 324
    .line 325
    .line 326
    invoke-static {v5}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 327
    .line 328
    .line 329
    move-result-object v5

    .line 330
    check-cast v5, Ljava/util/Collection;

    .line 331
    .line 332
    check-cast v2, Ljava/lang/Iterable;

    .line 333
    .line 334
    invoke-static {v2, v5}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 335
    .line 336
    .line 337
    move-result-object v2

    .line 338
    invoke-direct {v6, v2, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 339
    .line 340
    .line 341
    :goto_4
    invoke-virtual {p1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    goto :goto_3

    .line 345
    :cond_e
    new-instance p0, Llz0/n;

    .line 346
    .line 347
    invoke-direct {p0, v0, p1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 348
    .line 349
    .line 350
    return-object p0

    .line 351
    :cond_f
    :goto_5
    new-instance p0, Llz0/g;

    .line 352
    .line 353
    invoke-direct {p0, v3}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    new-instance p0, Llz0/n;

    .line 360
    .line 361
    invoke-direct {p0, v0, v1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 362
    .line 363
    .line 364
    return-object p0
.end method

.method public static final e(Ljava/time/OffsetDateTime;)J
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {v0, p0}, Ljava/time/Duration;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)Ljava/time/Duration;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p0}, Ljava/time/Duration;->abs()Ljava/time/Duration;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v0, "abs(...)"

    .line 19
    .line 20
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/time/Duration;->getSeconds()J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 28
    .line 29
    invoke-static {v0, v1, v2}, Lmy0/h;->t(JLmy0/e;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v0

    .line 33
    invoke-virtual {p0}, Ljava/time/Duration;->getNano()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    sget-object v2, Lmy0/e;->e:Lmy0/e;

    .line 38
    .line 39
    invoke-static {p0, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 40
    .line 41
    .line 42
    move-result-wide v2

    .line 43
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->k(JJ)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    return-wide v0
.end method

.method public static declared-synchronized f(Landroid/content/Context;)Z
    .locals 3

    .line 1
    const-class v0, Lvo/a;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    sget-object v1, Lvo/a;->a:Landroid/content/Context;

    .line 9
    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    sget-object v2, Lvo/a;->b:Ljava/lang/Boolean;

    .line 13
    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    if-eq v1, p0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 20
    .line 21
    .line 22
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    monitor-exit v0

    .line 24
    return p0

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 28
    :try_start_1
    sput-object v1, Lvo/a;->b:Ljava/lang/Boolean;

    .line 29
    .line 30
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v1}, Landroid/content/pm/PackageManager;->isInstantApp()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    sput-object v1, Lvo/a;->b:Ljava/lang/Boolean;

    .line 43
    .line 44
    sput-object p0, Lvo/a;->a:Landroid/content/Context;

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 47
    .line 48
    .line 49
    move-result p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 50
    monitor-exit v0

    .line 51
    return p0

    .line 52
    :goto_1
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 53
    throw p0
.end method

.method public static g(Ljava/time/OffsetDateTime;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefault(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "<this>"

    .line 11
    .line 12
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v1, Ljava/time/format/FormatStyle;->MEDIUM:Ljava/time/format/FormatStyle;

    .line 16
    .line 17
    invoke-static {v1}, Ljava/time/format/DateTimeFormatter;->ofLocalizedDate(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1, v0}, Ljava/time/format/DateTimeFormatter;->withZone(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p0, v0}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string v0, "format(...)"

    .line 30
    .line 31
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-object p0
.end method

.method public static final h(Ljava/time/OffsetDateTime;Ljava/time/ZoneId;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/time/format/FormatStyle;->MEDIUM:Ljava/time/format/FormatStyle;

    .line 7
    .line 8
    sget-object v1, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 9
    .line 10
    invoke-static {v0, v1}, Ljava/time/format/DateTimeFormatter;->ofLocalizedDateTime(Ljava/time/format/FormatStyle;Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0, p1}, Ljava/time/format/DateTimeFormatter;->withZone(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string p1, "format(...)"

    .line 23
    .line 24
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method

.method public static synthetic i(Ljava/time/OffsetDateTime;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefault(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0, v0}, Lvo/a;->h(Ljava/time/OffsetDateTime;Ljava/time/ZoneId;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static j(Ljava/time/OffsetDateTime;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefault(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "<this>"

    .line 11
    .line 12
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v1, Ljava/time/format/FormatStyle;->MEDIUM:Ljava/time/format/FormatStyle;

    .line 16
    .line 17
    invoke-static {v1}, Ljava/time/format/DateTimeFormatter;->ofLocalizedDateTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1, v0}, Ljava/time/format/DateTimeFormatter;->withZone(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p0, v0}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string v0, "format(...)"

    .line 30
    .line 31
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-object p0
.end method

.method public static k(Ljava/time/OffsetDateTime;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefault(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "<this>"

    .line 11
    .line 12
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v1, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 16
    .line 17
    invoke-static {v1}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1, v0}, Ljava/time/format/DateTimeFormatter;->withZone(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p0, v0}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string v0, "format(...)"

    .line 30
    .line 31
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-object p0
.end method

.method public static final l(Ljava/time/OffsetDateTime;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/time/format/DateTimeFormatter;->ISO_OFFSET_DATE_TIME:Ljava/time/format/DateTimeFormatter;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "format(...)"

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    return-object p0
.end method

.method public static final m(Ljava/time/OffsetDateTime;)Ljava/time/OffsetDateTime;
    .locals 3

    .line 1
    sget-object v0, Ljava/time/temporal/ChronoField;->HOUR_OF_DAY:Ljava/time/temporal/ChronoField;

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    invoke-virtual {p0, v0, v1, v2}, Ljava/time/OffsetDateTime;->with(Ljava/time/temporal/TemporalField;J)Ljava/time/OffsetDateTime;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    sget-object v0, Ljava/time/temporal/ChronoField;->MINUTE_OF_HOUR:Ljava/time/temporal/ChronoField;

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1, v2}, Ljava/time/OffsetDateTime;->with(Ljava/time/temporal/TemporalField;J)Ljava/time/OffsetDateTime;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object v0, Ljava/time/temporal/ChronoField;->SECOND_OF_MINUTE:Ljava/time/temporal/ChronoField;

    .line 16
    .line 17
    invoke-virtual {p0, v0, v1, v2}, Ljava/time/OffsetDateTime;->with(Ljava/time/temporal/TemporalField;J)Ljava/time/OffsetDateTime;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sget-object v0, Ljava/time/temporal/ChronoField;->NANO_OF_SECOND:Ljava/time/temporal/ChronoField;

    .line 22
    .line 23
    invoke-virtual {p0, v0, v1, v2}, Ljava/time/OffsetDateTime;->with(Ljava/time/temporal/TemporalField;J)Ljava/time/OffsetDateTime;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const-string v0, "with(...)"

    .line 28
    .line 29
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-object p0
.end method
