.class public final Lii/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhi/a;


# instance fields
.field public a:Z

.field public final b:Lnx0/f;

.field public final c:Lnx0/f;


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const-string v1, "Useless empty Lokator"

    .line 9
    .line 10
    if-nez v0, :cond_c

    .line 11
    .line 12
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 15
    .line 16
    .line 17
    check-cast p1, Ljava/lang/Iterable;

    .line 18
    .line 19
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const/4 v3, 0x0

    .line 24
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-eqz v4, :cond_4

    .line 29
    .line 30
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    check-cast v4, Lhi/b;

    .line 35
    .line 36
    iget-object v5, v4, Lhi/b;->a:Ljava/util/List;

    .line 37
    .line 38
    iget-object v6, v4, Lhi/b;->b:Ljava/util/Map;

    .line 39
    .line 40
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    add-int/2addr v5, v3

    .line 45
    invoke-interface {v6}, Ljava/util/Map;->size()I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    add-int/2addr v3, v5

    .line 50
    iget-object v4, v4, Lhi/b;->a:Ljava/util/List;

    .line 51
    .line 52
    check-cast v4, Ljava/lang/Iterable;

    .line 53
    .line 54
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    if-eqz v5, :cond_2

    .line 63
    .line 64
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    check-cast v5, Lii/b;

    .line 69
    .line 70
    iget-object v5, v5, Lii/b;->c:Lhy0/d;

    .line 71
    .line 72
    invoke-interface {v0, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    if-nez v7, :cond_1

    .line 77
    .line 78
    invoke-interface {v0, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_1
    invoke-static {p0, v0, v5}, Lii/a;->a(Lii/a;Ljava/util/LinkedHashSet;Lhy0/d;)Ljava/lang/IllegalArgumentException;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    throw p0

    .line 87
    :cond_2
    invoke-interface {v6}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_0

    .line 100
    .line 101
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    check-cast v5, Ljava/util/Map$Entry;

    .line 106
    .line 107
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    check-cast v5, Lhy0/d;

    .line 112
    .line 113
    invoke-interface {v0, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v6

    .line 117
    if-nez v6, :cond_3

    .line 118
    .line 119
    invoke-interface {v0, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_3
    invoke-static {p0, v0, v5}, Lii/a;->a(Lii/a;Ljava/util/LinkedHashSet;Lhy0/d;)Ljava/lang/IllegalArgumentException;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    throw p0

    .line 128
    :cond_4
    if-eqz v3, :cond_b

    .line 129
    .line 130
    new-instance v0, Lnx0/f;

    .line 131
    .line 132
    invoke-direct {v0}, Lnx0/f;-><init>()V

    .line 133
    .line 134
    .line 135
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-eqz v2, :cond_7

    .line 144
    .line 145
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, Lhi/b;

    .line 150
    .line 151
    iget-object v2, v2, Lhi/b;->a:Ljava/util/List;

    .line 152
    .line 153
    check-cast v2, Ljava/lang/Iterable;

    .line 154
    .line 155
    const/16 v3, 0xa

    .line 156
    .line 157
    invoke-static {v2, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    invoke-static {v3}, Lmx0/x;->k(I)I

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    const/16 v4, 0x10

    .line 166
    .line 167
    if-ge v3, v4, :cond_5

    .line 168
    .line 169
    move v3, v4

    .line 170
    :cond_5
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 171
    .line 172
    invoke-direct {v4, v3}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 173
    .line 174
    .line 175
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 180
    .line 181
    .line 182
    move-result v3

    .line 183
    if-eqz v3, :cond_6

    .line 184
    .line 185
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    move-object v5, v3

    .line 190
    check-cast v5, Lii/b;

    .line 191
    .line 192
    iget-object v5, v5, Lii/b;->c:Lhy0/d;

    .line 193
    .line 194
    invoke-interface {v4, v5, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    goto :goto_3

    .line 198
    :cond_6
    invoke-virtual {v0, v4}, Lnx0/f;->putAll(Ljava/util/Map;)V

    .line 199
    .line 200
    .line 201
    goto :goto_2

    .line 202
    :cond_7
    invoke-virtual {v0}, Lnx0/f;->b()Lnx0/f;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    iput-object v0, p0, Lii/a;->b:Lnx0/f;

    .line 207
    .line 208
    new-instance v0, Lnx0/f;

    .line 209
    .line 210
    invoke-direct {v0}, Lnx0/f;-><init>()V

    .line 211
    .line 212
    .line 213
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 218
    .line 219
    .line 220
    move-result v1

    .line 221
    if-eqz v1, :cond_8

    .line 222
    .line 223
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    check-cast v1, Lhi/b;

    .line 228
    .line 229
    iget-object v1, v1, Lhi/b;->b:Ljava/util/Map;

    .line 230
    .line 231
    invoke-virtual {v0, v1}, Lnx0/f;->putAll(Ljava/util/Map;)V

    .line 232
    .line 233
    .line 234
    goto :goto_4

    .line 235
    :cond_8
    invoke-virtual {v0}, Lnx0/f;->b()Lnx0/f;

    .line 236
    .line 237
    .line 238
    move-result-object p1

    .line 239
    iput-object p1, p0, Lii/a;->c:Lnx0/f;

    .line 240
    .line 241
    iget-object p1, p0, Lii/a;->b:Lnx0/f;

    .line 242
    .line 243
    invoke-virtual {p1}, Lnx0/f;->values()Ljava/util/Collection;

    .line 244
    .line 245
    .line 246
    move-result-object p1

    .line 247
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    :goto_5
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 252
    .line 253
    .line 254
    move-result v0

    .line 255
    if-eqz v0, :cond_a

    .line 256
    .line 257
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    check-cast v0, Lii/b;

    .line 262
    .line 263
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 264
    .line 265
    .line 266
    iget-boolean v1, v0, Lii/b;->a:Z

    .line 267
    .line 268
    if-eqz v1, :cond_9

    .line 269
    .line 270
    iget-object v1, v0, Lii/b;->b:Lay0/k;

    .line 271
    .line 272
    invoke-interface {v1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    new-instance v2, Llx0/f;

    .line 277
    .line 278
    invoke-direct {v2, v1}, Llx0/f;-><init>(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    goto :goto_6

    .line 282
    :cond_9
    new-instance v1, Li2/t;

    .line 283
    .line 284
    const/16 v2, 0x10

    .line 285
    .line 286
    invoke-direct {v1, v2, v0, p0}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 290
    .line 291
    .line 292
    move-result-object v2

    .line 293
    :goto_6
    iput-object v2, v0, Lii/b;->d:Ljava/lang/Object;

    .line 294
    .line 295
    goto :goto_5

    .line 296
    :cond_a
    return-void

    .line 297
    :cond_b
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 298
    .line 299
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    throw p0

    .line 303
    :cond_c
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 304
    .line 305
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    throw p0
.end method

.method public static final a(Lii/a;Ljava/util/LinkedHashSet;Lhy0/d;)Ljava/lang/IllegalArgumentException;
    .locals 4

    .line 1
    sget-object p0, Lgi/b;->h:Lgi/b;

    .line 2
    .line 3
    new-instance v0, Li40/j0;

    .line 4
    .line 5
    const/16 v1, 0xc

    .line 6
    .line 7
    invoke-direct {v0, v1, p1, p2}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sget-object p1, Lgi/a;->e:Lgi/a;

    .line 11
    .line 12
    const-class v1, Lii/a;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const/16 v2, 0x24

    .line 19
    .line 20
    invoke-static {v1, v2}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    const/16 v3, 0x2e

    .line 25
    .line 26
    invoke-static {v3, v2, v2}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-nez v3, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const-string v1, "Kt"

    .line 38
    .line 39
    invoke-static {v2, v1}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    :goto_0
    const/4 v2, 0x0

    .line 44
    invoke-static {v1, p1, p0, v2, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 45
    .line 46
    .line 47
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 48
    .line 49
    invoke-interface {p2}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    const-string p2, "Duplicated creator for "

    .line 54
    .line 55
    invoke-static {p2, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    return-object p0
.end method


# virtual methods
.method public final b(Lhy0/d;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "type"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lii/a;->a:Z

    .line 7
    .line 8
    if-nez v0, :cond_5

    .line 9
    .line 10
    iget-object v0, p0, Lii/a;->b:Lnx0/f;

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lii/b;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    iget-object v0, v0, Lii/b;->d:Ljava/lang/Object;

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    if-nez v0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move-object v1, v0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const-string p0, "lazy"

    .line 35
    .line 36
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v1

    .line 40
    :cond_2
    :goto_0
    iget-object v0, p0, Lii/a;->c:Lnx0/f;

    .line 41
    .line 42
    invoke-virtual {v0, p1}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Lay0/k;

    .line 47
    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    :cond_3
    :goto_1
    if-eqz v1, :cond_4

    .line 55
    .line 56
    return-object v1

    .line 57
    :cond_4
    new-instance p0, Ljava/lang/ClassNotFoundException;

    .line 58
    .line 59
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    const-string v0, "No single or factory registered for "

    .line 64
    .line 65
    invoke-static {v0, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    invoke-direct {p0, p1}, Ljava/lang/ClassNotFoundException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string p1, "This instance of the Lokator is closed."

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0
.end method
