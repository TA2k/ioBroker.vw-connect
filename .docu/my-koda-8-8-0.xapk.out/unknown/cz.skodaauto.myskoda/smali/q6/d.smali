.class public final Lq6/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/u0;


# static fields
.field public static final a:Lq6/d;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lq6/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lq6/d;->a:Lq6/d;

    .line 7
    .line 8
    return-void
.end method

.method public static d(Lb3/g;Ljava/util/List;Lay0/a;I)Lq6/c;
    .locals 4

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p0, v1

    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 12
    .line 13
    :cond_1
    sget-object p3, Lvy0/p0;->a:Lcz0/e;

    .line 14
    .line 15
    sget-object p3, Lcz0/d;->e:Lcz0/d;

    .line 16
    .line 17
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {p3, v0}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 22
    .line 23
    .line 24
    move-result-object p3

    .line 25
    invoke-static {p3}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    new-instance v0, Lm6/b0;

    .line 30
    .line 31
    new-instance v2, La7/j;

    .line 32
    .line 33
    const/16 v3, 0x12

    .line 34
    .line 35
    invoke-direct {v2, p2, v3}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    sget-object p2, Lm6/a0;->f:Lm6/a0;

    .line 39
    .line 40
    sget-object v3, Lq6/d;->a:Lq6/d;

    .line 41
    .line 42
    invoke-direct {v0, v3, p2, v2}, Lm6/b0;-><init>(Lm6/u0;Lay0/k;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    new-instance p2, Lq6/c;

    .line 46
    .line 47
    if-eqz p0, :cond_2

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    new-instance p0, La61/a;

    .line 51
    .line 52
    const/16 v2, 0xa

    .line 53
    .line 54
    invoke-direct {p0, v2}, La61/a;-><init>(I)V

    .line 55
    .line 56
    .line 57
    :goto_0
    new-instance v2, Lk31/t;

    .line 58
    .line 59
    const/16 v3, 0x13

    .line 60
    .line 61
    invoke-direct {v2, p1, v1, v3}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 62
    .line 63
    .line 64
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    new-instance v1, Lm6/w;

    .line 69
    .line 70
    invoke-direct {v1, v0, p1, p0, p3}, Lm6/w;-><init>(Lm6/b0;Ljava/util/List;Lm6/c;Lvy0/b0;)V

    .line 71
    .line 72
    .line 73
    invoke-direct {p2, v1}, Lq6/c;-><init>(Lm6/g;)V

    .line 74
    .line 75
    .line 76
    new-instance p0, Lq6/c;

    .line 77
    .line 78
    invoke-direct {p0, p2}, Lq6/c;-><init>(Lm6/g;)V

    .line 79
    .line 80
    .line 81
    return-object p0
.end method


# virtual methods
.method public a()Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance p0, Lq6/b;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {p0, v0}, Lq6/b;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public b(Ljava/io/FileInputStream;)Ljava/lang/Object;
    .locals 6

    .line 1
    :try_start_0
    invoke-static {p1}, Lp6/e;->o(Ljava/io/FileInputStream;)Lp6/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Landroidx/datastore/preferences/protobuf/c0; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    const/4 p1, 0x0

    .line 6
    new-array v0, p1, [Lq6/f;

    .line 7
    .line 8
    new-instance v1, Lq6/b;

    .line 9
    .line 10
    invoke-direct {v1, p1}, Lq6/b;-><init>(Z)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, [Lq6/f;

    .line 18
    .line 19
    const-string v2, "pairs"

    .line 20
    .line 21
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1}, Lq6/b;->b()V

    .line 25
    .line 26
    .line 27
    array-length v2, v0

    .line 28
    const/4 v3, 0x0

    .line 29
    if-gtz v2, :cond_3

    .line 30
    .line 31
    invoke-virtual {p0}, Lp6/e;->m()Ljava/util/Map;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    const-string p1, "preferencesProto.preferencesMap"

    .line 36
    .line 37
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

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
    move-result p1

    .line 52
    if-eqz p1, :cond_2

    .line 53
    .line 54
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    check-cast p1, Ljava/util/Map$Entry;

    .line 59
    .line 60
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Ljava/lang/String;

    .line 65
    .line 66
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    check-cast p1, Lp6/i;

    .line 71
    .line 72
    const-string v2, "name"

    .line 73
    .line 74
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v2, "value"

    .line 78
    .line 79
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1}, Lp6/i;->C()I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-nez v2, :cond_0

    .line 87
    .line 88
    const/4 v2, -0x1

    .line 89
    goto :goto_1

    .line 90
    :cond_0
    sget-object v4, Lq6/g;->a:[I

    .line 91
    .line 92
    invoke-static {v2}, Lu/w;->o(I)I

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    aget v2, v4, v2

    .line 97
    .line 98
    :goto_1
    packed-switch v2, :pswitch_data_0

    .line 99
    .line 100
    .line 101
    :pswitch_0
    new-instance p0, La8/r0;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :pswitch_1
    new-instance p0, Lm6/b;

    .line 108
    .line 109
    const-string p1, "Value not set."

    .line 110
    .line 111
    invoke-direct {p0, p1, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :pswitch_2
    new-instance v2, Lq6/e;

    .line 116
    .line 117
    invoke-direct {v2, v0}, Lq6/e;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1}, Lp6/i;->u()Landroidx/datastore/preferences/protobuf/h;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/h;->size()I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    if-nez v0, :cond_1

    .line 129
    .line 130
    sget-object p1, Landroidx/datastore/preferences/protobuf/a0;->b:[B

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_1
    new-array v4, v0, [B

    .line 134
    .line 135
    invoke-virtual {p1, v0, v4}, Landroidx/datastore/preferences/protobuf/h;->i(I[B)V

    .line 136
    .line 137
    .line 138
    move-object p1, v4

    .line 139
    :goto_2
    const-string v0, "value.bytes.toByteArray()"

    .line 140
    .line 141
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v1, v2, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_0

    .line 148
    :pswitch_3
    invoke-static {v0}, Ljp/ne;->c(Ljava/lang/String;)Lq6/e;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    invoke-virtual {p1}, Lp6/i;->B()Lp6/g;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    invoke-virtual {p1}, Lp6/g;->n()Landroidx/datastore/preferences/protobuf/z;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    const-string v2, "value.stringSet.stringsList"

    .line 161
    .line 162
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-static {p1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-virtual {v1, v0, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    goto :goto_0

    .line 173
    :pswitch_4
    invoke-static {v0}, Ljp/ne;->b(Ljava/lang/String;)Lq6/e;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    invoke-virtual {p1}, Lp6/i;->A()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    const-string v2, "value.string"

    .line 182
    .line 183
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v1, v0, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    goto/16 :goto_0

    .line 190
    .line 191
    :pswitch_5
    new-instance v2, Lq6/e;

    .line 192
    .line 193
    invoke-direct {v2, v0}, Lq6/e;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p1}, Lp6/i;->z()J

    .line 197
    .line 198
    .line 199
    move-result-wide v4

    .line 200
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    invoke-virtual {v1, v2, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    goto/16 :goto_0

    .line 208
    .line 209
    :pswitch_6
    new-instance v2, Lq6/e;

    .line 210
    .line 211
    invoke-direct {v2, v0}, Lq6/e;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p1}, Lp6/i;->y()I

    .line 215
    .line 216
    .line 217
    move-result p1

    .line 218
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 219
    .line 220
    .line 221
    move-result-object p1

    .line 222
    invoke-virtual {v1, v2, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    goto/16 :goto_0

    .line 226
    .line 227
    :pswitch_7
    new-instance v2, Lq6/e;

    .line 228
    .line 229
    invoke-direct {v2, v0}, Lq6/e;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {p1}, Lp6/i;->w()D

    .line 233
    .line 234
    .line 235
    move-result-wide v4

    .line 236
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    invoke-virtual {v1, v2, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    goto/16 :goto_0

    .line 244
    .line 245
    :pswitch_8
    new-instance v2, Lq6/e;

    .line 246
    .line 247
    invoke-direct {v2, v0}, Lq6/e;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {p1}, Lp6/i;->x()F

    .line 251
    .line 252
    .line 253
    move-result p1

    .line 254
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    invoke-virtual {v1, v2, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 259
    .line 260
    .line 261
    goto/16 :goto_0

    .line 262
    .line 263
    :pswitch_9
    invoke-static {v0}, Ljp/ne;->a(Ljava/lang/String;)Lq6/e;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    invoke-virtual {p1}, Lp6/i;->t()Z

    .line 268
    .line 269
    .line 270
    move-result p1

    .line 271
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 272
    .line 273
    .line 274
    move-result-object p1

    .line 275
    invoke-virtual {v1, v0, p1}, Lq6/b;->f(Lq6/e;Ljava/lang/Object;)V

    .line 276
    .line 277
    .line 278
    goto/16 :goto_0

    .line 279
    .line 280
    :pswitch_a
    new-instance p0, Lm6/b;

    .line 281
    .line 282
    const-string p1, "Value case is null."

    .line 283
    .line 284
    invoke-direct {p0, p1, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 285
    .line 286
    .line 287
    throw p0

    .line 288
    :cond_2
    invoke-virtual {v1}, Lq6/b;->h()Lq6/b;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    return-object p0

    .line 293
    :cond_3
    aget-object p0, v0, p1

    .line 294
    .line 295
    throw v3

    .line 296
    :catch_0
    move-exception p0

    .line 297
    new-instance p1, Lm6/b;

    .line 298
    .line 299
    const-string v0, "Unable to parse preferences proto."

    .line 300
    .line 301
    invoke-direct {p1, v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 302
    .line 303
    .line 304
    throw p1

    .line 305
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_a
        :pswitch_0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public c(Ljava/lang/Object;Lm6/b1;)V
    .locals 5

    .line 1
    check-cast p1, Lq6/b;

    .line 2
    .line 3
    invoke-virtual {p1}, Lq6/b;->a()Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {}, Lp6/e;->n()Lp6/c;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_8

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Ljava/util/Map$Entry;

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lq6/e;

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iget-object v1, v1, Lq6/e;->a:Ljava/lang/String;

    .line 42
    .line 43
    instance-of v2, v0, Ljava/lang/Boolean;

    .line 44
    .line 45
    if-eqz v2, :cond_0

    .line 46
    .line 47
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    check-cast v0, Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 58
    .line 59
    .line 60
    iget-object v3, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 61
    .line 62
    check-cast v3, Lp6/i;

    .line 63
    .line 64
    invoke-static {v3, v0}, Lp6/i;->q(Lp6/i;Z)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    check-cast v0, Lp6/i;

    .line 72
    .line 73
    goto/16 :goto_1

    .line 74
    .line 75
    :cond_0
    instance-of v2, v0, Ljava/lang/Float;

    .line 76
    .line 77
    if-eqz v2, :cond_1

    .line 78
    .line 79
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    check-cast v0, Ljava/lang/Number;

    .line 84
    .line 85
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 90
    .line 91
    .line 92
    iget-object v3, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 93
    .line 94
    check-cast v3, Lp6/i;

    .line 95
    .line 96
    invoke-static {v3, v0}, Lp6/i;->r(Lp6/i;F)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    check-cast v0, Lp6/i;

    .line 104
    .line 105
    goto/16 :goto_1

    .line 106
    .line 107
    :cond_1
    instance-of v2, v0, Ljava/lang/Double;

    .line 108
    .line 109
    if-eqz v2, :cond_2

    .line 110
    .line 111
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    check-cast v0, Ljava/lang/Number;

    .line 116
    .line 117
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 118
    .line 119
    .line 120
    move-result-wide v3

    .line 121
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 122
    .line 123
    .line 124
    iget-object v0, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 125
    .line 126
    check-cast v0, Lp6/i;

    .line 127
    .line 128
    invoke-static {v0, v3, v4}, Lp6/i;->o(Lp6/i;D)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    check-cast v0, Lp6/i;

    .line 136
    .line 137
    goto/16 :goto_1

    .line 138
    .line 139
    :cond_2
    instance-of v2, v0, Ljava/lang/Integer;

    .line 140
    .line 141
    if-eqz v2, :cond_3

    .line 142
    .line 143
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    check-cast v0, Ljava/lang/Number;

    .line 148
    .line 149
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 154
    .line 155
    .line 156
    iget-object v3, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 157
    .line 158
    check-cast v3, Lp6/i;

    .line 159
    .line 160
    invoke-static {v3, v0}, Lp6/i;->s(Lp6/i;I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    check-cast v0, Lp6/i;

    .line 168
    .line 169
    goto/16 :goto_1

    .line 170
    .line 171
    :cond_3
    instance-of v2, v0, Ljava/lang/Long;

    .line 172
    .line 173
    if-eqz v2, :cond_4

    .line 174
    .line 175
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    check-cast v0, Ljava/lang/Number;

    .line 180
    .line 181
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 182
    .line 183
    .line 184
    move-result-wide v3

    .line 185
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 186
    .line 187
    .line 188
    iget-object v0, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 189
    .line 190
    check-cast v0, Lp6/i;

    .line 191
    .line 192
    invoke-static {v0, v3, v4}, Lp6/i;->l(Lp6/i;J)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    check-cast v0, Lp6/i;

    .line 200
    .line 201
    goto :goto_1

    .line 202
    :cond_4
    instance-of v2, v0, Ljava/lang/String;

    .line 203
    .line 204
    if-eqz v2, :cond_5

    .line 205
    .line 206
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    check-cast v0, Ljava/lang/String;

    .line 211
    .line 212
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 213
    .line 214
    .line 215
    iget-object v3, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 216
    .line 217
    check-cast v3, Lp6/i;

    .line 218
    .line 219
    invoke-static {v3, v0}, Lp6/i;->m(Lp6/i;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    check-cast v0, Lp6/i;

    .line 227
    .line 228
    goto :goto_1

    .line 229
    :cond_5
    instance-of v2, v0, Ljava/util/Set;

    .line 230
    .line 231
    if-eqz v2, :cond_6

    .line 232
    .line 233
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    invoke-static {}, Lp6/g;->o()Lp6/f;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    check-cast v0, Ljava/util/Set;

    .line 242
    .line 243
    check-cast v0, Ljava/lang/Iterable;

    .line 244
    .line 245
    invoke-virtual {v3}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 246
    .line 247
    .line 248
    iget-object v4, v3, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 249
    .line 250
    check-cast v4, Lp6/g;

    .line 251
    .line 252
    invoke-static {v4, v0}, Lp6/g;->l(Lp6/g;Ljava/lang/Iterable;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 256
    .line 257
    .line 258
    iget-object v0, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 259
    .line 260
    check-cast v0, Lp6/i;

    .line 261
    .line 262
    invoke-virtual {v3}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    check-cast v3, Lp6/g;

    .line 267
    .line 268
    invoke-static {v0, v3}, Lp6/i;->n(Lp6/i;Lp6/g;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    check-cast v0, Lp6/i;

    .line 276
    .line 277
    goto :goto_1

    .line 278
    :cond_6
    instance-of v2, v0, [B

    .line 279
    .line 280
    if-eqz v2, :cond_7

    .line 281
    .line 282
    invoke-static {}, Lp6/i;->D()Lp6/h;

    .line 283
    .line 284
    .line 285
    move-result-object v2

    .line 286
    check-cast v0, [B

    .line 287
    .line 288
    const/4 v3, 0x0

    .line 289
    array-length v4, v0

    .line 290
    invoke-static {v0, v3, v4}, Landroidx/datastore/preferences/protobuf/h;->g([BII)Landroidx/datastore/preferences/protobuf/h;

    .line 291
    .line 292
    .line 293
    move-result-object v0

    .line 294
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 295
    .line 296
    .line 297
    iget-object v3, v2, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 298
    .line 299
    check-cast v3, Lp6/i;

    .line 300
    .line 301
    invoke-static {v3, v0}, Lp6/i;->p(Lp6/i;Landroidx/datastore/preferences/protobuf/h;)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v2}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    check-cast v0, Lp6/i;

    .line 309
    .line 310
    :goto_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 311
    .line 312
    .line 313
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 314
    .line 315
    .line 316
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/v;->c()V

    .line 317
    .line 318
    .line 319
    iget-object v2, p1, Landroidx/datastore/preferences/protobuf/v;->e:Landroidx/datastore/preferences/protobuf/x;

    .line 320
    .line 321
    check-cast v2, Lp6/e;

    .line 322
    .line 323
    invoke-static {v2}, Lp6/e;->l(Lp6/e;)Landroidx/datastore/preferences/protobuf/m0;

    .line 324
    .line 325
    .line 326
    move-result-object v2

    .line 327
    invoke-virtual {v2, v1, v0}, Landroidx/datastore/preferences/protobuf/m0;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    goto/16 :goto_0

    .line 331
    .line 332
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 333
    .line 334
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 335
    .line 336
    .line 337
    move-result-object p1

    .line 338
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object p1

    .line 342
    const-string p2, "PreferencesSerializer does not support type: "

    .line 343
    .line 344
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 345
    .line 346
    .line 347
    move-result-object p1

    .line 348
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    throw p0

    .line 352
    :cond_8
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/v;->a()Landroidx/datastore/preferences/protobuf/x;

    .line 353
    .line 354
    .line 355
    move-result-object p0

    .line 356
    check-cast p0, Lp6/e;

    .line 357
    .line 358
    const/4 p1, 0x0

    .line 359
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 360
    .line 361
    .line 362
    move-result p1

    .line 363
    sget-object v0, Landroidx/datastore/preferences/protobuf/l;->f:Ljava/util/logging/Logger;

    .line 364
    .line 365
    const/16 v0, 0x1000

    .line 366
    .line 367
    if-le p1, v0, :cond_9

    .line 368
    .line 369
    move p1, v0

    .line 370
    :cond_9
    new-instance v0, Landroidx/datastore/preferences/protobuf/l;

    .line 371
    .line 372
    invoke-direct {v0, p2, p1}, Landroidx/datastore/preferences/protobuf/l;-><init>(Lm6/b1;I)V

    .line 373
    .line 374
    .line 375
    invoke-virtual {p0, v0}, Landroidx/datastore/preferences/protobuf/x;->b(Landroidx/datastore/preferences/protobuf/l;)V

    .line 376
    .line 377
    .line 378
    iget p0, v0, Landroidx/datastore/preferences/protobuf/l;->d:I

    .line 379
    .line 380
    if-lez p0, :cond_a

    .line 381
    .line 382
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/l;->s()V

    .line 383
    .line 384
    .line 385
    :cond_a
    return-void
.end method
