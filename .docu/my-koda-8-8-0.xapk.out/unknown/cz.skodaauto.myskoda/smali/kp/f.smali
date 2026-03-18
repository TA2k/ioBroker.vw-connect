.class public final Lkp/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/e;


# static fields
.field public static final f:Ljava/nio/charset/Charset;

.field public static final g:Lzs/c;

.field public static final h:Lzs/c;

.field public static final i:Lkp/e;


# instance fields
.field public a:Ljava/io/OutputStream;

.field public final b:Ljava/util/HashMap;

.field public final c:Ljava/util/HashMap;

.field public final d:Lzs/d;

.field public final e:Lct/h;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-string v0, "UTF-8"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lkp/f;->f:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    new-instance v0, Lkp/a;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lkp/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    const-class v1, Lkp/d;

    .line 16
    .line 17
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v2, Lzs/c;

    .line 22
    .line 23
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const-string v3, "key"

    .line 28
    .line 29
    invoke-direct {v2, v3, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 30
    .line 31
    .line 32
    sput-object v2, Lkp/f;->g:Lzs/c;

    .line 33
    .line 34
    new-instance v0, Lkp/a;

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    invoke-direct {v0, v2}, Lkp/a;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1, v0}, Lia/b;->l(Ljava/lang/Class;Lkp/a;)Ljava/util/HashMap;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    new-instance v1, Lzs/c;

    .line 45
    .line 46
    invoke-static {v0}, Lp3/m;->u(Ljava/util/HashMap;)Ljava/util/Map;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    const-string v2, "value"

    .line 51
    .line 52
    invoke-direct {v1, v2, v0}, Lzs/c;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 53
    .line 54
    .line 55
    sput-object v1, Lkp/f;->h:Lzs/c;

    .line 56
    .line 57
    sget-object v0, Lkp/e;->b:Lkp/e;

    .line 58
    .line 59
    sput-object v0, Lkp/f;->i:Lkp/e;

    .line 60
    .line 61
    return-void
.end method

.method public constructor <init>(Ljava/io/ByteArrayOutputStream;Ljava/util/HashMap;Ljava/util/HashMap;Lzs/d;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lct/h;

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    invoke-direct {v0, p0, v1}, Lct/h;-><init>(Lzs/e;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lkp/f;->e:Lct/h;

    .line 11
    .line 12
    iput-object p1, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 13
    .line 14
    iput-object p2, p0, Lkp/f;->b:Ljava/util/HashMap;

    .line 15
    .line 16
    iput-object p3, p0, Lkp/f;->c:Ljava/util/HashMap;

    .line 17
    .line 18
    iput-object p4, p0, Lkp/f;->d:Lzs/d;

    .line 19
    .line 20
    return-void
.end method

.method public static i(Lzs/c;)I
    .locals 1

    .line 1
    const-class v0, Lkp/d;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkp/d;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    check-cast p0, Lkp/a;

    .line 12
    .line 13
    iget p0, p0, Lkp/a;->a:I

    .line 14
    .line 15
    return p0

    .line 16
    :cond_0
    new-instance p0, Lzs/b;

    .line 17
    .line 18
    const-string v0, "Field has no @Protobuf config"

    .line 19
    .line 20
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method


# virtual methods
.method public final a(Lzs/c;Ljava/lang/Object;)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lkp/f;->c(Lzs/c;Ljava/lang/Object;Z)V

    .line 3
    .line 4
    .line 5
    return-object p0
.end method

.method public final b(Lzs/c;DZ)V
    .locals 2

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    cmpl-double p4, p2, v0

    .line 6
    .line 7
    if-nez p4, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    invoke-static {p1}, Lkp/f;->i(Lzs/c;)I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    shl-int/lit8 p1, p1, 0x3

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 22
    .line 23
    const/16 p1, 0x8

    .line 24
    .line 25
    invoke-static {p1}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    sget-object p4, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 30
    .line 31
    invoke-virtual {p1, p4}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p1, p2, p3}, Ljava/nio/ByteBuffer;->putDouble(D)Ljava/nio/ByteBuffer;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->array()[B

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write([B)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final c(Lzs/c;Ljava/lang/Object;Z)V
    .locals 3

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    goto/16 :goto_2

    .line 4
    .line 5
    :cond_0
    instance-of v0, p2, Ljava/lang/CharSequence;

    .line 6
    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    check-cast p2, Ljava/lang/CharSequence;

    .line 10
    .line 11
    if-eqz p3, :cond_1

    .line 12
    .line 13
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 14
    .line 15
    .line 16
    move-result p3

    .line 17
    if-nez p3, :cond_1

    .line 18
    .line 19
    goto/16 :goto_2

    .line 20
    .line 21
    :cond_1
    invoke-static {p1}, Lkp/f;->i(Lzs/c;)I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    shl-int/lit8 p1, p1, 0x3

    .line 26
    .line 27
    or-int/lit8 p1, p1, 0x2

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    sget-object p2, Lkp/f;->f:Ljava/nio/charset/Charset;

    .line 37
    .line 38
    invoke-virtual {p1, p2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    array-length p2, p1

    .line 43
    invoke-virtual {p0, p2}, Lkp/f;->k(I)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write([B)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_2
    instance-of v0, p2, Ljava/util/Collection;

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    check-cast p2, Ljava/util/Collection;

    .line 58
    .line 59
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 64
    .line 65
    .line 66
    move-result p3

    .line 67
    if-eqz p3, :cond_c

    .line 68
    .line 69
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p3

    .line 73
    invoke-virtual {p0, p1, p3, v1}, Lkp/f;->c(Lzs/c;Ljava/lang/Object;Z)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    instance-of v0, p2, Ljava/util/Map;

    .line 78
    .line 79
    if-eqz v0, :cond_4

    .line 80
    .line 81
    check-cast p2, Ljava/util/Map;

    .line 82
    .line 83
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result p3

    .line 95
    if-eqz p3, :cond_c

    .line 96
    .line 97
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p3

    .line 101
    check-cast p3, Ljava/util/Map$Entry;

    .line 102
    .line 103
    sget-object v0, Lkp/f;->i:Lkp/e;

    .line 104
    .line 105
    invoke-virtual {p0, v0, p1, p3, v1}, Lkp/f;->j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_4
    instance-of v0, p2, Ljava/lang/Double;

    .line 110
    .line 111
    if-eqz v0, :cond_5

    .line 112
    .line 113
    check-cast p2, Ljava/lang/Double;

    .line 114
    .line 115
    invoke-virtual {p2}, Ljava/lang/Double;->doubleValue()D

    .line 116
    .line 117
    .line 118
    move-result-wide v0

    .line 119
    invoke-virtual {p0, p1, v0, v1, p3}, Lkp/f;->b(Lzs/c;DZ)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :cond_5
    instance-of v0, p2, Ljava/lang/Float;

    .line 124
    .line 125
    if-eqz v0, :cond_7

    .line 126
    .line 127
    check-cast p2, Ljava/lang/Float;

    .line 128
    .line 129
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 130
    .line 131
    .line 132
    move-result p2

    .line 133
    if-eqz p3, :cond_6

    .line 134
    .line 135
    const/4 p3, 0x0

    .line 136
    cmpl-float p3, p2, p3

    .line 137
    .line 138
    if-nez p3, :cond_6

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_6
    invoke-static {p1}, Lkp/f;->i(Lzs/c;)I

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    shl-int/lit8 p1, p1, 0x3

    .line 146
    .line 147
    or-int/lit8 p1, p1, 0x5

    .line 148
    .line 149
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 150
    .line 151
    .line 152
    iget-object p0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 153
    .line 154
    const/4 p1, 0x4

    .line 155
    invoke-static {p1}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    sget-object p3, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 160
    .line 161
    invoke-virtual {p1, p3}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    invoke-virtual {p1, p2}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->array()[B

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write([B)V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :cond_7
    instance-of v0, p2, Ljava/lang/Number;

    .line 178
    .line 179
    if-eqz v0, :cond_a

    .line 180
    .line 181
    check-cast p2, Ljava/lang/Number;

    .line 182
    .line 183
    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    .line 184
    .line 185
    .line 186
    move-result-wide v0

    .line 187
    if-eqz p3, :cond_8

    .line 188
    .line 189
    const-wide/16 p2, 0x0

    .line 190
    .line 191
    cmp-long p2, v0, p2

    .line 192
    .line 193
    if-eqz p2, :cond_c

    .line 194
    .line 195
    :cond_8
    const-class p2, Lkp/d;

    .line 196
    .line 197
    invoke-virtual {p1, p2}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    check-cast p1, Lkp/d;

    .line 202
    .line 203
    if-eqz p1, :cond_9

    .line 204
    .line 205
    check-cast p1, Lkp/a;

    .line 206
    .line 207
    iget p1, p1, Lkp/a;->a:I

    .line 208
    .line 209
    shl-int/lit8 p1, p1, 0x3

    .line 210
    .line 211
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p0, v0, v1}, Lkp/f;->l(J)V

    .line 215
    .line 216
    .line 217
    return-void

    .line 218
    :cond_9
    new-instance p0, Lzs/b;

    .line 219
    .line 220
    const-string p1, "Field has no @Protobuf config"

    .line 221
    .line 222
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    throw p0

    .line 226
    :cond_a
    instance-of v0, p2, Ljava/lang/Boolean;

    .line 227
    .line 228
    if-eqz v0, :cond_b

    .line 229
    .line 230
    check-cast p2, Ljava/lang/Boolean;

    .line 231
    .line 232
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 233
    .line 234
    .line 235
    move-result p2

    .line 236
    invoke-virtual {p0, p1, p2, p3}, Lkp/f;->h(Lzs/c;IZ)V

    .line 237
    .line 238
    .line 239
    return-void

    .line 240
    :cond_b
    instance-of v0, p2, [B

    .line 241
    .line 242
    if-eqz v0, :cond_e

    .line 243
    .line 244
    check-cast p2, [B

    .line 245
    .line 246
    if-eqz p3, :cond_d

    .line 247
    .line 248
    array-length p3, p2

    .line 249
    if-nez p3, :cond_d

    .line 250
    .line 251
    :cond_c
    :goto_2
    return-void

    .line 252
    :cond_d
    invoke-static {p1}, Lkp/f;->i(Lzs/c;)I

    .line 253
    .line 254
    .line 255
    move-result p1

    .line 256
    shl-int/lit8 p1, p1, 0x3

    .line 257
    .line 258
    or-int/lit8 p1, p1, 0x2

    .line 259
    .line 260
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 261
    .line 262
    .line 263
    array-length p1, p2

    .line 264
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 265
    .line 266
    .line 267
    iget-object p0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 268
    .line 269
    invoke-virtual {p0, p2}, Ljava/io/OutputStream;->write([B)V

    .line 270
    .line 271
    .line 272
    return-void

    .line 273
    :cond_e
    iget-object v0, p0, Lkp/f;->b:Ljava/util/HashMap;

    .line 274
    .line 275
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 276
    .line 277
    .line 278
    move-result-object v2

    .line 279
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    check-cast v0, Lzs/d;

    .line 284
    .line 285
    if-eqz v0, :cond_f

    .line 286
    .line 287
    invoke-virtual {p0, v0, p1, p2, p3}, Lkp/f;->j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 288
    .line 289
    .line 290
    return-void

    .line 291
    :cond_f
    iget-object v0, p0, Lkp/f;->c:Ljava/util/HashMap;

    .line 292
    .line 293
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 294
    .line 295
    .line 296
    move-result-object v2

    .line 297
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v0

    .line 301
    check-cast v0, Lzs/f;

    .line 302
    .line 303
    if-eqz v0, :cond_10

    .line 304
    .line 305
    iget-object p0, p0, Lkp/f;->e:Lct/h;

    .line 306
    .line 307
    iput-boolean v1, p0, Lct/h;->b:Z

    .line 308
    .line 309
    iput-object p1, p0, Lct/h;->d:Lzs/c;

    .line 310
    .line 311
    iput-boolean p3, p0, Lct/h;->c:Z

    .line 312
    .line 313
    invoke-interface {v0, p2, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    return-void

    .line 317
    :cond_10
    instance-of v0, p2, Lkp/b;

    .line 318
    .line 319
    const/4 v1, 0x1

    .line 320
    if-eqz v0, :cond_11

    .line 321
    .line 322
    check-cast p2, Lkp/b;

    .line 323
    .line 324
    invoke-interface {p2}, Lkp/b;->h()I

    .line 325
    .line 326
    .line 327
    move-result p2

    .line 328
    invoke-virtual {p0, p1, p2, v1}, Lkp/f;->h(Lzs/c;IZ)V

    .line 329
    .line 330
    .line 331
    return-void

    .line 332
    :cond_11
    instance-of v0, p2, Ljava/lang/Enum;

    .line 333
    .line 334
    if-eqz v0, :cond_12

    .line 335
    .line 336
    check-cast p2, Ljava/lang/Enum;

    .line 337
    .line 338
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 339
    .line 340
    .line 341
    move-result p2

    .line 342
    invoke-virtual {p0, p1, p2, v1}, Lkp/f;->h(Lzs/c;IZ)V

    .line 343
    .line 344
    .line 345
    return-void

    .line 346
    :cond_12
    iget-object v0, p0, Lkp/f;->d:Lzs/d;

    .line 347
    .line 348
    invoke-virtual {p0, v0, p1, p2, p3}, Lkp/f;->j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 349
    .line 350
    .line 351
    return-void
.end method

.method public final synthetic d(Lzs/c;Z)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lkp/f;->h(Lzs/c;IZ)V

    .line 3
    .line 4
    .line 5
    return-object p0
.end method

.method public final e(Lzs/c;D)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Lkp/f;->b(Lzs/c;DZ)V

    .line 3
    .line 4
    .line 5
    return-object p0
.end method

.method public final f(Lzs/c;J)Lzs/e;
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p2, v0

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    const-class v0, Lkp/d;

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lkp/d;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    check-cast p1, Lkp/a;

    .line 18
    .line 19
    iget p1, p1, Lkp/a;->a:I

    .line 20
    .line 21
    shl-int/lit8 p1, p1, 0x3

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p2, p3}, Lkp/f;->l(J)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_0
    new-instance p0, Lzs/b;

    .line 31
    .line 32
    const-string p1, "Field has no @Protobuf config"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    return-object p0
.end method

.method public final synthetic g(Lzs/c;I)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lkp/f;->h(Lzs/c;IZ)V

    .line 3
    .line 4
    .line 5
    return-object p0
.end method

.method public final h(Lzs/c;IZ)V
    .locals 0

    .line 1
    if-eqz p3, :cond_1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    return-void

    .line 7
    :cond_1
    :goto_0
    const-class p3, Lkp/d;

    .line 8
    .line 9
    invoke-virtual {p1, p3}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lkp/d;

    .line 14
    .line 15
    if-eqz p1, :cond_2

    .line 16
    .line 17
    check-cast p1, Lkp/a;

    .line 18
    .line 19
    iget p1, p1, Lkp/a;->a:I

    .line 20
    .line 21
    shl-int/lit8 p1, p1, 0x3

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lkp/f;->k(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p2}, Lkp/f;->k(I)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_2
    new-instance p0, Lzs/b;

    .line 31
    .line 32
    const-string p1, "Field has no @Protobuf config"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public final j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V
    .locals 7

    .line 1
    const-class v0, Ljava/lang/Throwable;

    .line 2
    .line 3
    new-instance v1, Lct/b;

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    invoke-direct {v1, v2}, Lct/b;-><init>(I)V

    .line 7
    .line 8
    .line 9
    const-wide/16 v3, 0x0

    .line 10
    .line 11
    iput-wide v3, v1, Lct/b;->e:J

    .line 12
    .line 13
    :try_start_0
    iget-object v5, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 14
    .line 15
    iput-object v1, p0, Lkp/f;->a:Ljava/io/OutputStream;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    :try_start_1
    invoke-interface {p1, p3, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 18
    .line 19
    .line 20
    :try_start_2
    iput-object v5, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 21
    .line 22
    iget-wide v5, v1, Lct/b;->e:J
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/io/OutputStream;->close()V

    .line 25
    .line 26
    .line 27
    if-eqz p4, :cond_0

    .line 28
    .line 29
    cmp-long p4, v5, v3

    .line 30
    .line 31
    if-nez p4, :cond_0

    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    invoke-static {p2}, Lkp/f;->i(Lzs/c;)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    shl-int/lit8 p2, p2, 0x3

    .line 39
    .line 40
    or-int/2addr p2, v2

    .line 41
    invoke-virtual {p0, p2}, Lkp/f;->k(I)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, v5, v6}, Lkp/f;->l(J)V

    .line 45
    .line 46
    .line 47
    invoke-interface {p1, p3, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    goto :goto_0

    .line 53
    :catchall_1
    move-exception p1

    .line 54
    :try_start_3
    iput-object v5, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 55
    .line 56
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 57
    :goto_0
    :try_start_4
    invoke-virtual {v1}, Ljava/io/OutputStream;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :catchall_2
    move-exception p1

    .line 62
    :try_start_5
    const-string p2, "addSuppressed"

    .line 63
    .line 64
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    move-result-object p3

    .line 68
    invoke-virtual {v0, p2, p3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-virtual {p2, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0

    .line 77
    .line 78
    .line 79
    :catch_0
    :goto_1
    throw p0
.end method

.method public final k(I)V
    .locals 4

    .line 1
    :goto_0
    and-int/lit8 v0, p1, -0x80

    .line 2
    .line 3
    int-to-long v0, v0

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmp-long v0, v0, v2

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 11
    .line 12
    and-int/lit8 v1, p1, 0x7f

    .line 13
    .line 14
    or-int/lit16 v1, v1, 0x80

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/io/OutputStream;->write(I)V

    .line 17
    .line 18
    .line 19
    ushr-int/lit8 p1, p1, 0x7

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object p0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 23
    .line 24
    and-int/lit8 p1, p1, 0x7f

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write(I)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final l(J)V
    .locals 4

    .line 1
    :goto_0
    const-wide/16 v0, -0x80

    .line 2
    .line 3
    and-long/2addr v0, p1

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmp-long v0, v0, v2

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 11
    .line 12
    long-to-int v1, p1

    .line 13
    and-int/lit8 v1, v1, 0x7f

    .line 14
    .line 15
    or-int/lit16 v1, v1, 0x80

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/io/OutputStream;->write(I)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x7

    .line 21
    ushr-long/2addr p1, v0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object p0, p0, Lkp/f;->a:Ljava/io/OutputStream;

    .line 24
    .line 25
    long-to-int p1, p1

    .line 26
    and-int/lit8 p1, p1, 0x7f

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write(I)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
