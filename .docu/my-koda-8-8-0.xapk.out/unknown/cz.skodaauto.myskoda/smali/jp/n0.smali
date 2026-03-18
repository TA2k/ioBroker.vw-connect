.class public final Ljp/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/e;


# static fields
.field public static final f:Ljava/nio/charset/Charset;

.field public static final g:Lzs/c;

.field public static final h:Lzs/c;

.field public static final i:Ljp/m0;


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
    sput-object v0, Ljp/n0;->f:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    new-instance v0, Ljp/i0;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Ljp/i0;-><init>(I)V

    .line 13
    .line 14
    .line 15
    const-class v1, Ljp/l0;

    .line 16
    .line 17
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

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
    sput-object v2, Ljp/n0;->g:Lzs/c;

    .line 33
    .line 34
    new-instance v0, Ljp/i0;

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    invoke-direct {v0, v2}, Ljp/i0;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1, v0}, Lia/b;->k(Ljava/lang/Class;Ljp/i0;)Ljava/util/HashMap;

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
    sput-object v1, Ljp/n0;->h:Lzs/c;

    .line 56
    .line 57
    new-instance v0, Ljp/m0;

    .line 58
    .line 59
    const/4 v1, 0x0

    .line 60
    invoke-direct {v0, v1}, Ljp/m0;-><init>(I)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Ljp/n0;->i:Ljp/m0;

    .line 64
    .line 65
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
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, p0, v1}, Lct/h;-><init>(Lzs/e;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ljp/n0;->e:Lct/h;

    .line 11
    .line 12
    iput-object p1, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 13
    .line 14
    iput-object p2, p0, Ljp/n0;->b:Ljava/util/HashMap;

    .line 15
    .line 16
    iput-object p3, p0, Ljp/n0;->c:Ljava/util/HashMap;

    .line 17
    .line 18
    iput-object p4, p0, Ljp/n0;->d:Lzs/d;

    .line 19
    .line 20
    return-void
.end method

.method public static i(Lzs/c;)I
    .locals 1

    .line 1
    const-class v0, Ljp/l0;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljp/l0;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    check-cast p0, Ljp/i0;

    .line 12
    .line 13
    iget p0, p0, Ljp/i0;->a:I

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
    invoke-virtual {p0, p1, p2, v0}, Ljp/n0;->c(Lzs/c;Ljava/lang/Object;Z)V

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
    invoke-static {p1}, Ljp/n0;->i(Lzs/c;)I

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
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

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
    if-eqz p3, :cond_c

    .line 18
    .line 19
    :cond_1
    invoke-static {p1}, Ljp/n0;->i(Lzs/c;)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    shl-int/lit8 p1, p1, 0x3

    .line 24
    .line 25
    or-int/lit8 p1, p1, 0x2

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    sget-object p2, Ljp/n0;->f:Ljava/nio/charset/Charset;

    .line 35
    .line 36
    invoke-virtual {p1, p2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    array-length p2, p1

    .line 41
    invoke-virtual {p0, p2}, Ljp/n0;->k(I)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write([B)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    instance-of v0, p2, Ljava/util/Collection;

    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    check-cast p2, Ljava/util/Collection;

    .line 56
    .line 57
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 62
    .line 63
    .line 64
    move-result p3

    .line 65
    if-eqz p3, :cond_c

    .line 66
    .line 67
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p3

    .line 71
    invoke-virtual {p0, p1, p3, v1}, Ljp/n0;->c(Lzs/c;Ljava/lang/Object;Z)V

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    instance-of v0, p2, Ljava/util/Map;

    .line 76
    .line 77
    if-eqz v0, :cond_4

    .line 78
    .line 79
    check-cast p2, Ljava/util/Map;

    .line 80
    .line 81
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result p3

    .line 93
    if-eqz p3, :cond_c

    .line 94
    .line 95
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p3

    .line 99
    check-cast p3, Ljava/util/Map$Entry;

    .line 100
    .line 101
    sget-object v0, Ljp/n0;->i:Ljp/m0;

    .line 102
    .line 103
    invoke-virtual {p0, v0, p1, p3, v1}, Ljp/n0;->j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    instance-of v0, p2, Ljava/lang/Double;

    .line 108
    .line 109
    if-eqz v0, :cond_5

    .line 110
    .line 111
    check-cast p2, Ljava/lang/Double;

    .line 112
    .line 113
    invoke-virtual {p2}, Ljava/lang/Double;->doubleValue()D

    .line 114
    .line 115
    .line 116
    move-result-wide v0

    .line 117
    invoke-virtual {p0, p1, v0, v1, p3}, Ljp/n0;->b(Lzs/c;DZ)V

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :cond_5
    instance-of v0, p2, Ljava/lang/Float;

    .line 122
    .line 123
    if-eqz v0, :cond_7

    .line 124
    .line 125
    check-cast p2, Ljava/lang/Float;

    .line 126
    .line 127
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-eqz p3, :cond_6

    .line 132
    .line 133
    const/4 p3, 0x0

    .line 134
    cmpl-float p3, p2, p3

    .line 135
    .line 136
    if-nez p3, :cond_6

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_6
    invoke-static {p1}, Ljp/n0;->i(Lzs/c;)I

    .line 140
    .line 141
    .line 142
    move-result p1

    .line 143
    shl-int/lit8 p1, p1, 0x3

    .line 144
    .line 145
    or-int/lit8 p1, p1, 0x5

    .line 146
    .line 147
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 148
    .line 149
    .line 150
    iget-object p0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 151
    .line 152
    const/4 p1, 0x4

    .line 153
    invoke-static {p1}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    sget-object p3, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 158
    .line 159
    invoke-virtual {p1, p3}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-virtual {p1, p2}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->array()[B

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-virtual {p0, p1}, Ljava/io/OutputStream;->write([B)V

    .line 172
    .line 173
    .line 174
    return-void

    .line 175
    :cond_7
    instance-of v0, p2, Ljava/lang/Number;

    .line 176
    .line 177
    if-eqz v0, :cond_a

    .line 178
    .line 179
    check-cast p2, Ljava/lang/Number;

    .line 180
    .line 181
    invoke-virtual {p2}, Ljava/lang/Number;->longValue()J

    .line 182
    .line 183
    .line 184
    move-result-wide v0

    .line 185
    if-eqz p3, :cond_8

    .line 186
    .line 187
    const-wide/16 p2, 0x0

    .line 188
    .line 189
    cmp-long p2, v0, p2

    .line 190
    .line 191
    if-eqz p2, :cond_c

    .line 192
    .line 193
    :cond_8
    const-class p2, Ljp/l0;

    .line 194
    .line 195
    invoke-virtual {p1, p2}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 196
    .line 197
    .line 198
    move-result-object p1

    .line 199
    check-cast p1, Ljp/l0;

    .line 200
    .line 201
    if-eqz p1, :cond_9

    .line 202
    .line 203
    check-cast p1, Ljp/i0;

    .line 204
    .line 205
    iget p1, p1, Ljp/i0;->a:I

    .line 206
    .line 207
    shl-int/lit8 p1, p1, 0x3

    .line 208
    .line 209
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {p0, v0, v1}, Ljp/n0;->l(J)V

    .line 213
    .line 214
    .line 215
    return-void

    .line 216
    :cond_9
    new-instance p0, Lzs/b;

    .line 217
    .line 218
    const-string p1, "Field has no @Protobuf config"

    .line 219
    .line 220
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    throw p0

    .line 224
    :cond_a
    instance-of v0, p2, Ljava/lang/Boolean;

    .line 225
    .line 226
    if-eqz v0, :cond_b

    .line 227
    .line 228
    check-cast p2, Ljava/lang/Boolean;

    .line 229
    .line 230
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 231
    .line 232
    .line 233
    move-result p2

    .line 234
    invoke-virtual {p0, p1, p2, p3}, Ljp/n0;->h(Lzs/c;IZ)V

    .line 235
    .line 236
    .line 237
    return-void

    .line 238
    :cond_b
    instance-of v0, p2, [B

    .line 239
    .line 240
    if-eqz v0, :cond_e

    .line 241
    .line 242
    check-cast p2, [B

    .line 243
    .line 244
    if-eqz p3, :cond_d

    .line 245
    .line 246
    array-length p3, p2

    .line 247
    if-eqz p3, :cond_c

    .line 248
    .line 249
    goto :goto_3

    .line 250
    :cond_c
    :goto_2
    return-void

    .line 251
    :cond_d
    :goto_3
    invoke-static {p1}, Ljp/n0;->i(Lzs/c;)I

    .line 252
    .line 253
    .line 254
    move-result p1

    .line 255
    shl-int/lit8 p1, p1, 0x3

    .line 256
    .line 257
    or-int/lit8 p1, p1, 0x2

    .line 258
    .line 259
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 260
    .line 261
    .line 262
    array-length p1, p2

    .line 263
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 264
    .line 265
    .line 266
    iget-object p0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 267
    .line 268
    invoke-virtual {p0, p2}, Ljava/io/OutputStream;->write([B)V

    .line 269
    .line 270
    .line 271
    return-void

    .line 272
    :cond_e
    iget-object v0, p0, Ljp/n0;->b:Ljava/util/HashMap;

    .line 273
    .line 274
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    check-cast v0, Lzs/d;

    .line 283
    .line 284
    if-eqz v0, :cond_f

    .line 285
    .line 286
    invoke-virtual {p0, v0, p1, p2, p3}, Ljp/n0;->j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 287
    .line 288
    .line 289
    return-void

    .line 290
    :cond_f
    iget-object v0, p0, Ljp/n0;->c:Ljava/util/HashMap;

    .line 291
    .line 292
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    check-cast v0, Lzs/f;

    .line 301
    .line 302
    if-eqz v0, :cond_10

    .line 303
    .line 304
    iget-object p0, p0, Ljp/n0;->e:Lct/h;

    .line 305
    .line 306
    iput-boolean v1, p0, Lct/h;->b:Z

    .line 307
    .line 308
    iput-object p1, p0, Lct/h;->d:Lzs/c;

    .line 309
    .line 310
    iput-boolean p3, p0, Lct/h;->c:Z

    .line 311
    .line 312
    invoke-interface {v0, p2, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    return-void

    .line 316
    :cond_10
    instance-of v0, p2, Ljp/j0;

    .line 317
    .line 318
    const/4 v1, 0x1

    .line 319
    if-eqz v0, :cond_11

    .line 320
    .line 321
    check-cast p2, Ljp/j0;

    .line 322
    .line 323
    invoke-interface {p2}, Ljp/j0;->h()I

    .line 324
    .line 325
    .line 326
    move-result p2

    .line 327
    invoke-virtual {p0, p1, p2, v1}, Ljp/n0;->h(Lzs/c;IZ)V

    .line 328
    .line 329
    .line 330
    return-void

    .line 331
    :cond_11
    instance-of v0, p2, Ljava/lang/Enum;

    .line 332
    .line 333
    if-eqz v0, :cond_12

    .line 334
    .line 335
    check-cast p2, Ljava/lang/Enum;

    .line 336
    .line 337
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 338
    .line 339
    .line 340
    move-result p2

    .line 341
    invoke-virtual {p0, p1, p2, v1}, Ljp/n0;->h(Lzs/c;IZ)V

    .line 342
    .line 343
    .line 344
    return-void

    .line 345
    :cond_12
    iget-object v0, p0, Ljp/n0;->d:Lzs/d;

    .line 346
    .line 347
    invoke-virtual {p0, v0, p1, p2, p3}, Ljp/n0;->j(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 348
    .line 349
    .line 350
    return-void
.end method

.method public final synthetic d(Lzs/c;Z)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Ljp/n0;->h(Lzs/c;IZ)V

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
    invoke-virtual {p0, p1, p2, p3, v0}, Ljp/n0;->b(Lzs/c;DZ)V

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
    const-class v0, Ljp/l0;

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Ljp/l0;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    check-cast p1, Ljp/i0;

    .line 18
    .line 19
    iget p1, p1, Ljp/i0;->a:I

    .line 20
    .line 21
    shl-int/lit8 p1, p1, 0x3

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p2, p3}, Ljp/n0;->l(J)V

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
    invoke-virtual {p0, p1, p2, v0}, Ljp/n0;->h(Lzs/c;IZ)V

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
    const-class p3, Ljp/l0;

    .line 8
    .line 9
    invoke-virtual {p1, p3}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Ljp/l0;

    .line 14
    .line 15
    if-eqz p1, :cond_2

    .line 16
    .line 17
    check-cast p1, Ljp/i0;

    .line 18
    .line 19
    iget p1, p1, Ljp/i0;->a:I

    .line 20
    .line 21
    shl-int/lit8 p1, p1, 0x3

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Ljp/n0;->k(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p2}, Ljp/n0;->k(I)V

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
    .locals 5

    .line 1
    new-instance v0, Lct/b;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lct/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-wide/16 v1, 0x0

    .line 8
    .line 9
    iput-wide v1, v0, Lct/b;->e:J

    .line 10
    .line 11
    :try_start_0
    iget-object v3, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 12
    .line 13
    iput-object v0, p0, Ljp/n0;->a:Ljava/io/OutputStream;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    :try_start_1
    invoke-interface {p1, p3, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 16
    .line 17
    .line 18
    :try_start_2
    iput-object v3, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 19
    .line 20
    iget-wide v3, v0, Lct/b;->e:J
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V

    .line 23
    .line 24
    .line 25
    if-eqz p4, :cond_0

    .line 26
    .line 27
    cmp-long p4, v3, v1

    .line 28
    .line 29
    if-nez p4, :cond_0

    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    invoke-static {p2}, Ljp/n0;->i(Lzs/c;)I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    shl-int/lit8 p2, p2, 0x3

    .line 37
    .line 38
    or-int/lit8 p2, p2, 0x2

    .line 39
    .line 40
    invoke-virtual {p0, p2}, Ljp/n0;->k(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v3, v4}, Ljp/n0;->l(J)V

    .line 44
    .line 45
    .line 46
    invoke-interface {p1, p3, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    goto :goto_0

    .line 52
    :catchall_1
    move-exception p1

    .line 53
    :try_start_3
    iput-object v3, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 54
    .line 55
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 56
    :goto_0
    :try_start_4
    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :catchall_2
    move-exception p1

    .line 61
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 62
    .line 63
    .line 64
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
    and-int/lit8 v1, p1, 0x7f

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

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
    iget-object p0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 23
    .line 24
    invoke-virtual {p0, v1}, Ljava/io/OutputStream;->write(I)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final l(J)V
    .locals 5

    .line 1
    :goto_0
    const-wide/16 v0, -0x80

    .line 2
    .line 3
    and-long/2addr v0, p1

    .line 4
    long-to-int v2, p1

    .line 5
    const-wide/16 v3, 0x0

    .line 6
    .line 7
    cmp-long v0, v0, v3

    .line 8
    .line 9
    and-int/lit8 v1, v2, 0x7f

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

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
    iget-object p0, p0, Ljp/n0;->a:Ljava/io/OutputStream;

    .line 24
    .line 25
    invoke-virtual {p0, v1}, Ljava/io/OutputStream;->write(I)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
