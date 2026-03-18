.class public final Lct/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/e;


# static fields
.field public static final f:Ljava/nio/charset/Charset;

.field public static final g:Lzs/c;

.field public static final h:Lzs/c;

.field public static final i:Lbt/a;


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
    sput-object v0, Lct/f;->f:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    new-instance v0, Lct/a;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lct/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    const-class v1, Lct/e;

    .line 16
    .line 17
    invoke-static {v1, v0}, Lp3/m;->t(Ljava/lang/Class;Lct/a;)Ljava/util/HashMap;

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
    sput-object v2, Lct/f;->g:Lzs/c;

    .line 33
    .line 34
    new-instance v0, Lct/a;

    .line 35
    .line 36
    const/4 v2, 0x2

    .line 37
    invoke-direct {v0, v2}, Lct/a;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1, v0}, Lp3/m;->t(Ljava/lang/Class;Lct/a;)Ljava/util/HashMap;

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
    sput-object v1, Lct/f;->h:Lzs/c;

    .line 56
    .line 57
    new-instance v0, Lbt/a;

    .line 58
    .line 59
    const/4 v1, 0x1

    .line 60
    invoke-direct {v0, v1}, Lbt/a;-><init>(I)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Lct/f;->i:Lbt/a;

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
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, v1}, Lct/h;-><init>(Lzs/e;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lct/f;->e:Lct/h;

    .line 11
    .line 12
    iput-object p1, p0, Lct/f;->a:Ljava/io/OutputStream;

    .line 13
    .line 14
    iput-object p2, p0, Lct/f;->b:Ljava/util/HashMap;

    .line 15
    .line 16
    iput-object p3, p0, Lct/f;->c:Ljava/util/HashMap;

    .line 17
    .line 18
    iput-object p4, p0, Lct/f;->d:Lzs/d;

    .line 19
    .line 20
    return-void
.end method

.method public static j(Lzs/c;)I
    .locals 1

    .line 1
    const-class v0, Lct/e;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lct/e;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    check-cast p0, Lct/a;

    .line 12
    .line 13
    iget p0, p0, Lct/a;->a:I

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
    invoke-virtual {p0, p1, p2, v0}, Lct/f;->h(Lzs/c;Ljava/lang/Object;Z)V

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
    invoke-static {p1}, Lct/f;->j(Lzs/c;)I

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
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lct/f;->a:Ljava/io/OutputStream;

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

.method public final c(Lzs/c;IZ)V
    .locals 0

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const-class p3, Lct/e;

    .line 7
    .line 8
    invoke-virtual {p1, p3}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    check-cast p1, Lct/e;

    .line 13
    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    check-cast p1, Lct/a;

    .line 17
    .line 18
    iget p1, p1, Lct/a;->a:I

    .line 19
    .line 20
    shl-int/lit8 p1, p1, 0x3

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p2}, Lct/f;->k(I)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    new-instance p0, Lzs/b;

    .line 30
    .line 31
    const-string p1, "Field has no @Protobuf config"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public final d(Lzs/c;Z)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lct/f;->c(Lzs/c;IZ)V

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
    invoke-virtual {p0, p1, p2, p3, v0}, Lct/f;->b(Lzs/c;DZ)V

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
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const-class v0, Lct/e;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Lct/e;

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    check-cast p1, Lct/a;

    .line 19
    .line 20
    iget p1, p1, Lct/a;->a:I

    .line 21
    .line 22
    shl-int/lit8 p1, p1, 0x3

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p2, p3}, Lct/f;->l(J)V

    .line 28
    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    new-instance p0, Lzs/b;

    .line 32
    .line 33
    const-string p1, "Field has no @Protobuf config"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public final g(Lzs/c;I)Lzs/e;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, p2, v0}, Lct/f;->c(Lzs/c;IZ)V

    .line 3
    .line 4
    .line 5
    return-object p0
.end method

.method public final h(Lzs/c;Ljava/lang/Object;Z)V
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
    invoke-static {p1}, Lct/f;->j(Lzs/c;)I

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
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p2}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    sget-object p2, Lct/f;->f:Ljava/nio/charset/Charset;

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
    invoke-virtual {p0, p2}, Lct/f;->k(I)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    invoke-virtual {p0, p1, p3, v1}, Lct/f;->h(Lzs/c;Ljava/lang/Object;Z)V

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
    sget-object v0, Lct/f;->i:Lbt/a;

    .line 104
    .line 105
    invoke-virtual {p0, v0, p1, p3, v1}, Lct/f;->i(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

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
    invoke-virtual {p0, p1, v0, v1, p3}, Lct/f;->b(Lzs/c;DZ)V

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
    invoke-static {p1}, Lct/f;->j(Lzs/c;)I

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
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 150
    .line 151
    .line 152
    iget-object p0, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    if-nez p2, :cond_8

    .line 194
    .line 195
    goto :goto_2

    .line 196
    :cond_8
    const-class p2, Lct/e;

    .line 197
    .line 198
    invoke-virtual {p1, p2}, Lzs/c;->a(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    check-cast p1, Lct/e;

    .line 203
    .line 204
    if-eqz p1, :cond_9

    .line 205
    .line 206
    check-cast p1, Lct/a;

    .line 207
    .line 208
    iget p1, p1, Lct/a;->a:I

    .line 209
    .line 210
    shl-int/lit8 p1, p1, 0x3

    .line 211
    .line 212
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p0, v0, v1}, Lct/f;->l(J)V

    .line 216
    .line 217
    .line 218
    return-void

    .line 219
    :cond_9
    new-instance p0, Lzs/b;

    .line 220
    .line 221
    const-string p1, "Field has no @Protobuf config"

    .line 222
    .line 223
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    throw p0

    .line 227
    :cond_a
    instance-of v0, p2, Ljava/lang/Boolean;

    .line 228
    .line 229
    if-eqz v0, :cond_b

    .line 230
    .line 231
    check-cast p2, Ljava/lang/Boolean;

    .line 232
    .line 233
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 234
    .line 235
    .line 236
    move-result p2

    .line 237
    invoke-virtual {p0, p1, p2, p3}, Lct/f;->c(Lzs/c;IZ)V

    .line 238
    .line 239
    .line 240
    return-void

    .line 241
    :cond_b
    instance-of v0, p2, [B

    .line 242
    .line 243
    if-eqz v0, :cond_e

    .line 244
    .line 245
    check-cast p2, [B

    .line 246
    .line 247
    if-eqz p3, :cond_d

    .line 248
    .line 249
    array-length p3, p2

    .line 250
    if-nez p3, :cond_d

    .line 251
    .line 252
    :cond_c
    :goto_2
    return-void

    .line 253
    :cond_d
    invoke-static {p1}, Lct/f;->j(Lzs/c;)I

    .line 254
    .line 255
    .line 256
    move-result p1

    .line 257
    shl-int/lit8 p1, p1, 0x3

    .line 258
    .line 259
    or-int/lit8 p1, p1, 0x2

    .line 260
    .line 261
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 262
    .line 263
    .line 264
    array-length p1, p2

    .line 265
    invoke-virtual {p0, p1}, Lct/f;->k(I)V

    .line 266
    .line 267
    .line 268
    iget-object p0, p0, Lct/f;->a:Ljava/io/OutputStream;

    .line 269
    .line 270
    invoke-virtual {p0, p2}, Ljava/io/OutputStream;->write([B)V

    .line 271
    .line 272
    .line 273
    return-void

    .line 274
    :cond_e
    iget-object v0, p0, Lct/f;->b:Ljava/util/HashMap;

    .line 275
    .line 276
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 277
    .line 278
    .line 279
    move-result-object v2

    .line 280
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    check-cast v0, Lzs/d;

    .line 285
    .line 286
    if-eqz v0, :cond_f

    .line 287
    .line 288
    invoke-virtual {p0, v0, p1, p2, p3}, Lct/f;->i(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 289
    .line 290
    .line 291
    return-void

    .line 292
    :cond_f
    iget-object v0, p0, Lct/f;->c:Ljava/util/HashMap;

    .line 293
    .line 294
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    check-cast v0, Lzs/f;

    .line 303
    .line 304
    if-eqz v0, :cond_10

    .line 305
    .line 306
    iget-object p0, p0, Lct/f;->e:Lct/h;

    .line 307
    .line 308
    iput-boolean v1, p0, Lct/h;->b:Z

    .line 309
    .line 310
    iput-object p1, p0, Lct/h;->d:Lzs/c;

    .line 311
    .line 312
    iput-boolean p3, p0, Lct/h;->c:Z

    .line 313
    .line 314
    invoke-interface {v0, p2, p0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    return-void

    .line 318
    :cond_10
    instance-of v0, p2, Lct/c;

    .line 319
    .line 320
    const/4 v1, 0x1

    .line 321
    if-eqz v0, :cond_11

    .line 322
    .line 323
    check-cast p2, Lct/c;

    .line 324
    .line 325
    invoke-interface {p2}, Lct/c;->getNumber()I

    .line 326
    .line 327
    .line 328
    move-result p2

    .line 329
    invoke-virtual {p0, p1, p2, v1}, Lct/f;->c(Lzs/c;IZ)V

    .line 330
    .line 331
    .line 332
    return-void

    .line 333
    :cond_11
    instance-of v0, p2, Ljava/lang/Enum;

    .line 334
    .line 335
    if-eqz v0, :cond_12

    .line 336
    .line 337
    check-cast p2, Ljava/lang/Enum;

    .line 338
    .line 339
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 340
    .line 341
    .line 342
    move-result p2

    .line 343
    invoke-virtual {p0, p1, p2, v1}, Lct/f;->c(Lzs/c;IZ)V

    .line 344
    .line 345
    .line 346
    return-void

    .line 347
    :cond_12
    iget-object v0, p0, Lct/f;->d:Lzs/d;

    .line 348
    .line 349
    invoke-virtual {p0, v0, p1, p2, p3}, Lct/f;->i(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V

    .line 350
    .line 351
    .line 352
    return-void
.end method

.method public final i(Lzs/d;Lzs/c;Ljava/lang/Object;Z)V
    .locals 5

    .line 1
    new-instance v0, Lct/b;

    .line 2
    .line 3
    const/4 v1, 0x0

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
    iget-object v3, p0, Lct/f;->a:Ljava/io/OutputStream;

    .line 12
    .line 13
    iput-object v0, p0, Lct/f;->a:Ljava/io/OutputStream;
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
    iput-object v3, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    invoke-static {p2}, Lct/f;->j(Lzs/c;)I

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
    invoke-virtual {p0, p2}, Lct/f;->k(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v3, v4}, Lct/f;->l(J)V

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
    iput-object v3, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    iget-object p0, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    iget-object v0, p0, Lct/f;->a:Ljava/io/OutputStream;

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
    iget-object p0, p0, Lct/f;->a:Ljava/io/OutputStream;

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
