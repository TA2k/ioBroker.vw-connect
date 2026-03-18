.class public final Lcom/google/protobuf/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic c:I


# instance fields
.field public final a:Lcom/google/protobuf/y0;

.field public b:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/protobuf/k;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/protobuf/k;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lcom/google/protobuf/y0;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, Lcom/google/protobuf/y0;-><init>(I)V

    .line 3
    iput-object v0, p0, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 4
    new-instance p1, Lcom/google/protobuf/y0;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Lcom/google/protobuf/y0;-><init>(I)V

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    .line 7
    invoke-virtual {p0}, Lcom/google/protobuf/k;->a()V

    .line 8
    invoke-virtual {p0}, Lcom/google/protobuf/k;->a()V

    return-void
.end method

.method public static b(Lcom/google/protobuf/f;Lcom/google/protobuf/u1;ILjava/lang/Object;)V
    .locals 2

    .line 1
    sget-object v0, Lcom/google/protobuf/u1;->h:Lcom/google/protobuf/r1;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    check-cast p3, Lcom/google/protobuf/a;

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-virtual {p0, p2, p1}, Lcom/google/protobuf/f;->r(II)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3, p0}, Lcom/google/protobuf/a;->i(Lcom/google/protobuf/f;)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x4

    .line 15
    invoke-virtual {p0, p2, p1}, Lcom/google/protobuf/f;->r(II)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget v0, p1, Lcom/google/protobuf/u1;->e:I

    .line 20
    .line 21
    invoke-virtual {p0, p2, v0}, Lcom/google/protobuf/f;->r(II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    packed-switch p1, :pswitch_data_0

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_0
    check-cast p3, Ljava/lang/Long;

    .line 33
    .line 34
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 35
    .line 36
    .line 37
    move-result-wide p1

    .line 38
    const/4 p3, 0x1

    .line 39
    shl-long v0, p1, p3

    .line 40
    .line 41
    const/16 p3, 0x3f

    .line 42
    .line 43
    shr-long/2addr p1, p3

    .line 44
    xor-long/2addr p1, v0

    .line 45
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/f;->u(J)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_1
    check-cast p3, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    shl-int/lit8 p2, p1, 0x1

    .line 56
    .line 57
    shr-int/lit8 p1, p1, 0x1f

    .line 58
    .line 59
    xor-int/2addr p1, p2

    .line 60
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->s(I)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :pswitch_2
    check-cast p3, Ljava/lang/Long;

    .line 65
    .line 66
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 67
    .line 68
    .line 69
    move-result-wide p1

    .line 70
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/f;->o(J)V

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :pswitch_3
    check-cast p3, Ljava/lang/Integer;

    .line 75
    .line 76
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->m(I)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :pswitch_4
    instance-of p1, p3, Lau/i;

    .line 85
    .line 86
    if-eqz p1, :cond_1

    .line 87
    .line 88
    check-cast p3, Lau/i;

    .line 89
    .line 90
    iget p1, p3, Lau/i;->d:I

    .line 91
    .line 92
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->p(I)V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :cond_1
    check-cast p3, Ljava/lang/Integer;

    .line 97
    .line 98
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->p(I)V

    .line 103
    .line 104
    .line 105
    return-void

    .line 106
    :pswitch_5
    check-cast p3, Ljava/lang/Integer;

    .line 107
    .line 108
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->s(I)V

    .line 113
    .line 114
    .line 115
    return-void

    .line 116
    :pswitch_6
    instance-of p1, p3, Lcom/google/protobuf/e;

    .line 117
    .line 118
    if-eqz p1, :cond_2

    .line 119
    .line 120
    check-cast p3, Lcom/google/protobuf/e;

    .line 121
    .line 122
    invoke-virtual {p0, p3}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 123
    .line 124
    .line 125
    return-void

    .line 126
    :cond_2
    check-cast p3, [B

    .line 127
    .line 128
    array-length p1, p3

    .line 129
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->s(I)V

    .line 130
    .line 131
    .line 132
    const/4 p2, 0x0

    .line 133
    invoke-virtual {p0, p3, p2, p1}, Lcom/google/protobuf/f;->j([BII)V

    .line 134
    .line 135
    .line 136
    return-void

    .line 137
    :pswitch_7
    check-cast p3, Lcom/google/protobuf/a;

    .line 138
    .line 139
    move-object p1, p3

    .line 140
    check-cast p1, Lcom/google/protobuf/p;

    .line 141
    .line 142
    const/4 p2, 0x0

    .line 143
    invoke-virtual {p1, p2}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 144
    .line 145
    .line 146
    move-result p1

    .line 147
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->s(I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {p3, p0}, Lcom/google/protobuf/a;->i(Lcom/google/protobuf/f;)V

    .line 151
    .line 152
    .line 153
    return-void

    .line 154
    :pswitch_8
    check-cast p3, Lcom/google/protobuf/a;

    .line 155
    .line 156
    invoke-virtual {p3, p0}, Lcom/google/protobuf/a;->i(Lcom/google/protobuf/f;)V

    .line 157
    .line 158
    .line 159
    return-void

    .line 160
    :pswitch_9
    instance-of p1, p3, Lcom/google/protobuf/e;

    .line 161
    .line 162
    if-eqz p1, :cond_3

    .line 163
    .line 164
    check-cast p3, Lcom/google/protobuf/e;

    .line 165
    .line 166
    invoke-virtual {p0, p3}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 167
    .line 168
    .line 169
    return-void

    .line 170
    :cond_3
    check-cast p3, Ljava/lang/String;

    .line 171
    .line 172
    invoke-virtual {p0, p3}, Lcom/google/protobuf/f;->q(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    return-void

    .line 176
    :pswitch_a
    check-cast p3, Ljava/lang/Boolean;

    .line 177
    .line 178
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 179
    .line 180
    .line 181
    move-result p1

    .line 182
    int-to-byte p1, p1

    .line 183
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->i(B)V

    .line 184
    .line 185
    .line 186
    return-void

    .line 187
    :pswitch_b
    check-cast p3, Ljava/lang/Integer;

    .line 188
    .line 189
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 190
    .line 191
    .line 192
    move-result p1

    .line 193
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->m(I)V

    .line 194
    .line 195
    .line 196
    return-void

    .line 197
    :pswitch_c
    check-cast p3, Ljava/lang/Long;

    .line 198
    .line 199
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 200
    .line 201
    .line 202
    move-result-wide p1

    .line 203
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/f;->o(J)V

    .line 204
    .line 205
    .line 206
    return-void

    .line 207
    :pswitch_d
    check-cast p3, Ljava/lang/Integer;

    .line 208
    .line 209
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 210
    .line 211
    .line 212
    move-result p1

    .line 213
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->p(I)V

    .line 214
    .line 215
    .line 216
    return-void

    .line 217
    :pswitch_e
    check-cast p3, Ljava/lang/Long;

    .line 218
    .line 219
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 220
    .line 221
    .line 222
    move-result-wide p1

    .line 223
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/f;->u(J)V

    .line 224
    .line 225
    .line 226
    return-void

    .line 227
    :pswitch_f
    check-cast p3, Ljava/lang/Long;

    .line 228
    .line 229
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 230
    .line 231
    .line 232
    move-result-wide p1

    .line 233
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/f;->u(J)V

    .line 234
    .line 235
    .line 236
    return-void

    .line 237
    :pswitch_10
    check-cast p3, Ljava/lang/Float;

    .line 238
    .line 239
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 240
    .line 241
    .line 242
    move-result p1

    .line 243
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 244
    .line 245
    .line 246
    move-result p1

    .line 247
    invoke-virtual {p0, p1}, Lcom/google/protobuf/f;->m(I)V

    .line 248
    .line 249
    .line 250
    return-void

    .line 251
    :pswitch_11
    check-cast p3, Ljava/lang/Double;

    .line 252
    .line 253
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    .line 254
    .line 255
    .line 256
    move-result-wide p1

    .line 257
    invoke-static {p1, p2}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 258
    .line 259
    .line 260
    move-result-wide p1

    .line 261
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/f;->o(J)V

    .line 262
    .line 263
    .line 264
    return-void

    .line 265
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lcom/google/protobuf/k;->b:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const/4 v0, 0x0

    .line 7
    move v1, v0

    .line 8
    :goto_0
    iget-object v2, p0, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    .line 9
    .line 10
    iget-object v3, v2, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 11
    .line 12
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-ge v1, v3, :cond_2

    .line 17
    .line 18
    invoke-virtual {v2, v1}, Lcom/google/protobuf/y0;->c(I)Ljava/util/Map$Entry;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    instance-of v3, v3, Lcom/google/protobuf/p;

    .line 27
    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lcom/google/protobuf/p;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    sget-object v3, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 40
    .line 41
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    invoke-virtual {v3, v4}, Lcom/google/protobuf/t0;->a(Ljava/lang/Class;)Lcom/google/protobuf/w0;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v3, v2}, Lcom/google/protobuf/w0;->a(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2}, Lcom/google/protobuf/p;->o()V

    .line 56
    .line 57
    .line 58
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iget-boolean v1, v2, Lcom/google/protobuf/y0;->g:Z

    .line 62
    .line 63
    if-nez v1, :cond_5

    .line 64
    .line 65
    iget-object v1, v2, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 66
    .line 67
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-gtz v1, :cond_4

    .line 72
    .line 73
    invoke-virtual {v2}, Lcom/google/protobuf/y0;->d()Ljava/lang/Iterable;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    if-nez v1, :cond_3

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_3
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ljava/util/Map$Entry;

    .line 93
    .line 94
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    new-instance p0, Ljava/lang/ClassCastException;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_4
    invoke-virtual {v2, v0}, Lcom/google/protobuf/y0;->c(I)Ljava/util/Map$Entry;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    new-instance p0, Ljava/lang/ClassCastException;

    .line 119
    .line 120
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_5
    :goto_1
    iget-boolean v0, v2, Lcom/google/protobuf/y0;->g:Z

    .line 125
    .line 126
    const/4 v1, 0x1

    .line 127
    if-nez v0, :cond_8

    .line 128
    .line 129
    iget-object v0, v2, Lcom/google/protobuf/y0;->f:Ljava/util/Map;

    .line 130
    .line 131
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    if-eqz v0, :cond_6

    .line 136
    .line 137
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_6
    iget-object v0, v2, Lcom/google/protobuf/y0;->f:Ljava/util/Map;

    .line 141
    .line 142
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    :goto_2
    iput-object v0, v2, Lcom/google/protobuf/y0;->f:Ljava/util/Map;

    .line 147
    .line 148
    iget-object v0, v2, Lcom/google/protobuf/y0;->i:Ljava/util/Map;

    .line 149
    .line 150
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    if-eqz v0, :cond_7

    .line 155
    .line 156
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_7
    iget-object v0, v2, Lcom/google/protobuf/y0;->i:Ljava/util/Map;

    .line 160
    .line 161
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    :goto_3
    iput-object v0, v2, Lcom/google/protobuf/y0;->i:Ljava/util/Map;

    .line 166
    .line 167
    iput-boolean v1, v2, Lcom/google/protobuf/y0;->g:Z

    .line 168
    .line 169
    :cond_8
    iput-boolean v1, p0, Lcom/google/protobuf/k;->b:Z

    .line 170
    .line 171
    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/protobuf/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/protobuf/k;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    .line 7
    .line 8
    iget-object v1, p0, Lcom/google/protobuf/y0;->e:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-gtz v1, :cond_2

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/google/protobuf/y0;->d()Ljava/lang/Iterable;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/util/Map$Entry;

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    if-nez v0, :cond_1

    .line 43
    .line 44
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    throw v2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    const/4 v0, 0x0

    .line 55
    invoke-virtual {p0, v0}, Lcom/google/protobuf/y0;->c(I)Ljava/util/Map$Entry;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    throw v2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/ClassCastException;

    .line 70
    .line 71
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 72
    .line 73
    .line 74
    throw p0
.end method

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
    instance-of v0, p1, Lcom/google/protobuf/k;

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
    check-cast p1, Lcom/google/protobuf/k;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    .line 14
    .line 15
    iget-object p1, p1, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lcom/google/protobuf/y0;->equals(Ljava/lang/Object;)Z

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
    iget-object p0, p0, Lcom/google/protobuf/k;->a:Lcom/google/protobuf/y0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/protobuf/y0;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
