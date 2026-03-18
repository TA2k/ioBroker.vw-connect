.class public final Lcom/google/android/gms/internal/measurement/f5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic c:I


# instance fields
.field public final a:Lcom/google/android/gms/internal/measurement/p6;

.field public b:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/f5;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/measurement/f5;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Lcom/google/android/gms/internal/measurement/p6;

    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/p6;-><init>()V

    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 2
    new-instance p1, Lcom/google/android/gms/internal/measurement/p6;

    invoke-direct {p1}, Lcom/google/android/gms/internal/measurement/p6;-><init>()V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/f5;->a()V

    .line 4
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/f5;->a()V

    return-void
.end method

.method public static b(Lcom/google/android/gms/internal/measurement/b5;Lcom/google/android/gms/internal/measurement/z6;ILjava/lang/Object;)V
    .locals 2

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/z6;->g:Lcom/google/android/gms/internal/measurement/z6;

    .line 2
    .line 3
    if-eq p1, v0, :cond_3

    .line 4
    .line 5
    iget v0, p1, Lcom/google/android/gms/internal/measurement/z6;->e:I

    .line 6
    .line 7
    invoke-virtual {p0, p2, v0}, Lcom/google/android/gms/internal/measurement/b5;->e(II)V

    .line 8
    .line 9
    .line 10
    sget-object p2, Lcom/google/android/gms/internal/measurement/a7;->d:Lcom/google/android/gms/internal/measurement/a7;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    packed-switch p1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    check-cast p3, Ljava/lang/Long;

    .line 21
    .line 22
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    add-long v0, p1, p1

    .line 27
    .line 28
    const/16 p3, 0x3f

    .line 29
    .line 30
    shr-long/2addr p1, p3

    .line 31
    xor-long/2addr p1, v0

    .line 32
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->q(J)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :pswitch_1
    check-cast p3, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    add-int p2, p1, p1

    .line 43
    .line 44
    shr-int/lit8 p1, p1, 0x1f

    .line 45
    .line 46
    xor-int/2addr p1, p2

    .line 47
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->o(I)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_2
    check-cast p3, Ljava/lang/Long;

    .line 52
    .line 53
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 54
    .line 55
    .line 56
    move-result-wide p1

    .line 57
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->r(J)V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :pswitch_3
    check-cast p3, Ljava/lang/Integer;

    .line 62
    .line 63
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->p(I)V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :pswitch_4
    instance-of p1, p3, Lcom/google/android/gms/internal/measurement/n5;

    .line 72
    .line 73
    if-eqz p1, :cond_0

    .line 74
    .line 75
    check-cast p3, Lcom/google/android/gms/internal/measurement/n5;

    .line 76
    .line 77
    invoke-interface {p3}, Lcom/google/android/gms/internal/measurement/n5;->h()I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->n(I)V

    .line 82
    .line 83
    .line 84
    return-void

    .line 85
    :cond_0
    check-cast p3, Ljava/lang/Integer;

    .line 86
    .line 87
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->n(I)V

    .line 92
    .line 93
    .line 94
    return-void

    .line 95
    :pswitch_5
    check-cast p3, Ljava/lang/Integer;

    .line 96
    .line 97
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->o(I)V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :pswitch_6
    instance-of p1, p3, Lcom/google/android/gms/internal/measurement/a5;

    .line 106
    .line 107
    if-eqz p1, :cond_1

    .line 108
    .line 109
    check-cast p3, Lcom/google/android/gms/internal/measurement/a5;

    .line 110
    .line 111
    invoke-virtual {p0, p3}, Lcom/google/android/gms/internal/measurement/b5;->l(Lcom/google/android/gms/internal/measurement/a5;)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_1
    check-cast p3, [B

    .line 116
    .line 117
    array-length p1, p3

    .line 118
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->o(I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p0, p1, p3}, Lcom/google/android/gms/internal/measurement/b5;->s(I[B)V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :pswitch_7
    check-cast p3, Lcom/google/android/gms/internal/measurement/t4;

    .line 126
    .line 127
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    check-cast p3, Lcom/google/android/gms/internal/measurement/l5;

    .line 131
    .line 132
    invoke-virtual {p3}, Lcom/google/android/gms/internal/measurement/l5;->k()I

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->o(I)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p3, p0}, Lcom/google/android/gms/internal/measurement/l5;->d(Lcom/google/android/gms/internal/measurement/b5;)V

    .line 140
    .line 141
    .line 142
    return-void

    .line 143
    :pswitch_8
    check-cast p3, Lcom/google/android/gms/internal/measurement/t4;

    .line 144
    .line 145
    check-cast p3, Lcom/google/android/gms/internal/measurement/l5;

    .line 146
    .line 147
    invoke-virtual {p3, p0}, Lcom/google/android/gms/internal/measurement/l5;->d(Lcom/google/android/gms/internal/measurement/b5;)V

    .line 148
    .line 149
    .line 150
    return-void

    .line 151
    :pswitch_9
    instance-of p1, p3, Lcom/google/android/gms/internal/measurement/a5;

    .line 152
    .line 153
    if-eqz p1, :cond_2

    .line 154
    .line 155
    check-cast p3, Lcom/google/android/gms/internal/measurement/a5;

    .line 156
    .line 157
    invoke-virtual {p0, p3}, Lcom/google/android/gms/internal/measurement/b5;->l(Lcom/google/android/gms/internal/measurement/a5;)V

    .line 158
    .line 159
    .line 160
    return-void

    .line 161
    :cond_2
    check-cast p3, Ljava/lang/String;

    .line 162
    .line 163
    invoke-virtual {p0, p3}, Lcom/google/android/gms/internal/measurement/b5;->t(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    return-void

    .line 167
    :pswitch_a
    check-cast p3, Ljava/lang/Boolean;

    .line 168
    .line 169
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 170
    .line 171
    .line 172
    move-result p1

    .line 173
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->m(B)V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :pswitch_b
    check-cast p3, Ljava/lang/Integer;

    .line 178
    .line 179
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 180
    .line 181
    .line 182
    move-result p1

    .line 183
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->p(I)V

    .line 184
    .line 185
    .line 186
    return-void

    .line 187
    :pswitch_c
    check-cast p3, Ljava/lang/Long;

    .line 188
    .line 189
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 190
    .line 191
    .line 192
    move-result-wide p1

    .line 193
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->r(J)V

    .line 194
    .line 195
    .line 196
    return-void

    .line 197
    :pswitch_d
    check-cast p3, Ljava/lang/Integer;

    .line 198
    .line 199
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 200
    .line 201
    .line 202
    move-result p1

    .line 203
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->n(I)V

    .line 204
    .line 205
    .line 206
    return-void

    .line 207
    :pswitch_e
    check-cast p3, Ljava/lang/Long;

    .line 208
    .line 209
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 210
    .line 211
    .line 212
    move-result-wide p1

    .line 213
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->q(J)V

    .line 214
    .line 215
    .line 216
    return-void

    .line 217
    :pswitch_f
    check-cast p3, Ljava/lang/Long;

    .line 218
    .line 219
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 220
    .line 221
    .line 222
    move-result-wide p1

    .line 223
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->q(J)V

    .line 224
    .line 225
    .line 226
    return-void

    .line 227
    :pswitch_10
    check-cast p3, Ljava/lang/Float;

    .line 228
    .line 229
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 230
    .line 231
    .line 232
    move-result p1

    .line 233
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 234
    .line 235
    .line 236
    move-result p1

    .line 237
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b5;->p(I)V

    .line 238
    .line 239
    .line 240
    return-void

    .line 241
    :pswitch_11
    check-cast p3, Ljava/lang/Double;

    .line 242
    .line 243
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    .line 244
    .line 245
    .line 246
    move-result-wide p1

    .line 247
    invoke-static {p1, p2}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 248
    .line 249
    .line 250
    move-result-wide p1

    .line 251
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/b5;->r(J)V

    .line 252
    .line 253
    .line 254
    return-void

    .line 255
    :cond_3
    check-cast p3, Lcom/google/android/gms/internal/measurement/t4;

    .line 256
    .line 257
    sget-object p1, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    .line 258
    .line 259
    const/4 p1, 0x3

    .line 260
    invoke-virtual {p0, p2, p1}, Lcom/google/android/gms/internal/measurement/b5;->e(II)V

    .line 261
    .line 262
    .line 263
    check-cast p3, Lcom/google/android/gms/internal/measurement/l5;

    .line 264
    .line 265
    invoke-virtual {p3, p0}, Lcom/google/android/gms/internal/measurement/l5;->d(Lcom/google/android/gms/internal/measurement/b5;)V

    .line 266
    .line 267
    .line 268
    const/4 p1, 0x4

    .line 269
    invoke-virtual {p0, p2, p1}, Lcom/google/android/gms/internal/measurement/b5;->e(II)V

    .line 270
    .line 271
    .line 272
    return-void

    .line 273
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
    .locals 6

    .line 1
    iget-boolean v0, p0, Lcom/google/android/gms/internal/measurement/f5;->b:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    .line 7
    .line 8
    iget v1, v0, Lcom/google/android/gms/internal/measurement/p6;->e:I

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    if-ge v3, v1, :cond_2

    .line 13
    .line 14
    invoke-virtual {v0, v3}, Lcom/google/android/gms/internal/measurement/p6;->a(I)Lcom/google/android/gms/internal/measurement/q6;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    iget-object v4, v4, Lcom/google/android/gms/internal/measurement/q6;->e:Ljava/lang/Object;

    .line 19
    .line 20
    instance-of v5, v4, Lcom/google/android/gms/internal/measurement/l5;

    .line 21
    .line 22
    if-eqz v5, :cond_1

    .line 23
    .line 24
    check-cast v4, Lcom/google/android/gms/internal/measurement/l5;

    .line 25
    .line 26
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/l5;->g()V

    .line 27
    .line 28
    .line 29
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/p6;->b()Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    :cond_3
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-eqz v3, :cond_4

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    check-cast v3, Ljava/util/Map$Entry;

    .line 51
    .line 52
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    instance-of v4, v3, Lcom/google/android/gms/internal/measurement/l5;

    .line 57
    .line 58
    if-eqz v4, :cond_3

    .line 59
    .line 60
    check-cast v3, Lcom/google/android/gms/internal/measurement/l5;

    .line 61
    .line 62
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/l5;->g()V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    iget-boolean v1, v0, Lcom/google/android/gms/internal/measurement/p6;->g:Z

    .line 67
    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    iget v1, v0, Lcom/google/android/gms/internal/measurement/p6;->e:I

    .line 71
    .line 72
    if-gtz v1, :cond_6

    .line 73
    .line 74
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/p6;->b()Ljava/util/Set;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-nez v2, :cond_5

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_5
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    check-cast p0, Ljava/util/Map$Entry;

    .line 94
    .line 95
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    new-instance p0, Ljava/lang/ClassCastException;

    .line 103
    .line 104
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 105
    .line 106
    .line 107
    throw p0

    .line 108
    :cond_6
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/measurement/p6;->a(I)Lcom/google/android/gms/internal/measurement/q6;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/q6;->d:Ljava/lang/Comparable;

    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    new-instance p0, Ljava/lang/ClassCastException;

    .line 118
    .line 119
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_7
    :goto_2
    iget-boolean v1, v0, Lcom/google/android/gms/internal/measurement/p6;->g:Z

    .line 124
    .line 125
    const/4 v2, 0x1

    .line 126
    if-nez v1, :cond_a

    .line 127
    .line 128
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/p6;->f:Ljava/util/Map;

    .line 129
    .line 130
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_8

    .line 135
    .line 136
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_8
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/p6;->f:Ljava/util/Map;

    .line 140
    .line 141
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    :goto_3
    iput-object v1, v0, Lcom/google/android/gms/internal/measurement/p6;->f:Ljava/util/Map;

    .line 146
    .line 147
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/p6;->i:Ljava/util/Map;

    .line 148
    .line 149
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-eqz v1, :cond_9

    .line 154
    .line 155
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_9
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/p6;->i:Ljava/util/Map;

    .line 159
    .line 160
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    :goto_4
    iput-object v1, v0, Lcom/google/android/gms/internal/measurement/p6;->i:Ljava/util/Map;

    .line 165
    .line 166
    iput-boolean v2, v0, Lcom/google/android/gms/internal/measurement/p6;->g:Z

    .line 167
    .line 168
    :cond_a
    iput-boolean v2, p0, Lcom/google/android/gms/internal/measurement/f5;->b:Z

    .line 169
    .line 170
    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/f5;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/f5;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    .line 7
    .line 8
    iget v1, p0, Lcom/google/android/gms/internal/measurement/p6;->e:I

    .line 9
    .line 10
    if-gtz v1, :cond_2

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/p6;->b()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Ljava/util/Map$Entry;

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    const/4 p0, 0x0

    .line 43
    throw p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 45
    .line 46
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    const/4 v0, 0x0

    .line 51
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/p6;->a(I)Lcom/google/android/gms/internal/measurement/q6;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/q6;->d:Ljava/lang/Comparable;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    new-instance p0, Ljava/lang/ClassCastException;

    .line 61
    .line 62
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 63
    .line 64
    .line 65
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
    instance-of v0, p1, Lcom/google/android/gms/internal/measurement/f5;

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
    check-cast p1, Lcom/google/android/gms/internal/measurement/f5;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    .line 14
    .line 15
    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/p6;->equals(Ljava/lang/Object;)Z

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
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/f5;->a:Lcom/google/android/gms/internal/measurement/p6;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/p6;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
