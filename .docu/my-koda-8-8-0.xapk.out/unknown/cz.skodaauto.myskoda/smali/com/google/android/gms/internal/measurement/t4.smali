.class public abstract Lcom/google/android/gms/internal/measurement/t4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field protected zza:I


# direct methods
.method public static c(Ljava/lang/Iterable;Ljava/util/List;)V
    .locals 5

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/s5;->a:Ljava/nio/charset/Charset;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lcom/google/android/gms/internal/measurement/w5;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_4

    .line 10
    .line 11
    check-cast p0, Lcom/google/android/gms/internal/measurement/w5;

    .line 12
    .line 13
    invoke-interface {p0}, Lcom/google/android/gms/internal/measurement/w5;->h()Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    move-object v0, p1

    .line 18
    check-cast v0, Lcom/google/android/gms/internal/measurement/w5;

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_d

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    if-nez v2, :cond_1

    .line 39
    .line 40
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    sub-int/2addr p0, p1

    .line 45
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    new-instance v2, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    add-int/lit8 v1, v1, 0x1a

    .line 56
    .line 57
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 58
    .line 59
    .line 60
    const-string v1, "Element at index "

    .line 61
    .line 62
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string p0, " is null."

    .line 69
    .line 70
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    :goto_1
    add-int/lit8 v1, v1, -0x1

    .line 82
    .line 83
    if-lt v1, p1, :cond_0

    .line 84
    .line 85
    invoke-interface {v0, v1}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    .line 90
    .line 91
    invoke-direct {p1, p0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p1

    .line 95
    :cond_1
    instance-of v3, v2, Lcom/google/android/gms/internal/measurement/a5;

    .line 96
    .line 97
    if-eqz v3, :cond_2

    .line 98
    .line 99
    check-cast v2, Lcom/google/android/gms/internal/measurement/a5;

    .line 100
    .line 101
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/w5;->l()V

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_2
    instance-of v3, v2, [B

    .line 106
    .line 107
    if-eqz v3, :cond_3

    .line 108
    .line 109
    check-cast v2, [B

    .line 110
    .line 111
    array-length v3, v2

    .line 112
    invoke-static {v2, v1, v3}, Lcom/google/android/gms/internal/measurement/a5;->i([BII)Lcom/google/android/gms/internal/measurement/a5;

    .line 113
    .line 114
    .line 115
    invoke-interface {v0}, Lcom/google/android/gms/internal/measurement/w5;->l()V

    .line 116
    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_3
    check-cast v2, Ljava/lang/String;

    .line 120
    .line 121
    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_4
    instance-of v0, p0, Lcom/google/android/gms/internal/measurement/j6;

    .line 126
    .line 127
    if-nez v0, :cond_e

    .line 128
    .line 129
    instance-of v0, p0, Ljava/util/Collection;

    .line 130
    .line 131
    if-eqz v0, :cond_9

    .line 132
    .line 133
    move-object v0, p0

    .line 134
    check-cast v0, Ljava/util/Collection;

    .line 135
    .line 136
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    instance-of v2, p1, Ljava/util/ArrayList;

    .line 141
    .line 142
    if-eqz v2, :cond_5

    .line 143
    .line 144
    move-object v2, p1

    .line 145
    check-cast v2, Ljava/util/ArrayList;

    .line 146
    .line 147
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    add-int/2addr v3, v0

    .line 152
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->ensureCapacity(I)V

    .line 153
    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_5
    instance-of v2, p1, Lcom/google/android/gms/internal/measurement/l6;

    .line 157
    .line 158
    if-eqz v2, :cond_9

    .line 159
    .line 160
    move-object v2, p1

    .line 161
    check-cast v2, Lcom/google/android/gms/internal/measurement/l6;

    .line 162
    .line 163
    iget v3, v2, Lcom/google/android/gms/internal/measurement/l6;->f:I

    .line 164
    .line 165
    add-int/2addr v3, v0

    .line 166
    iget-object v0, v2, Lcom/google/android/gms/internal/measurement/l6;->e:[Ljava/lang/Object;

    .line 167
    .line 168
    array-length v0, v0

    .line 169
    if-gt v3, v0, :cond_6

    .line 170
    .line 171
    goto :goto_3

    .line 172
    :cond_6
    const/16 v4, 0xa

    .line 173
    .line 174
    if-eqz v0, :cond_8

    .line 175
    .line 176
    :goto_2
    if-ge v0, v3, :cond_7

    .line 177
    .line 178
    mul-int/lit8 v0, v0, 0x3

    .line 179
    .line 180
    div-int/lit8 v0, v0, 0x2

    .line 181
    .line 182
    add-int/lit8 v0, v0, 0x1

    .line 183
    .line 184
    invoke-static {v0, v4}, Ljava/lang/Math;->max(II)I

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    goto :goto_2

    .line 189
    :cond_7
    iget-object v3, v2, Lcom/google/android/gms/internal/measurement/l6;->e:[Ljava/lang/Object;

    .line 190
    .line 191
    invoke-static {v3, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    iput-object v0, v2, Lcom/google/android/gms/internal/measurement/l6;->e:[Ljava/lang/Object;

    .line 196
    .line 197
    goto :goto_3

    .line 198
    :cond_8
    invoke-static {v3, v4}, Ljava/lang/Math;->max(II)I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    new-array v0, v0, [Ljava/lang/Object;

    .line 203
    .line 204
    iput-object v0, v2, Lcom/google/android/gms/internal/measurement/l6;->e:[Ljava/lang/Object;

    .line 205
    .line 206
    :cond_9
    :goto_3
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 207
    .line 208
    .line 209
    move-result v0

    .line 210
    instance-of v2, p0, Ljava/util/List;

    .line 211
    .line 212
    const/4 v3, 0x0

    .line 213
    if-eqz v2, :cond_b

    .line 214
    .line 215
    instance-of v2, p0, Ljava/util/RandomAccess;

    .line 216
    .line 217
    if-eqz v2, :cond_b

    .line 218
    .line 219
    check-cast p0, Ljava/util/List;

    .line 220
    .line 221
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 222
    .line 223
    .line 224
    move-result v2

    .line 225
    :goto_4
    if-ge v1, v2, :cond_d

    .line 226
    .line 227
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v4

    .line 231
    if-eqz v4, :cond_a

    .line 232
    .line 233
    invoke-interface {p1, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    add-int/lit8 v1, v1, 0x1

    .line 237
    .line 238
    goto :goto_4

    .line 239
    :cond_a
    invoke-static {v0, p1}, Lcom/google/android/gms/internal/measurement/k5;->a(ILjava/util/List;)V

    .line 240
    .line 241
    .line 242
    throw v3

    .line 243
    :cond_b
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 248
    .line 249
    .line 250
    move-result v1

    .line 251
    if-eqz v1, :cond_d

    .line 252
    .line 253
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    if-eqz v1, :cond_c

    .line 258
    .line 259
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    goto :goto_5

    .line 263
    :cond_c
    invoke-static {v0, p1}, Lcom/google/android/gms/internal/measurement/k5;->a(ILjava/util/List;)V

    .line 264
    .line 265
    .line 266
    throw v3

    .line 267
    :cond_d
    return-void

    .line 268
    :cond_e
    check-cast p0, Ljava/util/Collection;

    .line 269
    .line 270
    invoke-interface {p1, p0}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 271
    .line 272
    .line 273
    return-void
.end method


# virtual methods
.method public final a()[B
    .locals 5

    .line 1
    :try_start_0
    move-object v0, p0

    .line 2
    check-cast v0, Lcom/google/android/gms/internal/measurement/l5;

    .line 3
    .line 4
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/l5;->k()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    new-array v2, v1, [B

    .line 9
    .line 10
    new-instance v3, Lcom/google/android/gms/internal/measurement/b5;

    .line 11
    .line 12
    invoke-direct {v3, v1, v2}, Lcom/google/android/gms/internal/measurement/b5;-><init>(I[B)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v3}, Lcom/google/android/gms/internal/measurement/l5;->d(Lcom/google/android/gms/internal/measurement/b5;)V

    .line 16
    .line 17
    .line 18
    iget v0, v3, Lcom/google/android/gms/internal/measurement/b5;->d:I

    .line 19
    .line 20
    sub-int/2addr v1, v0

    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    return-object v2

    .line 24
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string v1, "Did not write as much data as expected."

    .line 27
    .line 28
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    :catch_0
    move-exception v0

    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance v1, Ljava/lang/RuntimeException;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    new-instance v3, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    add-int/lit8 v2, v2, 0x48

    .line 50
    .line 51
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 52
    .line 53
    .line 54
    const-string v2, "Serializing "

    .line 55
    .line 56
    const-string v4, " to a byte array threw an IOException (should never happen)."

    .line 57
    .line 58
    invoke-static {v3, v2, p0, v4}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-direct {v1, p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    throw v1
.end method

.method public abstract b(Lcom/google/android/gms/internal/measurement/n6;)I
.end method
