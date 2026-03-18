.class public final Lvp/p0;
.super Lvp/n1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:C

.field public h:J

.field public i:Ljava/lang/String;

.field public final j:Lvp/n0;

.field public final k:Lvp/n0;

.field public final l:Lvp/n0;

.field public final m:Lvp/n0;

.field public final n:Lvp/n0;

.field public final o:Lvp/n0;

.field public final p:Lvp/n0;

.field public final q:Lvp/n0;

.field public final r:Lvp/n0;


# direct methods
.method public constructor <init>(Lvp/g1;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1}, Lvp/n1;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    iput-char p1, p0, Lvp/p0;->g:C

    .line 6
    .line 7
    const-wide/16 v0, -0x1

    .line 8
    .line 9
    iput-wide v0, p0, Lvp/p0;->h:J

    .line 10
    .line 11
    new-instance v0, Lvp/n0;

    .line 12
    .line 13
    const/4 v1, 0x6

    .line 14
    invoke-direct {v0, p0, v1, p1, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lvp/p0;->j:Lvp/n0;

    .line 18
    .line 19
    new-instance v0, Lvp/n0;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-direct {v0, p0, v1, v2, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lvp/p0;->k:Lvp/n0;

    .line 26
    .line 27
    new-instance v0, Lvp/n0;

    .line 28
    .line 29
    invoke-direct {v0, p0, v1, p1, v2}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lvp/p0;->l:Lvp/n0;

    .line 33
    .line 34
    new-instance v0, Lvp/n0;

    .line 35
    .line 36
    const/4 v1, 0x5

    .line 37
    invoke-direct {v0, p0, v1, p1, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lvp/p0;->m:Lvp/n0;

    .line 41
    .line 42
    new-instance v0, Lvp/n0;

    .line 43
    .line 44
    invoke-direct {v0, p0, v1, v2, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lvp/p0;->n:Lvp/n0;

    .line 48
    .line 49
    new-instance v0, Lvp/n0;

    .line 50
    .line 51
    invoke-direct {v0, p0, v1, p1, v2}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Lvp/p0;->o:Lvp/n0;

    .line 55
    .line 56
    new-instance v0, Lvp/n0;

    .line 57
    .line 58
    const/4 v1, 0x4

    .line 59
    invoke-direct {v0, p0, v1, p1, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 60
    .line 61
    .line 62
    iput-object v0, p0, Lvp/p0;->p:Lvp/n0;

    .line 63
    .line 64
    new-instance v0, Lvp/n0;

    .line 65
    .line 66
    const/4 v1, 0x3

    .line 67
    invoke-direct {v0, p0, v1, p1, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 68
    .line 69
    .line 70
    iput-object v0, p0, Lvp/p0;->q:Lvp/n0;

    .line 71
    .line 72
    new-instance v0, Lvp/n0;

    .line 73
    .line 74
    const/4 v1, 0x2

    .line 75
    invoke-direct {v0, p0, v1, p1, p1}, Lvp/n0;-><init>(Lvp/p0;IZZ)V

    .line 76
    .line 77
    .line 78
    iput-object v0, p0, Lvp/p0;->r:Lvp/n0;

    .line 79
    .line 80
    return-void
.end method

.method public static i0(Ljava/lang/String;)Lvp/o0;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    new-instance v0, Lvp/o0;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lvp/o0;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public static l0(ZLjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p2, p0}, Lvp/p0;->m0(Ljava/lang/Object;Z)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-static {p3, p0}, Lvp/p0;->m0(Ljava/lang/Object;Z)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p3

    .line 9
    invoke-static {p4, p0}, Lvp/p0;->m0(Ljava/lang/Object;Z)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance p4, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    invoke-direct {p4}, Ljava/lang/StringBuilder;-><init>()V

    .line 16
    .line 17
    .line 18
    const-string v0, ""

    .line 19
    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    move-object p1, v0

    .line 23
    :cond_0
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_1

    .line 28
    .line 29
    invoke-virtual {p4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v0, ": "

    .line 33
    .line 34
    :cond_1
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    const-string v1, ", "

    .line 39
    .line 40
    if-nez p1, :cond_2

    .line 41
    .line 42
    invoke-virtual {p4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    move-object v0, v1

    .line 49
    :cond_2
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    if-nez p1, :cond_3

    .line 54
    .line 55
    invoke-virtual {p4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    move-object v1, v0

    .line 63
    :goto_0
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-nez p1, :cond_4

    .line 68
    .line 69
    invoke-virtual {p4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    :cond_4
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0
.end method

.method public static m0(Ljava/lang/Object;Z)Ljava/lang/String;
    .locals 10

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    instance-of v1, p0, Ljava/lang/Integer;

    .line 7
    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p0, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    int-to-long v1, p0

    .line 17
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :cond_1
    instance-of v1, p0, Ljava/lang/Long;

    .line 22
    .line 23
    const/4 v2, -0x1

    .line 24
    const-string v3, "-"

    .line 25
    .line 26
    const/4 v4, 0x0

    .line 27
    if-eqz v1, :cond_5

    .line 28
    .line 29
    if-nez p1, :cond_2

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_2
    move-object p1, p0

    .line 37
    check-cast p1, Ljava/lang/Long;

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 40
    .line 41
    .line 42
    move-result-wide v5

    .line 43
    invoke-static {v5, v6}, Ljava/lang/Math;->abs(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v5

    .line 47
    const-wide/16 v7, 0x64

    .line 48
    .line 49
    cmp-long v1, v5, v7

    .line 50
    .line 51
    if-gez v1, :cond_3

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 67
    .line 68
    .line 69
    move-result-wide v4

    .line 70
    invoke-static {v4, v5}, Ljava/lang/Math;->abs(J)J

    .line 71
    .line 72
    .line 73
    move-result-wide v4

    .line 74
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    add-int/2addr v1, v2

    .line 83
    int-to-double v1, v1

    .line 84
    const-wide/high16 v4, 0x4024000000000000L    # 10.0

    .line 85
    .line 86
    invoke-static {v4, v5, v1, v2}, Ljava/lang/Math;->pow(DD)D

    .line 87
    .line 88
    .line 89
    move-result-wide v1

    .line 90
    invoke-static {v1, v2}, Ljava/lang/Math;->round(D)J

    .line 91
    .line 92
    .line 93
    move-result-wide v1

    .line 94
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    int-to-double v6, p1

    .line 99
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 100
    .line 101
    .line 102
    move-result-wide v4

    .line 103
    const-wide/high16 v6, -0x4010000000000000L    # -1.0

    .line 104
    .line 105
    add-double/2addr v4, v6

    .line 106
    invoke-static {v4, v5}, Ljava/lang/Math;->round(D)J

    .line 107
    .line 108
    .line 109
    move-result-wide v4

    .line 110
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    const/16 v6, 0x2d

    .line 119
    .line 120
    if-ne p0, v6, :cond_4

    .line 121
    .line 122
    move-object v0, v3

    .line 123
    :cond_4
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    add-int/2addr p0, p1

    .line 128
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    new-instance v3, Ljava/lang/StringBuilder;

    .line 137
    .line 138
    add-int/lit8 p0, p0, 0x3

    .line 139
    .line 140
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    add-int/2addr v6, p0

    .line 145
    add-int/2addr v6, p1

    .line 146
    invoke-direct {v3, v6}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v3, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    const-string p0, "..."

    .line 156
    .line 157
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v3, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    return-object p0

    .line 171
    :cond_5
    instance-of v1, p0, Ljava/lang/Boolean;

    .line 172
    .line 173
    if-eqz v1, :cond_6

    .line 174
    .line 175
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    return-object p0

    .line 180
    :cond_6
    instance-of v1, p0, Ljava/lang/Throwable;

    .line 181
    .line 182
    if-eqz v1, :cond_f

    .line 183
    .line 184
    check-cast p0, Ljava/lang/Throwable;

    .line 185
    .line 186
    new-instance v1, Ljava/lang/StringBuilder;

    .line 187
    .line 188
    if-eqz p1, :cond_7

    .line 189
    .line 190
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    move-result-object p1

    .line 194
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    goto :goto_0

    .line 199
    :cond_7
    invoke-virtual {p0}, Ljava/lang/Throwable;->toString()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    :goto_0
    invoke-direct {v1, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    const-class p1, Lvp/g1;

    .line 207
    .line 208
    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 213
    .line 214
    .line 215
    move-result v3

    .line 216
    const/16 v5, 0x2e

    .line 217
    .line 218
    if-eqz v3, :cond_8

    .line 219
    .line 220
    :goto_1
    move-object p1, v0

    .line 221
    goto :goto_2

    .line 222
    :cond_8
    invoke-virtual {p1, v5}, Ljava/lang/String;->lastIndexOf(I)I

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    if-ne v3, v2, :cond_9

    .line 227
    .line 228
    goto :goto_1

    .line 229
    :cond_9
    invoke-virtual {p1, v4, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    :goto_2
    invoke-virtual {p0}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    array-length v3, p0

    .line 238
    move v6, v4

    .line 239
    :goto_3
    if-ge v6, v3, :cond_e

    .line 240
    .line 241
    aget-object v7, p0, v6

    .line 242
    .line 243
    invoke-virtual {v7}, Ljava/lang/StackTraceElement;->isNativeMethod()Z

    .line 244
    .line 245
    .line 246
    move-result v8

    .line 247
    if-eqz v8, :cond_a

    .line 248
    .line 249
    goto :goto_6

    .line 250
    :cond_a
    invoke-virtual {v7}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v8

    .line 254
    if-eqz v8, :cond_d

    .line 255
    .line 256
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 257
    .line 258
    .line 259
    move-result v9

    .line 260
    if-eqz v9, :cond_b

    .line 261
    .line 262
    :goto_4
    move-object v8, v0

    .line 263
    goto :goto_5

    .line 264
    :cond_b
    invoke-virtual {v8, v5}, Ljava/lang/String;->lastIndexOf(I)I

    .line 265
    .line 266
    .line 267
    move-result v9

    .line 268
    if-ne v9, v2, :cond_c

    .line 269
    .line 270
    goto :goto_4

    .line 271
    :cond_c
    invoke-virtual {v8, v4, v9}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v8

    .line 275
    :goto_5
    invoke-virtual {v8, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v8

    .line 279
    if-eqz v8, :cond_d

    .line 280
    .line 281
    const-string p0, ": "

    .line 282
    .line 283
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 287
    .line 288
    .line 289
    goto :goto_7

    .line 290
    :cond_d
    :goto_6
    add-int/lit8 v6, v6, 0x1

    .line 291
    .line 292
    goto :goto_3

    .line 293
    :cond_e
    :goto_7
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    return-object p0

    .line 298
    :cond_f
    instance-of v0, p0, Lvp/o0;

    .line 299
    .line 300
    if-eqz v0, :cond_10

    .line 301
    .line 302
    check-cast p0, Lvp/o0;

    .line 303
    .line 304
    iget-object p0, p0, Lvp/o0;->a:Ljava/lang/String;

    .line 305
    .line 306
    return-object p0

    .line 307
    :cond_10
    if-eqz p1, :cond_11

    .line 308
    .line 309
    return-object v3

    .line 310
    :cond_11
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    return-object p0
.end method


# virtual methods
.method public final b0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final e0()Lvp/n0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f0()Lvp/n0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g0()Lvp/n0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/p0;->q:Lvp/n0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h0()Lvp/n0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j0(IZZLjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 7

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Lvp/p0;->k0()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-static {p2, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    const/4 p2, 0x0

    .line 14
    invoke-static {p2, p4, p5, p6, p7}, Lvp/p0;->l0(ZLjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-virtual {p0}, Lvp/p0;->k0()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {p1, v0, p2}, Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    :cond_0
    if-nez p3, :cond_4

    .line 26
    .line 27
    const/4 p2, 0x5

    .line 28
    if-lt p1, p2, :cond_4

    .line 29
    .line 30
    invoke-static {p4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p2, Lvp/g1;

    .line 36
    .line 37
    iget-object p2, p2, Lvp/g1;->j:Lvp/e1;

    .line 38
    .line 39
    const/4 p3, 0x6

    .line 40
    if-nez p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p0}, Lvp/p0;->k0()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const-string p1, "Scheduler not set. Not logging error/warn"

    .line 47
    .line 48
    invoke-static {p3, p0, p1}, Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_1
    iget-boolean v0, p2, Lvp/n1;->f:Z

    .line 53
    .line 54
    if-nez v0, :cond_2

    .line 55
    .line 56
    invoke-virtual {p0}, Lvp/p0;->k0()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    const-string p1, "Scheduler not initialized. Not logging error/warn"

    .line 61
    .line 62
    invoke-static {p3, p0, p1}, Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_2
    const/16 p3, 0x9

    .line 67
    .line 68
    if-lt p1, p3, :cond_3

    .line 69
    .line 70
    const/16 p1, 0x8

    .line 71
    .line 72
    :cond_3
    move v2, p1

    .line 73
    new-instance v0, Lvp/m0;

    .line 74
    .line 75
    move-object v1, p0

    .line 76
    move-object v3, p4

    .line 77
    move-object v4, p5

    .line 78
    move-object v5, p6

    .line 79
    move-object v6, p7

    .line 80
    invoke-direct/range {v0 .. v6}, Lvp/m0;-><init>(Lvp/p0;ILjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p2, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 84
    .line 85
    .line 86
    :cond_4
    return-void
.end method

.method public final k0()Ljava/lang/String;
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lvp/p0;->i:Ljava/lang/String;

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvp/g1;

    .line 9
    .line 10
    iget-object v0, v0, Lvp/g1;->g:Lvp/h;

    .line 11
    .line 12
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lvp/g1;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const-string v0, "FA"

    .line 20
    .line 21
    iput-object v0, p0, Lvp/p0;->i:Ljava/lang/String;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    :goto_0
    iget-object v0, p0, Lvp/p0;->i:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lvp/p0;->i:Ljava/lang/String;

    .line 32
    .line 33
    monitor-exit p0

    .line 34
    return-object v0

    .line 35
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    throw v0
.end method
