.class public final Ll9/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll9/d;


# static fields
.field public static final f:Lhr/p;


# instance fields
.field public final d:Lhr/h0;

.field public final e:[J


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lhr/v0;->e:Lhr/v0;

    .line 2
    .line 3
    new-instance v1, Lj9/d;

    .line 4
    .line 5
    const/16 v2, 0x8

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lj9/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Lhr/p;

    .line 11
    .line 12
    invoke-direct {v2, v1, v0}, Lhr/p;-><init>(Lgr/e;Lhr/w0;)V

    .line 13
    .line 14
    .line 15
    sput-object v2, Ll9/b;->f:Lhr/p;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lhr/x0;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    iget v2, v1, Lhr/x0;->g:I

    .line 9
    .line 10
    const/4 v3, 0x2

    .line 11
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    const/4 v8, 0x0

    .line 17
    const/4 v9, 0x1

    .line 18
    if-ne v2, v9, :cond_5

    .line 19
    .line 20
    invoke-virtual {v1, v8}, Lhr/h0;->s(I)Lhr/f0;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Lhr/f0;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v1}, Lhr/f0;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v10

    .line 32
    if-nez v10, :cond_2

    .line 33
    .line 34
    check-cast v2, Ll9/a;

    .line 35
    .line 36
    iget-wide v10, v2, Ll9/a;->b:J

    .line 37
    .line 38
    iget-object v1, v2, Ll9/a;->a:Lhr/h0;

    .line 39
    .line 40
    iget-wide v12, v2, Ll9/a;->c:J

    .line 41
    .line 42
    cmp-long v2, v10, v6

    .line 43
    .line 44
    if-nez v2, :cond_0

    .line 45
    .line 46
    const-wide/16 v4, 0x0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    move-wide v4, v10

    .line 50
    :goto_0
    cmp-long v2, v12, v6

    .line 51
    .line 52
    if-nez v2, :cond_1

    .line 53
    .line 54
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    iput-object v1, v0, Ll9/b;->d:Lhr/h0;

    .line 59
    .line 60
    new-array v1, v9, [J

    .line 61
    .line 62
    aput-wide v4, v1, v8

    .line 63
    .line 64
    iput-object v1, v0, Ll9/b;->e:[J

    .line 65
    .line 66
    return-void

    .line 67
    :cond_1
    sget-object v2, Lhr/h0;->e:Lhr/f0;

    .line 68
    .line 69
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 70
    .line 71
    invoke-static {v1, v2}, Lhr/h0;->v(Ljava/lang/Object;Ljava/lang/Object;)Lhr/x0;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    iput-object v1, v0, Ll9/b;->d:Lhr/h0;

    .line 76
    .line 77
    add-long/2addr v12, v4

    .line 78
    new-array v1, v3, [J

    .line 79
    .line 80
    aput-wide v4, v1, v8

    .line 81
    .line 82
    aput-wide v12, v1, v9

    .line 83
    .line 84
    iput-object v1, v0, Ll9/b;->e:[J

    .line 85
    .line 86
    return-void

    .line 87
    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string v3, "expected one element but was: <"

    .line 90
    .line 91
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    :goto_1
    const/4 v2, 0x4

    .line 98
    if-ge v8, v2, :cond_3

    .line 99
    .line 100
    invoke-virtual {v1}, Lhr/f0;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-eqz v2, :cond_3

    .line 105
    .line 106
    const-string v2, ", "

    .line 107
    .line 108
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v1}, Lhr/f0;->next()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    add-int/lit8 v8, v8, 0x1

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_3
    invoke-virtual {v1}, Lhr/f0;->hasNext()Z

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    if-eqz v1, :cond_4

    .line 126
    .line 127
    const-string v1, ", ..."

    .line 128
    .line 129
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    :cond_4
    const/16 v1, 0x3e

    .line 133
    .line 134
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 138
    .line 139
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw v1

    .line 147
    :cond_5
    mul-int/2addr v2, v3

    .line 148
    new-array v2, v2, [J

    .line 149
    .line 150
    iput-object v2, v0, Ll9/b;->e:[J

    .line 151
    .line 152
    const-wide v9, 0x7fffffffffffffffL

    .line 153
    .line 154
    .line 155
    .line 156
    .line 157
    invoke-static {v2, v9, v10}, Ljava/util/Arrays;->fill([JJ)V

    .line 158
    .line 159
    .line 160
    new-instance v2, Ljava/util/ArrayList;

    .line 161
    .line 162
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 163
    .line 164
    .line 165
    sget-object v3, Ll9/b;->f:Lhr/p;

    .line 166
    .line 167
    invoke-static {v3, v1}, Lhr/h0;->x(Lhr/w0;Ljava/util/List;)Lhr/x0;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    move v3, v8

    .line 172
    :goto_2
    iget v9, v1, Lhr/x0;->g:I

    .line 173
    .line 174
    if-ge v8, v9, :cond_b

    .line 175
    .line 176
    invoke-virtual {v1, v8}, Lhr/x0;->get(I)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v9

    .line 180
    check-cast v9, Ll9/a;

    .line 181
    .line 182
    iget-wide v10, v9, Ll9/a;->b:J

    .line 183
    .line 184
    iget-wide v12, v9, Ll9/a;->c:J

    .line 185
    .line 186
    iget-object v9, v9, Ll9/a;->a:Lhr/h0;

    .line 187
    .line 188
    cmp-long v14, v10, v6

    .line 189
    .line 190
    if-nez v14, :cond_6

    .line 191
    .line 192
    const-wide/16 v10, 0x0

    .line 193
    .line 194
    :cond_6
    add-long v14, v10, v12

    .line 195
    .line 196
    if-eqz v3, :cond_7

    .line 197
    .line 198
    iget-object v4, v0, Ll9/b;->e:[J

    .line 199
    .line 200
    add-int/lit8 v5, v3, -0x1

    .line 201
    .line 202
    aget-wide v16, v4, v5

    .line 203
    .line 204
    cmp-long v4, v16, v10

    .line 205
    .line 206
    if-gez v4, :cond_8

    .line 207
    .line 208
    :cond_7
    move-wide/from16 v16, v6

    .line 209
    .line 210
    goto :goto_3

    .line 211
    :cond_8
    if-nez v4, :cond_9

    .line 212
    .line 213
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    check-cast v4, Lhr/h0;

    .line 218
    .line 219
    invoke-virtual {v4}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 220
    .line 221
    .line 222
    move-result v4

    .line 223
    if-eqz v4, :cond_9

    .line 224
    .line 225
    invoke-virtual {v2, v5, v9}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-wide/from16 v16, v6

    .line 229
    .line 230
    goto :goto_4

    .line 231
    :cond_9
    const-string v4, "CuesWithTimingSubtitle"

    .line 232
    .line 233
    move-wide/from16 v16, v6

    .line 234
    .line 235
    const-string v6, "Truncating unsupported overlapping cues."

    .line 236
    .line 237
    invoke-static {v4, v6}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    iget-object v4, v0, Ll9/b;->e:[J

    .line 241
    .line 242
    aput-wide v10, v4, v5

    .line 243
    .line 244
    invoke-virtual {v2, v5, v9}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    goto :goto_4

    .line 248
    :goto_3
    iget-object v4, v0, Ll9/b;->e:[J

    .line 249
    .line 250
    add-int/lit8 v5, v3, 0x1

    .line 251
    .line 252
    aput-wide v10, v4, v3

    .line 253
    .line 254
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move v3, v5

    .line 258
    :goto_4
    cmp-long v4, v12, v16

    .line 259
    .line 260
    if-eqz v4, :cond_a

    .line 261
    .line 262
    iget-object v4, v0, Ll9/b;->e:[J

    .line 263
    .line 264
    add-int/lit8 v5, v3, 0x1

    .line 265
    .line 266
    aput-wide v14, v4, v3

    .line 267
    .line 268
    sget-object v3, Lhr/x0;->h:Lhr/x0;

    .line 269
    .line 270
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move v3, v5

    .line 274
    :cond_a
    add-int/lit8 v8, v8, 0x1

    .line 275
    .line 276
    move-wide/from16 v6, v16

    .line 277
    .line 278
    goto :goto_2

    .line 279
    :cond_b
    invoke-static {v2}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    iput-object v1, v0, Ll9/b;->d:Lhr/h0;

    .line 284
    .line 285
    return-void
.end method


# virtual methods
.method public final e(J)I
    .locals 2

    .line 1
    iget-object v0, p0, Ll9/b;->e:[J

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v0, p1, p2, v1}, Lw7/w;->a([JJZ)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iget-object p0, p0, Ll9/b;->d:Lhr/h0;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->size()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-ge p1, p0, :cond_0

    .line 15
    .line 16
    return p1

    .line 17
    :cond_0
    const/4 p0, -0x1

    .line 18
    return p0
.end method

.method public final f(J)Ljava/util/List;
    .locals 2

    .line 1
    iget-object v0, p0, Ll9/b;->e:[J

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v0, p1, p2, v1}, Lw7/w;->d([JJZ)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    const/4 p2, -0x1

    .line 9
    if-ne p1, p2, :cond_0

    .line 10
    .line 11
    sget-object p0, Lhr/h0;->e:Lhr/f0;

    .line 12
    .line 13
    sget-object p0, Lhr/x0;->h:Lhr/x0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    iget-object p0, p0, Ll9/b;->d:Lhr/h0;

    .line 17
    .line 18
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lhr/h0;

    .line 23
    .line 24
    return-object p0
.end method

.method public final i(I)J
    .locals 1

    .line 1
    iget-object v0, p0, Ll9/b;->d:Lhr/h0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ge p1, v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 v0, 0x0

    .line 12
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Ll9/b;->e:[J

    .line 16
    .line 17
    aget-wide p0, p0, p1

    .line 18
    .line 19
    return-wide p0
.end method

.method public final k()I
    .locals 0

    .line 1
    iget-object p0, p0, Ll9/b;->d:Lhr/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
