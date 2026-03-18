.class public final Lf2/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/v;


# instance fields
.field public final d:J

.field public final e:Lt4/c;

.field public final f:Lay0/n;


# direct methods
.method public constructor <init>(JLt4/c;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lf2/w;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Lf2/w;->e:Lt4/c;

    .line 7
    .line 8
    iput-object p4, p0, Lf2/w;->f:Lay0/n;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final F(Lt4/k;JLt4/m;J)J
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    sget v3, Lf2/d0;->b:F

    .line 8
    .line 9
    iget-object v4, v0, Lf2/w;->e:Lt4/c;

    .line 10
    .line 11
    invoke-interface {v4, v3}, Lt4/c;->Q(F)I

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    iget-wide v5, v0, Lf2/w;->d:J

    .line 16
    .line 17
    const/16 v7, 0x20

    .line 18
    .line 19
    shr-long v8, v5, v7

    .line 20
    .line 21
    long-to-int v8, v8

    .line 22
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 23
    .line 24
    .line 25
    move-result v8

    .line 26
    invoke-interface {v4, v8}, Lt4/c;->Q(F)I

    .line 27
    .line 28
    .line 29
    move-result v8

    .line 30
    sget-object v9, Lt4/m;->d:Lt4/m;

    .line 31
    .line 32
    if-ne v2, v9, :cond_0

    .line 33
    .line 34
    const/4 v10, 0x1

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v10, -0x1

    .line 37
    :goto_0
    mul-int/2addr v8, v10

    .line 38
    const-wide v10, 0xffffffffL

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    and-long/2addr v5, v10

    .line 44
    long-to-int v5, v5

    .line 45
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    invoke-interface {v4, v5}, Lt4/c;->Q(F)I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    iget v5, v1, Lt4/k;->a:I

    .line 54
    .line 55
    iget v6, v1, Lt4/k;->c:I

    .line 56
    .line 57
    add-int/2addr v5, v8

    .line 58
    shr-long v12, p5, v7

    .line 59
    .line 60
    long-to-int v12, v12

    .line 61
    sub-int v13, v6, v12

    .line 62
    .line 63
    add-int/2addr v13, v8

    .line 64
    shr-long v14, p2, v7

    .line 65
    .line 66
    long-to-int v8, v14

    .line 67
    sub-int v14, v8, v12

    .line 68
    .line 69
    const/4 v15, 0x0

    .line 70
    if-ne v2, v9, :cond_2

    .line 71
    .line 72
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    iget v6, v1, Lt4/k;->a:I

    .line 81
    .line 82
    if-ltz v6, :cond_1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_1
    move v14, v15

    .line 86
    :goto_1
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 87
    .line 88
    .line 89
    move-result-object v6

    .line 90
    filled-new-array {v2, v5, v6}, [Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-static {v2}, Lmx0/n;->c([Ljava/lang/Object;)Lky0/j;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    goto :goto_2

    .line 99
    :cond_2
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    if-gt v6, v8, :cond_3

    .line 108
    .line 109
    move v14, v15

    .line 110
    :cond_3
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    filled-new-array {v2, v5, v6}, [Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    invoke-static {v2}, Lmx0/n;->c([Ljava/lang/Object;)Lky0/j;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    :goto_2
    invoke-interface {v2}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    :cond_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v5

    .line 130
    const/4 v6, 0x0

    .line 131
    if-eqz v5, :cond_5

    .line 132
    .line 133
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    move-object v9, v5

    .line 138
    check-cast v9, Ljava/lang/Number;

    .line 139
    .line 140
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 141
    .line 142
    .line 143
    move-result v9

    .line 144
    if-ltz v9, :cond_4

    .line 145
    .line 146
    add-int/2addr v9, v12

    .line 147
    if-gt v9, v8, :cond_4

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :cond_5
    move-object v5, v6

    .line 151
    :goto_3
    check-cast v5, Ljava/lang/Integer;

    .line 152
    .line 153
    if-eqz v5, :cond_6

    .line 154
    .line 155
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 156
    .line 157
    .line 158
    move-result v13

    .line 159
    :cond_6
    iget v2, v1, Lt4/k;->d:I

    .line 160
    .line 161
    add-int/2addr v2, v4

    .line 162
    invoke-static {v2, v3}, Ljava/lang/Math;->max(II)I

    .line 163
    .line 164
    .line 165
    move-result v2

    .line 166
    iget v5, v1, Lt4/k;->b:I

    .line 167
    .line 168
    and-long v8, p5, v10

    .line 169
    .line 170
    long-to-int v8, v8

    .line 171
    sub-int v9, v5, v8

    .line 172
    .line 173
    add-int/2addr v9, v4

    .line 174
    div-int/lit8 v14, v8, 0x2

    .line 175
    .line 176
    sub-int/2addr v5, v14

    .line 177
    add-int/2addr v5, v4

    .line 178
    and-long v14, p2, v10

    .line 179
    .line 180
    long-to-int v4, v14

    .line 181
    sub-int v14, v4, v8

    .line 182
    .line 183
    sub-int/2addr v14, v3

    .line 184
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object v2

    .line 188
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 189
    .line 190
    .line 191
    move-result-object v15

    .line 192
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object v5

    .line 196
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 197
    .line 198
    .line 199
    move-result-object v14

    .line 200
    filled-new-array {v2, v15, v5, v14}, [Ljava/lang/Integer;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    invoke-static {v2}, Lmx0/n;->c([Ljava/lang/Object;)Lky0/j;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    invoke-interface {v2}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 209
    .line 210
    .line 211
    move-result-object v2

    .line 212
    :cond_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    if-eqz v5, :cond_8

    .line 217
    .line 218
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v5

    .line 222
    move-object v14, v5

    .line 223
    check-cast v14, Ljava/lang/Number;

    .line 224
    .line 225
    invoke-virtual {v14}, Ljava/lang/Number;->intValue()I

    .line 226
    .line 227
    .line 228
    move-result v14

    .line 229
    if-lt v14, v3, :cond_7

    .line 230
    .line 231
    add-int/2addr v14, v8

    .line 232
    sub-int v15, v4, v3

    .line 233
    .line 234
    if-gt v14, v15, :cond_7

    .line 235
    .line 236
    move-object v6, v5

    .line 237
    :cond_8
    check-cast v6, Ljava/lang/Integer;

    .line 238
    .line 239
    if-eqz v6, :cond_9

    .line 240
    .line 241
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 242
    .line 243
    .line 244
    move-result v9

    .line 245
    :cond_9
    new-instance v2, Lt4/k;

    .line 246
    .line 247
    add-int/2addr v12, v13

    .line 248
    add-int/2addr v8, v9

    .line 249
    invoke-direct {v2, v13, v9, v12, v8}, Lt4/k;-><init>(IIII)V

    .line 250
    .line 251
    .line 252
    iget-object v0, v0, Lf2/w;->f:Lay0/n;

    .line 253
    .line 254
    invoke-interface {v0, v1, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    int-to-long v0, v13

    .line 258
    shl-long/2addr v0, v7

    .line 259
    int-to-long v2, v9

    .line 260
    and-long/2addr v2, v10

    .line 261
    or-long/2addr v0, v2

    .line 262
    return-wide v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lf2/w;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lf2/w;

    .line 12
    .line 13
    iget-wide v3, p0, Lf2/w;->d:J

    .line 14
    .line 15
    iget-wide v5, p1, Lf2/w;->d:J

    .line 16
    .line 17
    cmp-long v1, v3, v5

    .line 18
    .line 19
    if-nez v1, :cond_4

    .line 20
    .line 21
    iget-object v1, p0, Lf2/w;->e:Lt4/c;

    .line 22
    .line 23
    iget-object v3, p1, Lf2/w;->e:Lt4/c;

    .line 24
    .line 25
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_2

    .line 30
    .line 31
    return v2

    .line 32
    :cond_2
    iget-object p0, p0, Lf2/w;->f:Lay0/n;

    .line 33
    .line 34
    iget-object p1, p1, Lf2/w;->f:Lay0/n;

    .line 35
    .line 36
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-nez p0, :cond_3

    .line 41
    .line 42
    return v2

    .line 43
    :cond_3
    return v0

    .line 44
    :cond_4
    return v2
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lf2/w;->d:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lf2/w;->e:Lt4/c;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object p0, p0, Lf2/w;->f:Lay0/n;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DropdownMenuPositionProvider(contentOffset="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lf2/w;->d:J

    .line 9
    .line 10
    invoke-static {v1, v2}, Lt4/g;->a(J)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", density="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lf2/w;->e:Lt4/c;

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v1, ", onPositionCalculated="

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lf2/w;->f:Lay0/n;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const/16 p0, 0x29

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
