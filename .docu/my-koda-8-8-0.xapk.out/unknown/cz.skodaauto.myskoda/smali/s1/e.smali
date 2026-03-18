.class public final Ls1/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le3/n0;


# instance fields
.field public final a:Ls1/a;

.field public final b:Ls1/a;

.field public final c:Ls1/a;

.field public final d:Ls1/a;


# direct methods
.method public constructor <init>(Ls1/a;Ls1/a;Ls1/a;Ls1/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls1/e;->a:Ls1/a;

    .line 5
    .line 6
    iput-object p2, p0, Ls1/e;->b:Ls1/a;

    .line 7
    .line 8
    iput-object p3, p0, Ls1/e;->c:Ls1/a;

    .line 9
    .line 10
    iput-object p4, p0, Ls1/e;->d:Ls1/a;

    .line 11
    .line 12
    return-void
.end method

.method public static b(Ls1/e;Ls1/a;Ls1/a;Ls1/a;Ls1/a;I)Ls1/e;
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ls1/e;->a:Ls1/a;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 v0, p5, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ls1/e;->b:Ls1/a;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 v0, p5, 0x4

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ls1/e;->c:Ls1/a;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ls1/e;->d:Ls1/a;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    new-instance p0, Ls1/e;

    .line 29
    .line 30
    invoke-direct {p0, p1, p2, p3, p4}, Ls1/e;-><init>(Ls1/a;Ls1/a;Ls1/a;Ls1/a;)V

    .line 31
    .line 32
    .line 33
    return-object p0
.end method


# virtual methods
.method public final a(JLt4/m;Lt4/c;)Le3/g0;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    move-object/from16 v4, p4

    .line 8
    .line 9
    iget-object v5, v0, Ls1/e;->a:Ls1/a;

    .line 10
    .line 11
    invoke-interface {v5, v1, v2, v4}, Ls1/a;->a(JLt4/c;)F

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    iget-object v6, v0, Ls1/e;->b:Ls1/a;

    .line 16
    .line 17
    invoke-interface {v6, v1, v2, v4}, Ls1/a;->a(JLt4/c;)F

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    iget-object v7, v0, Ls1/e;->c:Ls1/a;

    .line 22
    .line 23
    invoke-interface {v7, v1, v2, v4}, Ls1/a;->a(JLt4/c;)F

    .line 24
    .line 25
    .line 26
    move-result v7

    .line 27
    iget-object v0, v0, Ls1/e;->d:Ls1/a;

    .line 28
    .line 29
    invoke-interface {v0, v1, v2, v4}, Ls1/a;->a(JLt4/c;)F

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    invoke-static {v1, v2}, Ld3/e;->c(J)F

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    add-float v8, v5, v0

    .line 38
    .line 39
    cmpl-float v9, v8, v4

    .line 40
    .line 41
    if-lez v9, :cond_0

    .line 42
    .line 43
    div-float v8, v4, v8

    .line 44
    .line 45
    mul-float/2addr v5, v8

    .line 46
    mul-float/2addr v0, v8

    .line 47
    :cond_0
    add-float v8, v6, v7

    .line 48
    .line 49
    cmpl-float v9, v8, v4

    .line 50
    .line 51
    if-lez v9, :cond_1

    .line 52
    .line 53
    div-float/2addr v4, v8

    .line 54
    mul-float/2addr v6, v4

    .line 55
    mul-float/2addr v7, v4

    .line 56
    :cond_1
    const/4 v4, 0x0

    .line 57
    cmpl-float v8, v5, v4

    .line 58
    .line 59
    if-ltz v8, :cond_2

    .line 60
    .line 61
    cmpl-float v8, v6, v4

    .line 62
    .line 63
    if-ltz v8, :cond_2

    .line 64
    .line 65
    cmpl-float v8, v7, v4

    .line 66
    .line 67
    if-ltz v8, :cond_2

    .line 68
    .line 69
    cmpl-float v8, v0, v4

    .line 70
    .line 71
    if-ltz v8, :cond_2

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    new-instance v8, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v9, "Corner size in Px can\'t be negative(topStart = "

    .line 77
    .line 78
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v9, ", topEnd = "

    .line 85
    .line 86
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string v9, ", bottomEnd = "

    .line 93
    .line 94
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v9, ", bottomStart = "

    .line 101
    .line 102
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v8, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string v9, ")!"

    .line 109
    .line 110
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    invoke-static {v8}, Lj1/b;->a(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    :goto_0
    add-float v8, v5, v6

    .line 121
    .line 122
    add-float/2addr v8, v7

    .line 123
    add-float/2addr v8, v0

    .line 124
    cmpg-float v4, v8, v4

    .line 125
    .line 126
    const-wide/16 v8, 0x0

    .line 127
    .line 128
    if-nez v4, :cond_3

    .line 129
    .line 130
    new-instance v0, Le3/e0;

    .line 131
    .line 132
    invoke-static {v8, v9, v1, v2}, Ljp/cf;->c(JJ)Ld3/c;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-direct {v0, v1}, Le3/e0;-><init>(Ld3/c;)V

    .line 137
    .line 138
    .line 139
    return-object v0

    .line 140
    :cond_3
    new-instance v4, Le3/f0;

    .line 141
    .line 142
    invoke-static {v8, v9, v1, v2}, Ljp/cf;->c(JJ)Ld3/c;

    .line 143
    .line 144
    .line 145
    move-result-object v10

    .line 146
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 147
    .line 148
    if-ne v3, v1, :cond_4

    .line 149
    .line 150
    move v2, v5

    .line 151
    goto :goto_1

    .line 152
    :cond_4
    move v2, v6

    .line 153
    :goto_1
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 154
    .line 155
    .line 156
    move-result v8

    .line 157
    int-to-long v8, v8

    .line 158
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 159
    .line 160
    .line 161
    move-result v2

    .line 162
    int-to-long v11, v2

    .line 163
    const/16 v2, 0x20

    .line 164
    .line 165
    shl-long/2addr v8, v2

    .line 166
    const-wide v13, 0xffffffffL

    .line 167
    .line 168
    .line 169
    .line 170
    .line 171
    and-long/2addr v11, v13

    .line 172
    or-long/2addr v11, v8

    .line 173
    if-ne v3, v1, :cond_5

    .line 174
    .line 175
    move v5, v6

    .line 176
    :cond_5
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 177
    .line 178
    .line 179
    move-result v6

    .line 180
    int-to-long v8, v6

    .line 181
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    int-to-long v5, v5

    .line 186
    shl-long/2addr v8, v2

    .line 187
    and-long/2addr v5, v13

    .line 188
    or-long/2addr v5, v8

    .line 189
    if-ne v3, v1, :cond_6

    .line 190
    .line 191
    move v8, v7

    .line 192
    goto :goto_2

    .line 193
    :cond_6
    move v8, v0

    .line 194
    :goto_2
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 195
    .line 196
    .line 197
    move-result v9

    .line 198
    move-wide/from16 p0, v13

    .line 199
    .line 200
    int-to-long v13, v9

    .line 201
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 202
    .line 203
    .line 204
    move-result v8

    .line 205
    int-to-long v8, v8

    .line 206
    shl-long/2addr v13, v2

    .line 207
    and-long v8, v8, p0

    .line 208
    .line 209
    or-long v15, v13, v8

    .line 210
    .line 211
    if-ne v3, v1, :cond_7

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_7
    move v0, v7

    .line 215
    :goto_3
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    int-to-long v7, v1

    .line 220
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    int-to-long v0, v0

    .line 225
    shl-long v2, v7, v2

    .line 226
    .line 227
    and-long v0, v0, p0

    .line 228
    .line 229
    or-long v17, v2, v0

    .line 230
    .line 231
    move-wide v13, v5

    .line 232
    invoke-static/range {v10 .. v18}, Ljp/df;->a(Ld3/c;JJJJ)Ld3/d;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    invoke-direct {v4, v0}, Le3/f0;-><init>(Ld3/d;)V

    .line 237
    .line 238
    .line 239
    return-object v4
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ls1/e;

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
    check-cast p1, Ls1/e;

    .line 12
    .line 13
    iget-object v1, p1, Ls1/e;->a:Ls1/a;

    .line 14
    .line 15
    iget-object v3, p0, Ls1/e;->a:Ls1/a;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Ls1/e;->b:Ls1/a;

    .line 25
    .line 26
    iget-object v3, p1, Ls1/e;->b:Ls1/a;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Ls1/e;->c:Ls1/a;

    .line 36
    .line 37
    iget-object v3, p1, Ls1/e;->c:Ls1/a;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object p0, p0, Ls1/e;->d:Ls1/a;

    .line 47
    .line 48
    iget-object p1, p1, Ls1/e;->d:Ls1/a;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Ls1/e;->a:Ls1/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Ls1/e;->b:Ls1/a;

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
    iget-object v0, p0, Ls1/e;->c:Ls1/a;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v1

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object p0, p0, Ls1/e;->d:Ls1/a;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-int/2addr p0, v0

    .line 34
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "RoundedCornerShape(topStart = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ls1/e;->a:Ls1/a;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", topEnd = "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ls1/e;->b:Ls1/a;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", bottomEnd = "

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ls1/e;->c:Ls1/a;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", bottomStart = "

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Ls1/e;->d:Ls1/a;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const/16 p0, 0x29

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
