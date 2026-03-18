.class public final Lqn/l;
.super Lqn/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Integer;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqn/l;->a:Ljava/lang/Integer;

    .line 5
    .line 6
    iput-object p2, p0, Lqn/l;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lqn/l;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lqn/l;->d:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lqn/l;->e:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lqn/l;->f:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lqn/l;->g:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lqn/l;->h:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p9, p0, Lqn/l;->i:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p10, p0, Lqn/l;->j:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p11, p0, Lqn/l;->k:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p12, p0, Lqn/l;->l:Ljava/lang/String;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lqn/a;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_d

    .line 9
    .line 10
    check-cast p1, Lqn/a;

    .line 11
    .line 12
    iget-object v1, p0, Lqn/l;->a:Ljava/lang/Integer;

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    check-cast v1, Lqn/l;

    .line 18
    .line 19
    iget-object v1, v1, Lqn/l;->a:Ljava/lang/Integer;

    .line 20
    .line 21
    if-nez v1, :cond_d

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    move-object v3, p1

    .line 25
    check-cast v3, Lqn/l;

    .line 26
    .line 27
    iget-object v3, v3, Lqn/l;->a:Ljava/lang/Integer;

    .line 28
    .line 29
    invoke-virtual {v1, v3}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_d

    .line 34
    .line 35
    :goto_0
    iget-object v1, p0, Lqn/l;->b:Ljava/lang/String;

    .line 36
    .line 37
    if-nez v1, :cond_2

    .line 38
    .line 39
    move-object v1, p1

    .line 40
    check-cast v1, Lqn/l;

    .line 41
    .line 42
    iget-object v1, v1, Lqn/l;->b:Ljava/lang/String;

    .line 43
    .line 44
    if-nez v1, :cond_d

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    move-object v3, p1

    .line 48
    check-cast v3, Lqn/l;

    .line 49
    .line 50
    iget-object v3, v3, Lqn/l;->b:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_d

    .line 57
    .line 58
    :goto_1
    iget-object v1, p0, Lqn/l;->c:Ljava/lang/String;

    .line 59
    .line 60
    if-nez v1, :cond_3

    .line 61
    .line 62
    move-object v1, p1

    .line 63
    check-cast v1, Lqn/l;

    .line 64
    .line 65
    iget-object v1, v1, Lqn/l;->c:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v1, :cond_d

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_3
    move-object v3, p1

    .line 71
    check-cast v3, Lqn/l;

    .line 72
    .line 73
    iget-object v3, v3, Lqn/l;->c:Ljava/lang/String;

    .line 74
    .line 75
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_d

    .line 80
    .line 81
    :goto_2
    iget-object v1, p0, Lqn/l;->d:Ljava/lang/String;

    .line 82
    .line 83
    if-nez v1, :cond_4

    .line 84
    .line 85
    move-object v1, p1

    .line 86
    check-cast v1, Lqn/l;

    .line 87
    .line 88
    iget-object v1, v1, Lqn/l;->d:Ljava/lang/String;

    .line 89
    .line 90
    if-nez v1, :cond_d

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_4
    move-object v3, p1

    .line 94
    check-cast v3, Lqn/l;

    .line 95
    .line 96
    iget-object v3, v3, Lqn/l;->d:Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    if-eqz v1, :cond_d

    .line 103
    .line 104
    :goto_3
    iget-object v1, p0, Lqn/l;->e:Ljava/lang/String;

    .line 105
    .line 106
    if-nez v1, :cond_5

    .line 107
    .line 108
    move-object v1, p1

    .line 109
    check-cast v1, Lqn/l;

    .line 110
    .line 111
    iget-object v1, v1, Lqn/l;->e:Ljava/lang/String;

    .line 112
    .line 113
    if-nez v1, :cond_d

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_5
    move-object v3, p1

    .line 117
    check-cast v3, Lqn/l;

    .line 118
    .line 119
    iget-object v3, v3, Lqn/l;->e:Ljava/lang/String;

    .line 120
    .line 121
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    if-eqz v1, :cond_d

    .line 126
    .line 127
    :goto_4
    iget-object v1, p0, Lqn/l;->f:Ljava/lang/String;

    .line 128
    .line 129
    if-nez v1, :cond_6

    .line 130
    .line 131
    move-object v1, p1

    .line 132
    check-cast v1, Lqn/l;

    .line 133
    .line 134
    iget-object v1, v1, Lqn/l;->f:Ljava/lang/String;

    .line 135
    .line 136
    if-nez v1, :cond_d

    .line 137
    .line 138
    goto :goto_5

    .line 139
    :cond_6
    move-object v3, p1

    .line 140
    check-cast v3, Lqn/l;

    .line 141
    .line 142
    iget-object v3, v3, Lqn/l;->f:Ljava/lang/String;

    .line 143
    .line 144
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-eqz v1, :cond_d

    .line 149
    .line 150
    :goto_5
    iget-object v1, p0, Lqn/l;->g:Ljava/lang/String;

    .line 151
    .line 152
    if-nez v1, :cond_7

    .line 153
    .line 154
    move-object v1, p1

    .line 155
    check-cast v1, Lqn/l;

    .line 156
    .line 157
    iget-object v1, v1, Lqn/l;->g:Ljava/lang/String;

    .line 158
    .line 159
    if-nez v1, :cond_d

    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_7
    move-object v3, p1

    .line 163
    check-cast v3, Lqn/l;

    .line 164
    .line 165
    iget-object v3, v3, Lqn/l;->g:Ljava/lang/String;

    .line 166
    .line 167
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-eqz v1, :cond_d

    .line 172
    .line 173
    :goto_6
    iget-object v1, p0, Lqn/l;->h:Ljava/lang/String;

    .line 174
    .line 175
    if-nez v1, :cond_8

    .line 176
    .line 177
    move-object v1, p1

    .line 178
    check-cast v1, Lqn/l;

    .line 179
    .line 180
    iget-object v1, v1, Lqn/l;->h:Ljava/lang/String;

    .line 181
    .line 182
    if-nez v1, :cond_d

    .line 183
    .line 184
    goto :goto_7

    .line 185
    :cond_8
    move-object v3, p1

    .line 186
    check-cast v3, Lqn/l;

    .line 187
    .line 188
    iget-object v3, v3, Lqn/l;->h:Ljava/lang/String;

    .line 189
    .line 190
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v1

    .line 194
    if-eqz v1, :cond_d

    .line 195
    .line 196
    :goto_7
    iget-object v1, p0, Lqn/l;->i:Ljava/lang/String;

    .line 197
    .line 198
    if-nez v1, :cond_9

    .line 199
    .line 200
    move-object v1, p1

    .line 201
    check-cast v1, Lqn/l;

    .line 202
    .line 203
    iget-object v1, v1, Lqn/l;->i:Ljava/lang/String;

    .line 204
    .line 205
    if-nez v1, :cond_d

    .line 206
    .line 207
    goto :goto_8

    .line 208
    :cond_9
    move-object v3, p1

    .line 209
    check-cast v3, Lqn/l;

    .line 210
    .line 211
    iget-object v3, v3, Lqn/l;->i:Ljava/lang/String;

    .line 212
    .line 213
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    if-eqz v1, :cond_d

    .line 218
    .line 219
    :goto_8
    iget-object v1, p0, Lqn/l;->j:Ljava/lang/String;

    .line 220
    .line 221
    if-nez v1, :cond_a

    .line 222
    .line 223
    move-object v1, p1

    .line 224
    check-cast v1, Lqn/l;

    .line 225
    .line 226
    iget-object v1, v1, Lqn/l;->j:Ljava/lang/String;

    .line 227
    .line 228
    if-nez v1, :cond_d

    .line 229
    .line 230
    goto :goto_9

    .line 231
    :cond_a
    move-object v3, p1

    .line 232
    check-cast v3, Lqn/l;

    .line 233
    .line 234
    iget-object v3, v3, Lqn/l;->j:Ljava/lang/String;

    .line 235
    .line 236
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v1

    .line 240
    if-eqz v1, :cond_d

    .line 241
    .line 242
    :goto_9
    iget-object v1, p0, Lqn/l;->k:Ljava/lang/String;

    .line 243
    .line 244
    if-nez v1, :cond_b

    .line 245
    .line 246
    move-object v1, p1

    .line 247
    check-cast v1, Lqn/l;

    .line 248
    .line 249
    iget-object v1, v1, Lqn/l;->k:Ljava/lang/String;

    .line 250
    .line 251
    if-nez v1, :cond_d

    .line 252
    .line 253
    goto :goto_a

    .line 254
    :cond_b
    move-object v3, p1

    .line 255
    check-cast v3, Lqn/l;

    .line 256
    .line 257
    iget-object v3, v3, Lqn/l;->k:Ljava/lang/String;

    .line 258
    .line 259
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v1

    .line 263
    if-eqz v1, :cond_d

    .line 264
    .line 265
    :goto_a
    iget-object p0, p0, Lqn/l;->l:Ljava/lang/String;

    .line 266
    .line 267
    if-nez p0, :cond_c

    .line 268
    .line 269
    check-cast p1, Lqn/l;

    .line 270
    .line 271
    iget-object p0, p1, Lqn/l;->l:Ljava/lang/String;

    .line 272
    .line 273
    if-nez p0, :cond_d

    .line 274
    .line 275
    goto :goto_b

    .line 276
    :cond_c
    check-cast p1, Lqn/l;

    .line 277
    .line 278
    iget-object p1, p1, Lqn/l;->l:Ljava/lang/String;

    .line 279
    .line 280
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result p0

    .line 284
    if-eqz p0, :cond_d

    .line 285
    .line 286
    :goto_b
    return v0

    .line 287
    :cond_d
    return v2
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lqn/l;->a:Ljava/lang/Integer;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Integer;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const v2, 0xf4243

    .line 13
    .line 14
    .line 15
    xor-int/2addr v1, v2

    .line 16
    mul-int/2addr v1, v2

    .line 17
    iget-object v3, p0, Lqn/l;->b:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    move v3, v0

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_1
    xor-int/2addr v1, v3

    .line 28
    mul-int/2addr v1, v2

    .line 29
    iget-object v3, p0, Lqn/l;->c:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v3, :cond_2

    .line 32
    .line 33
    move v3, v0

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_2
    xor-int/2addr v1, v3

    .line 40
    mul-int/2addr v1, v2

    .line 41
    iget-object v3, p0, Lqn/l;->d:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v3, :cond_3

    .line 44
    .line 45
    move v3, v0

    .line 46
    goto :goto_3

    .line 47
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    :goto_3
    xor-int/2addr v1, v3

    .line 52
    mul-int/2addr v1, v2

    .line 53
    iget-object v3, p0, Lqn/l;->e:Ljava/lang/String;

    .line 54
    .line 55
    if-nez v3, :cond_4

    .line 56
    .line 57
    move v3, v0

    .line 58
    goto :goto_4

    .line 59
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    :goto_4
    xor-int/2addr v1, v3

    .line 64
    mul-int/2addr v1, v2

    .line 65
    iget-object v3, p0, Lqn/l;->f:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v3, :cond_5

    .line 68
    .line 69
    move v3, v0

    .line 70
    goto :goto_5

    .line 71
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    :goto_5
    xor-int/2addr v1, v3

    .line 76
    mul-int/2addr v1, v2

    .line 77
    iget-object v3, p0, Lqn/l;->g:Ljava/lang/String;

    .line 78
    .line 79
    if-nez v3, :cond_6

    .line 80
    .line 81
    move v3, v0

    .line 82
    goto :goto_6

    .line 83
    :cond_6
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    :goto_6
    xor-int/2addr v1, v3

    .line 88
    mul-int/2addr v1, v2

    .line 89
    iget-object v3, p0, Lqn/l;->h:Ljava/lang/String;

    .line 90
    .line 91
    if-nez v3, :cond_7

    .line 92
    .line 93
    move v3, v0

    .line 94
    goto :goto_7

    .line 95
    :cond_7
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    :goto_7
    xor-int/2addr v1, v3

    .line 100
    mul-int/2addr v1, v2

    .line 101
    iget-object v3, p0, Lqn/l;->i:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v3, :cond_8

    .line 104
    .line 105
    move v3, v0

    .line 106
    goto :goto_8

    .line 107
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    :goto_8
    xor-int/2addr v1, v3

    .line 112
    mul-int/2addr v1, v2

    .line 113
    iget-object v3, p0, Lqn/l;->j:Ljava/lang/String;

    .line 114
    .line 115
    if-nez v3, :cond_9

    .line 116
    .line 117
    move v3, v0

    .line 118
    goto :goto_9

    .line 119
    :cond_9
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    :goto_9
    xor-int/2addr v1, v3

    .line 124
    mul-int/2addr v1, v2

    .line 125
    iget-object v3, p0, Lqn/l;->k:Ljava/lang/String;

    .line 126
    .line 127
    if-nez v3, :cond_a

    .line 128
    .line 129
    move v3, v0

    .line 130
    goto :goto_a

    .line 131
    :cond_a
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    :goto_a
    xor-int/2addr v1, v3

    .line 136
    mul-int/2addr v1, v2

    .line 137
    iget-object p0, p0, Lqn/l;->l:Ljava/lang/String;

    .line 138
    .line 139
    if-nez p0, :cond_b

    .line 140
    .line 141
    goto :goto_b

    .line 142
    :cond_b
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    :goto_b
    xor-int p0, v1, v0

    .line 147
    .line 148
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "AndroidClientInfo{sdkVersion="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lqn/l;->a:Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", model="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lqn/l;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", hardware="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lqn/l;->c:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", device="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lqn/l;->d:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", product="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lqn/l;->e:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", osBuild="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lqn/l;->f:Ljava/lang/String;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", manufacturer="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lqn/l;->g:Ljava/lang/String;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", fingerprint="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lqn/l;->h:Ljava/lang/String;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", locale="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lqn/l;->i:Ljava/lang/String;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", country="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lqn/l;->j:Ljava/lang/String;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", mccMnc="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Lqn/l;->k:Ljava/lang/String;

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", applicationBuild="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object p0, p0, Lqn/l;->l:Ljava/lang/String;

    .line 119
    .line 120
    const-string v1, "}"

    .line 121
    .line 122
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0
.end method
