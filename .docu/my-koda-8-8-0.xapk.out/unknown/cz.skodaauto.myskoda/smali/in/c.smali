.class public final Lin/c;
.super Li4/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "(?s)/\\*.*?\\*/"

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-direct {p0, p1}, Li4/c;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static S(I)I
    .locals 2

    .line 1
    const/16 v0, 0x30

    .line 2
    .line 3
    if-lt p0, v0, :cond_0

    .line 4
    .line 5
    const/16 v1, 0x39

    .line 6
    .line 7
    if-gt p0, v1, :cond_0

    .line 8
    .line 9
    sub-int/2addr p0, v0

    .line 10
    return p0

    .line 11
    :cond_0
    const/16 v0, 0x41

    .line 12
    .line 13
    if-lt p0, v0, :cond_1

    .line 14
    .line 15
    const/16 v0, 0x46

    .line 16
    .line 17
    if-gt p0, v0, :cond_1

    .line 18
    .line 19
    add-int/lit8 p0, p0, -0x37

    .line 20
    .line 21
    return p0

    .line 22
    :cond_1
    const/16 v0, 0x61

    .line 23
    .line 24
    if-lt p0, v0, :cond_2

    .line 25
    .line 26
    const/16 v0, 0x66

    .line 27
    .line 28
    if-gt p0, v0, :cond_2

    .line 29
    .line 30
    add-int/lit8 p0, p0, -0x57

    .line 31
    .line 32
    return p0

    .line 33
    :cond_2
    const/4 p0, -0x1

    .line 34
    return p0
.end method


# virtual methods
.method public final T()Ljava/lang/String;
    .locals 8

    .line 1
    invoke-virtual {p0}, Li4/c;->q()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object v0, p0, Li4/c;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljava/lang/String;

    .line 11
    .line 12
    iget v1, p0, Li4/c;->b:I

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/16 v1, 0x27

    .line 19
    .line 20
    if-eq v0, v1, :cond_1

    .line 21
    .line 22
    const/16 v1, 0x22

    .line 23
    .line 24
    if-eq v0, v1, :cond_1

    .line 25
    .line 26
    :goto_0
    const/4 p0, 0x0

    .line 27
    return-object p0

    .line 28
    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 31
    .line 32
    .line 33
    iget v2, p0, Li4/c;->b:I

    .line 34
    .line 35
    const/4 v3, 0x1

    .line 36
    add-int/2addr v2, v3

    .line 37
    iput v2, p0, Li4/c;->b:I

    .line 38
    .line 39
    invoke-virtual {p0}, Li4/c;->B()Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    :goto_1
    const/4 v4, -0x1

    .line 48
    if-eq v2, v4, :cond_8

    .line 49
    .line 50
    if-eq v2, v0, :cond_8

    .line 51
    .line 52
    const/16 v5, 0x5c

    .line 53
    .line 54
    if-ne v2, v5, :cond_7

    .line 55
    .line 56
    invoke-virtual {p0}, Li4/c;->B()Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-ne v2, v4, :cond_2

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    const/16 v5, 0xa

    .line 68
    .line 69
    if-eq v2, v5, :cond_6

    .line 70
    .line 71
    const/16 v5, 0xd

    .line 72
    .line 73
    if-eq v2, v5, :cond_6

    .line 74
    .line 75
    const/16 v5, 0xc

    .line 76
    .line 77
    if-ne v2, v5, :cond_3

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_3
    invoke-static {v2}, Lin/c;->S(I)I

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    if-eq v5, v4, :cond_7

    .line 85
    .line 86
    move v6, v3

    .line 87
    :goto_2
    const/4 v7, 0x5

    .line 88
    if-gt v6, v7, :cond_5

    .line 89
    .line 90
    invoke-virtual {p0}, Li4/c;->B()Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    invoke-static {v2}, Lin/c;->S(I)I

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    if-ne v7, v4, :cond_4

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_4
    mul-int/lit8 v5, v5, 0x10

    .line 106
    .line 107
    add-int/2addr v5, v7

    .line 108
    add-int/lit8 v6, v6, 0x1

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_5
    :goto_3
    int-to-char v4, v5

    .line 112
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_6
    :goto_4
    invoke-virtual {p0}, Li4/c;->B()Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    goto :goto_1

    .line 125
    :cond_7
    int-to-char v2, v2

    .line 126
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {p0}, Li4/c;->B()Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    goto :goto_1

    .line 138
    :cond_8
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0
.end method

.method public final U()Ljava/lang/String;
    .locals 10

    .line 1
    iget-object v0, p0, Li4/c;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0}, Li4/c;->q()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget v1, p0, Li4/c;->b:I

    .line 12
    .line 13
    goto :goto_3

    .line 14
    :cond_0
    iget v1, p0, Li4/c;->b:I

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/16 v3, 0x2d

    .line 21
    .line 22
    if-ne v2, v3, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0}, Li4/c;->h()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    :cond_1
    const/16 v4, 0x5f

    .line 29
    .line 30
    const/16 v5, 0x7a

    .line 31
    .line 32
    const/16 v6, 0x61

    .line 33
    .line 34
    const/16 v7, 0x5a

    .line 35
    .line 36
    const/16 v8, 0x41

    .line 37
    .line 38
    if-lt v2, v8, :cond_2

    .line 39
    .line 40
    if-le v2, v7, :cond_4

    .line 41
    .line 42
    :cond_2
    if-lt v2, v6, :cond_3

    .line 43
    .line 44
    if-le v2, v5, :cond_4

    .line 45
    .line 46
    :cond_3
    if-ne v2, v4, :cond_a

    .line 47
    .line 48
    :cond_4
    invoke-virtual {p0}, Li4/c;->h()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    :goto_0
    if-lt v2, v8, :cond_5

    .line 53
    .line 54
    if-le v2, v7, :cond_9

    .line 55
    .line 56
    :cond_5
    if-lt v2, v6, :cond_6

    .line 57
    .line 58
    if-le v2, v5, :cond_9

    .line 59
    .line 60
    :cond_6
    const/16 v9, 0x30

    .line 61
    .line 62
    if-lt v2, v9, :cond_7

    .line 63
    .line 64
    const/16 v9, 0x39

    .line 65
    .line 66
    if-le v2, v9, :cond_9

    .line 67
    .line 68
    :cond_7
    if-eq v2, v3, :cond_9

    .line 69
    .line 70
    if-ne v2, v4, :cond_8

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_8
    iget v2, p0, Li4/c;->b:I

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_9
    :goto_1
    invoke-virtual {p0}, Li4/c;->h()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    goto :goto_0

    .line 81
    :cond_a
    move v2, v1

    .line 82
    :goto_2
    iput v1, p0, Li4/c;->b:I

    .line 83
    .line 84
    move v1, v2

    .line 85
    :goto_3
    iget v2, p0, Li4/c;->b:I

    .line 86
    .line 87
    if-ne v1, v2, :cond_b

    .line 88
    .line 89
    const/4 p0, 0x0

    .line 90
    return-object p0

    .line 91
    :cond_b
    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    iput v1, p0, Li4/c;->b:I

    .line 96
    .line 97
    return-object v0
.end method

.method public final V()Ljava/util/ArrayList;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    return-object v2

    .line 11
    :cond_0
    new-instance v1, Ljava/util/ArrayList;

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 15
    .line 16
    .line 17
    new-instance v4, Lin/m;

    .line 18
    .line 19
    invoke-direct {v4}, Lin/m;-><init>()V

    .line 20
    .line 21
    .line 22
    :goto_0
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    if-nez v5, :cond_49

    .line 27
    .line 28
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    goto/16 :goto_24

    .line 35
    .line 36
    :cond_1
    iget v5, v0, Li4/c;->b:I

    .line 37
    .line 38
    iget-object v6, v4, Lin/m;->a:Ljava/util/ArrayList;

    .line 39
    .line 40
    const/4 v8, 0x2

    .line 41
    const/4 v9, 0x0

    .line 42
    const/16 v10, 0x2b

    .line 43
    .line 44
    if-eqz v6, :cond_4

    .line 45
    .line 46
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    if-eqz v6, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    const/16 v6, 0x3e

    .line 54
    .line 55
    invoke-virtual {v0, v6}, Li4/c;->m(C)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-eqz v6, :cond_3

    .line 60
    .line 61
    invoke-virtual {v0}, Li4/c;->R()V

    .line 62
    .line 63
    .line 64
    move v6, v8

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    invoke-virtual {v0, v10}, Li4/c;->m(C)Z

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    if-eqz v6, :cond_4

    .line 71
    .line 72
    invoke-virtual {v0}, Li4/c;->R()V

    .line 73
    .line 74
    .line 75
    const/4 v6, 0x3

    .line 76
    goto :goto_2

    .line 77
    :cond_4
    :goto_1
    move v6, v9

    .line 78
    :goto_2
    const/16 v11, 0x2a

    .line 79
    .line 80
    invoke-virtual {v0, v11}, Li4/c;->m(C)Z

    .line 81
    .line 82
    .line 83
    move-result v11

    .line 84
    if-eqz v11, :cond_5

    .line 85
    .line 86
    new-instance v11, Lin/n;

    .line 87
    .line 88
    invoke-direct {v11, v6, v2}, Lin/n;-><init>(ILjava/lang/String;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_5
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v11

    .line 96
    if-eqz v11, :cond_6

    .line 97
    .line 98
    new-instance v12, Lin/n;

    .line 99
    .line 100
    invoke-direct {v12, v6, v11}, Lin/n;-><init>(ILjava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget v11, v4, Lin/m;->b:I

    .line 104
    .line 105
    add-int/2addr v11, v3

    .line 106
    iput v11, v4, Lin/m;->b:I

    .line 107
    .line 108
    move-object v11, v12

    .line 109
    goto :goto_3

    .line 110
    :cond_6
    move-object v11, v2

    .line 111
    :goto_3
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 112
    .line 113
    .line 114
    move-result v12

    .line 115
    if-nez v12, :cond_45

    .line 116
    .line 117
    const/16 v12, 0x2e

    .line 118
    .line 119
    invoke-virtual {v0, v12}, Li4/c;->m(C)Z

    .line 120
    .line 121
    .line 122
    move-result v12

    .line 123
    if-eqz v12, :cond_9

    .line 124
    .line 125
    if-nez v11, :cond_7

    .line 126
    .line 127
    new-instance v11, Lin/n;

    .line 128
    .line 129
    invoke-direct {v11, v6, v2}, Lin/n;-><init>(ILjava/lang/String;)V

    .line 130
    .line 131
    .line 132
    :cond_7
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v12

    .line 136
    if-eqz v12, :cond_8

    .line 137
    .line 138
    const-string v13, "class"

    .line 139
    .line 140
    invoke-virtual {v11, v13, v8, v12}, Lin/n;->a(Ljava/lang/String;ILjava/lang/String;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v4}, Lin/m;->a()V

    .line 144
    .line 145
    .line 146
    goto :goto_3

    .line 147
    :cond_8
    new-instance v0, Lin/a;

    .line 148
    .line 149
    const-string v1, "Invalid \".class\" simpleSelectors"

    .line 150
    .line 151
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v0

    .line 155
    :cond_9
    const/16 v12, 0x23

    .line 156
    .line 157
    invoke-virtual {v0, v12}, Li4/c;->m(C)Z

    .line 158
    .line 159
    .line 160
    move-result v12

    .line 161
    if-eqz v12, :cond_c

    .line 162
    .line 163
    if-nez v11, :cond_a

    .line 164
    .line 165
    new-instance v11, Lin/n;

    .line 166
    .line 167
    invoke-direct {v11, v6, v2}, Lin/n;-><init>(ILjava/lang/String;)V

    .line 168
    .line 169
    .line 170
    :cond_a
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v12

    .line 174
    if-eqz v12, :cond_b

    .line 175
    .line 176
    const-string v13, "id"

    .line 177
    .line 178
    invoke-virtual {v11, v13, v8, v12}, Lin/n;->a(Ljava/lang/String;ILjava/lang/String;)V

    .line 179
    .line 180
    .line 181
    iget v12, v4, Lin/m;->b:I

    .line 182
    .line 183
    const v13, 0xf4240

    .line 184
    .line 185
    .line 186
    add-int/2addr v12, v13

    .line 187
    iput v12, v4, Lin/m;->b:I

    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_b
    new-instance v0, Lin/a;

    .line 191
    .line 192
    const-string v1, "Invalid \"#id\" simpleSelectors"

    .line 193
    .line 194
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    throw v0

    .line 198
    :cond_c
    const/16 v12, 0x5b

    .line 199
    .line 200
    invoke-virtual {v0, v12}, Li4/c;->m(C)Z

    .line 201
    .line 202
    .line 203
    move-result v12

    .line 204
    if-eqz v12, :cond_18

    .line 205
    .line 206
    if-nez v11, :cond_d

    .line 207
    .line 208
    new-instance v11, Lin/n;

    .line 209
    .line 210
    invoke-direct {v11, v6, v2}, Lin/n;-><init>(ILjava/lang/String;)V

    .line 211
    .line 212
    .line 213
    :cond_d
    invoke-virtual {v0}, Li4/c;->R()V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v12

    .line 220
    const-string v13, "Invalid attribute simpleSelectors"

    .line 221
    .line 222
    if-eqz v12, :cond_17

    .line 223
    .line 224
    invoke-virtual {v0}, Li4/c;->R()V

    .line 225
    .line 226
    .line 227
    const/16 v14, 0x3d

    .line 228
    .line 229
    invoke-virtual {v0, v14}, Li4/c;->m(C)Z

    .line 230
    .line 231
    .line 232
    move-result v14

    .line 233
    if-eqz v14, :cond_e

    .line 234
    .line 235
    move v14, v8

    .line 236
    goto :goto_4

    .line 237
    :cond_e
    const-string v14, "~="

    .line 238
    .line 239
    invoke-virtual {v0, v14}, Li4/c;->n(Ljava/lang/String;)Z

    .line 240
    .line 241
    .line 242
    move-result v14

    .line 243
    if-eqz v14, :cond_f

    .line 244
    .line 245
    const/4 v14, 0x3

    .line 246
    goto :goto_4

    .line 247
    :cond_f
    const-string v14, "|="

    .line 248
    .line 249
    invoke-virtual {v0, v14}, Li4/c;->n(Ljava/lang/String;)Z

    .line 250
    .line 251
    .line 252
    move-result v14

    .line 253
    if-eqz v14, :cond_10

    .line 254
    .line 255
    const/4 v14, 0x4

    .line 256
    goto :goto_4

    .line 257
    :cond_10
    move v14, v9

    .line 258
    :goto_4
    if-eqz v14, :cond_14

    .line 259
    .line 260
    invoke-virtual {v0}, Li4/c;->R()V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 264
    .line 265
    .line 266
    move-result v15

    .line 267
    if-eqz v15, :cond_11

    .line 268
    .line 269
    move-object v15, v2

    .line 270
    goto :goto_5

    .line 271
    :cond_11
    invoke-virtual {v0}, Li4/c;->E()Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v15

    .line 275
    if-eqz v15, :cond_12

    .line 276
    .line 277
    goto :goto_5

    .line 278
    :cond_12
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v15

    .line 282
    :goto_5
    if-eqz v15, :cond_13

    .line 283
    .line 284
    invoke-virtual {v0}, Li4/c;->R()V

    .line 285
    .line 286
    .line 287
    goto :goto_6

    .line 288
    :cond_13
    new-instance v0, Lin/a;

    .line 289
    .line 290
    invoke-direct {v0, v13}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    throw v0

    .line 294
    :cond_14
    move-object v15, v2

    .line 295
    :goto_6
    const/16 v7, 0x5d

    .line 296
    .line 297
    invoke-virtual {v0, v7}, Li4/c;->m(C)Z

    .line 298
    .line 299
    .line 300
    move-result v7

    .line 301
    if-eqz v7, :cond_16

    .line 302
    .line 303
    if-nez v14, :cond_15

    .line 304
    .line 305
    move v14, v3

    .line 306
    :cond_15
    invoke-virtual {v11, v12, v14, v15}, Lin/n;->a(Ljava/lang/String;ILjava/lang/String;)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v4}, Lin/m;->a()V

    .line 310
    .line 311
    .line 312
    goto/16 :goto_3

    .line 313
    .line 314
    :cond_16
    new-instance v0, Lin/a;

    .line 315
    .line 316
    invoke-direct {v0, v13}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    throw v0

    .line 320
    :cond_17
    new-instance v0, Lin/a;

    .line 321
    .line 322
    invoke-direct {v0, v13}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    throw v0

    .line 326
    :cond_18
    const/16 v7, 0x3a

    .line 327
    .line 328
    invoke-virtual {v0, v7}, Li4/c;->m(C)Z

    .line 329
    .line 330
    .line 331
    move-result v7

    .line 332
    if-eqz v7, :cond_45

    .line 333
    .line 334
    if-nez v11, :cond_19

    .line 335
    .line 336
    new-instance v7, Lin/n;

    .line 337
    .line 338
    invoke-direct {v7, v6, v2}, Lin/n;-><init>(ILjava/lang/String;)V

    .line 339
    .line 340
    .line 341
    move-object v11, v7

    .line 342
    :cond_19
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v7

    .line 346
    if-eqz v7, :cond_44

    .line 347
    .line 348
    sget-object v12, Lin/h;->h:Ljava/util/HashMap;

    .line 349
    .line 350
    invoke-virtual {v12, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v12

    .line 354
    check-cast v12, Lin/h;

    .line 355
    .line 356
    if-eqz v12, :cond_1a

    .line 357
    .line 358
    goto :goto_7

    .line 359
    :cond_1a
    sget-object v12, Lin/h;->g:Lin/h;

    .line 360
    .line 361
    :goto_7
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 362
    .line 363
    .line 364
    move-result v13

    .line 365
    const-string v14, "Invalid or missing parameter section for pseudo class: "

    .line 366
    .line 367
    const/16 v15, 0x29

    .line 368
    .line 369
    const/16 v10, 0x28

    .line 370
    .line 371
    packed-switch v13, :pswitch_data_0

    .line 372
    .line 373
    .line 374
    new-instance v0, Lin/a;

    .line 375
    .line 376
    const-string v1, "Unsupported pseudo class: "

    .line 377
    .line 378
    invoke-virtual {v1, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    throw v0

    .line 386
    :pswitch_0
    new-instance v10, Lin/j;

    .line 387
    .line 388
    invoke-direct {v10, v7}, Lin/j;-><init>(Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v4}, Lin/m;->a()V

    .line 392
    .line 393
    .line 394
    :goto_8
    move-object v9, v11

    .line 395
    goto/16 :goto_22

    .line 396
    .line 397
    :pswitch_1
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 398
    .line 399
    .line 400
    move-result v12

    .line 401
    if-eqz v12, :cond_1b

    .line 402
    .line 403
    goto :goto_9

    .line 404
    :cond_1b
    iget v12, v0, Li4/c;->b:I

    .line 405
    .line 406
    invoke-virtual {v0, v10}, Li4/c;->m(C)Z

    .line 407
    .line 408
    .line 409
    move-result v10

    .line 410
    if-nez v10, :cond_1c

    .line 411
    .line 412
    goto :goto_9

    .line 413
    :cond_1c
    invoke-virtual {v0}, Li4/c;->R()V

    .line 414
    .line 415
    .line 416
    move-object v10, v2

    .line 417
    :cond_1d
    invoke-virtual {v0}, Lin/c;->U()Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v13

    .line 421
    if-nez v13, :cond_1e

    .line 422
    .line 423
    iput v12, v0, Li4/c;->b:I

    .line 424
    .line 425
    goto :goto_9

    .line 426
    :cond_1e
    if-nez v10, :cond_1f

    .line 427
    .line 428
    new-instance v10, Ljava/util/ArrayList;

    .line 429
    .line 430
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 431
    .line 432
    .line 433
    :cond_1f
    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 434
    .line 435
    .line 436
    invoke-virtual {v0}, Li4/c;->R()V

    .line 437
    .line 438
    .line 439
    invoke-virtual {v0}, Li4/c;->Q()Z

    .line 440
    .line 441
    .line 442
    move-result v13

    .line 443
    if-nez v13, :cond_1d

    .line 444
    .line 445
    invoke-virtual {v0, v15}, Li4/c;->m(C)Z

    .line 446
    .line 447
    .line 448
    move-result v10

    .line 449
    if-eqz v10, :cond_20

    .line 450
    .line 451
    goto :goto_9

    .line 452
    :cond_20
    iput v12, v0, Li4/c;->b:I

    .line 453
    .line 454
    :goto_9
    new-instance v10, Lin/j;

    .line 455
    .line 456
    invoke-direct {v10, v7}, Lin/j;-><init>(Ljava/lang/String;)V

    .line 457
    .line 458
    .line 459
    invoke-virtual {v4}, Lin/m;->a()V

    .line 460
    .line 461
    .line 462
    goto :goto_8

    .line 463
    :pswitch_2
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 464
    .line 465
    .line 466
    move-result v12

    .line 467
    if-eqz v12, :cond_21

    .line 468
    .line 469
    :goto_a
    move-object v10, v2

    .line 470
    goto :goto_e

    .line 471
    :cond_21
    iget v12, v0, Li4/c;->b:I

    .line 472
    .line 473
    invoke-virtual {v0, v10}, Li4/c;->m(C)Z

    .line 474
    .line 475
    .line 476
    move-result v10

    .line 477
    if-nez v10, :cond_22

    .line 478
    .line 479
    goto :goto_a

    .line 480
    :cond_22
    invoke-virtual {v0}, Li4/c;->R()V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v0}, Lin/c;->V()Ljava/util/ArrayList;

    .line 484
    .line 485
    .line 486
    move-result-object v10

    .line 487
    if-nez v10, :cond_23

    .line 488
    .line 489
    iput v12, v0, Li4/c;->b:I

    .line 490
    .line 491
    goto :goto_a

    .line 492
    :cond_23
    invoke-virtual {v0, v15}, Li4/c;->m(C)Z

    .line 493
    .line 494
    .line 495
    move-result v13

    .line 496
    if-nez v13, :cond_24

    .line 497
    .line 498
    iput v12, v0, Li4/c;->b:I

    .line 499
    .line 500
    goto :goto_a

    .line 501
    :cond_24
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 502
    .line 503
    .line 504
    move-result-object v12

    .line 505
    :goto_b
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 506
    .line 507
    .line 508
    move-result v13

    .line 509
    if-eqz v13, :cond_2a

    .line 510
    .line 511
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object v13

    .line 515
    check-cast v13, Lin/m;

    .line 516
    .line 517
    iget-object v13, v13, Lin/m;->a:Ljava/util/ArrayList;

    .line 518
    .line 519
    if-nez v13, :cond_25

    .line 520
    .line 521
    goto :goto_e

    .line 522
    :cond_25
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 523
    .line 524
    .line 525
    move-result-object v13

    .line 526
    :cond_26
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 527
    .line 528
    .line 529
    move-result v15

    .line 530
    if-eqz v15, :cond_29

    .line 531
    .line 532
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object v15

    .line 536
    check-cast v15, Lin/n;

    .line 537
    .line 538
    iget-object v15, v15, Lin/n;->d:Ljava/util/ArrayList;

    .line 539
    .line 540
    if-nez v15, :cond_27

    .line 541
    .line 542
    goto :goto_d

    .line 543
    :cond_27
    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 544
    .line 545
    .line 546
    move-result-object v15

    .line 547
    :goto_c
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 548
    .line 549
    .line 550
    move-result v16

    .line 551
    if-eqz v16, :cond_26

    .line 552
    .line 553
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    move-result-object v16

    .line 557
    move-object/from16 v8, v16

    .line 558
    .line 559
    check-cast v8, Lin/e;

    .line 560
    .line 561
    instance-of v8, v8, Lin/i;

    .line 562
    .line 563
    if-eqz v8, :cond_28

    .line 564
    .line 565
    goto :goto_a

    .line 566
    :cond_28
    const/4 v8, 0x2

    .line 567
    goto :goto_c

    .line 568
    :cond_29
    :goto_d
    const/4 v8, 0x2

    .line 569
    goto :goto_b

    .line 570
    :cond_2a
    :goto_e
    if-eqz v10, :cond_2d

    .line 571
    .line 572
    new-instance v7, Lin/i;

    .line 573
    .line 574
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 575
    .line 576
    .line 577
    iput-object v10, v7, Lin/i;->a:Ljava/util/List;

    .line 578
    .line 579
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 580
    .line 581
    .line 582
    move-result-object v8

    .line 583
    const/high16 v10, -0x80000000

    .line 584
    .line 585
    :cond_2b
    :goto_f
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 586
    .line 587
    .line 588
    move-result v12

    .line 589
    if-eqz v12, :cond_2c

    .line 590
    .line 591
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    move-result-object v12

    .line 595
    check-cast v12, Lin/m;

    .line 596
    .line 597
    iget v12, v12, Lin/m;->b:I

    .line 598
    .line 599
    if-le v12, v10, :cond_2b

    .line 600
    .line 601
    move v10, v12

    .line 602
    goto :goto_f

    .line 603
    :cond_2c
    iput v10, v4, Lin/m;->b:I

    .line 604
    .line 605
    move-object v10, v7

    .line 606
    goto/16 :goto_8

    .line 607
    .line 608
    :cond_2d
    new-instance v0, Lin/a;

    .line 609
    .line 610
    invoke-virtual {v14, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 611
    .line 612
    .line 613
    move-result-object v1

    .line 614
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    throw v0

    .line 618
    :pswitch_3
    new-instance v10, Lin/g;

    .line 619
    .line 620
    const/4 v7, 0x0

    .line 621
    invoke-direct {v10, v7}, Lin/g;-><init>(I)V

    .line 622
    .line 623
    .line 624
    invoke-virtual {v4}, Lin/m;->a()V

    .line 625
    .line 626
    .line 627
    goto/16 :goto_8

    .line 628
    .line 629
    :pswitch_4
    new-instance v10, Lin/k;

    .line 630
    .line 631
    iget-object v7, v11, Lin/n;->b:Ljava/lang/String;

    .line 632
    .line 633
    invoke-direct {v10, v3, v7}, Lin/k;-><init>(ZLjava/lang/String;)V

    .line 634
    .line 635
    .line 636
    invoke-virtual {v4}, Lin/m;->a()V

    .line 637
    .line 638
    .line 639
    goto/16 :goto_8

    .line 640
    .line 641
    :pswitch_5
    new-instance v10, Lin/k;

    .line 642
    .line 643
    invoke-direct {v10, v9, v2}, Lin/k;-><init>(ZLjava/lang/String;)V

    .line 644
    .line 645
    .line 646
    invoke-virtual {v4}, Lin/m;->a()V

    .line 647
    .line 648
    .line 649
    goto/16 :goto_8

    .line 650
    .line 651
    :pswitch_6
    new-instance v18, Lin/f;

    .line 652
    .line 653
    const/16 v23, 0x1

    .line 654
    .line 655
    iget-object v7, v11, Lin/n;->b:Ljava/lang/String;

    .line 656
    .line 657
    const/16 v19, 0x0

    .line 658
    .line 659
    const/16 v20, 0x1

    .line 660
    .line 661
    const/16 v22, 0x0

    .line 662
    .line 663
    move-object/from16 v21, v7

    .line 664
    .line 665
    invoke-direct/range {v18 .. v23}, Lin/f;-><init>(IILjava/lang/String;ZZ)V

    .line 666
    .line 667
    .line 668
    invoke-virtual {v4}, Lin/m;->a()V

    .line 669
    .line 670
    .line 671
    move-object v9, v11

    .line 672
    :goto_10
    move-object/from16 v10, v18

    .line 673
    .line 674
    goto/16 :goto_22

    .line 675
    .line 676
    :pswitch_7
    new-instance v19, Lin/f;

    .line 677
    .line 678
    const/16 v24, 0x1

    .line 679
    .line 680
    iget-object v7, v11, Lin/n;->b:Ljava/lang/String;

    .line 681
    .line 682
    const/16 v20, 0x0

    .line 683
    .line 684
    const/16 v21, 0x1

    .line 685
    .line 686
    const/16 v23, 0x1

    .line 687
    .line 688
    move-object/from16 v22, v7

    .line 689
    .line 690
    invoke-direct/range {v19 .. v24}, Lin/f;-><init>(IILjava/lang/String;ZZ)V

    .line 691
    .line 692
    .line 693
    invoke-virtual {v4}, Lin/m;->a()V

    .line 694
    .line 695
    .line 696
    move-object v9, v11

    .line 697
    move-object/from16 v10, v19

    .line 698
    .line 699
    goto/16 :goto_22

    .line 700
    .line 701
    :pswitch_8
    new-instance v20, Lin/f;

    .line 702
    .line 703
    const/16 v25, 0x0

    .line 704
    .line 705
    const/16 v23, 0x0

    .line 706
    .line 707
    const/16 v21, 0x0

    .line 708
    .line 709
    const/16 v22, 0x1

    .line 710
    .line 711
    const/16 v24, 0x0

    .line 712
    .line 713
    invoke-direct/range {v20 .. v25}, Lin/f;-><init>(IILjava/lang/String;ZZ)V

    .line 714
    .line 715
    .line 716
    invoke-virtual {v4}, Lin/m;->a()V

    .line 717
    .line 718
    .line 719
    move-object v9, v11

    .line 720
    move-object/from16 v10, v20

    .line 721
    .line 722
    goto/16 :goto_22

    .line 723
    .line 724
    :pswitch_9
    new-instance v21, Lin/f;

    .line 725
    .line 726
    const/16 v26, 0x0

    .line 727
    .line 728
    const/16 v24, 0x0

    .line 729
    .line 730
    const/16 v22, 0x0

    .line 731
    .line 732
    const/16 v23, 0x1

    .line 733
    .line 734
    const/16 v25, 0x1

    .line 735
    .line 736
    invoke-direct/range {v21 .. v26}, Lin/f;-><init>(IILjava/lang/String;ZZ)V

    .line 737
    .line 738
    .line 739
    invoke-virtual {v4}, Lin/m;->a()V

    .line 740
    .line 741
    .line 742
    move-object v9, v11

    .line 743
    move-object/from16 v10, v21

    .line 744
    .line 745
    goto/16 :goto_22

    .line 746
    .line 747
    :pswitch_a
    sget-object v8, Lin/h;->d:Lin/h;

    .line 748
    .line 749
    if-eq v12, v8, :cond_2f

    .line 750
    .line 751
    sget-object v8, Lin/h;->e:Lin/h;

    .line 752
    .line 753
    if-ne v12, v8, :cond_2e

    .line 754
    .line 755
    goto :goto_11

    .line 756
    :cond_2e
    move/from16 v22, v9

    .line 757
    .line 758
    goto :goto_12

    .line 759
    :cond_2f
    :goto_11
    move/from16 v22, v3

    .line 760
    .line 761
    :goto_12
    sget-object v8, Lin/h;->e:Lin/h;

    .line 762
    .line 763
    if-eq v12, v8, :cond_31

    .line 764
    .line 765
    sget-object v8, Lin/h;->f:Lin/h;

    .line 766
    .line 767
    if-ne v12, v8, :cond_30

    .line 768
    .line 769
    goto :goto_13

    .line 770
    :cond_30
    move/from16 v23, v9

    .line 771
    .line 772
    goto :goto_14

    .line 773
    :cond_31
    :goto_13
    move/from16 v23, v3

    .line 774
    .line 775
    :goto_14
    iget v8, v0, Li4/c;->c:I

    .line 776
    .line 777
    iget-object v12, v0, Li4/c;->d:Ljava/lang/Object;

    .line 778
    .line 779
    check-cast v12, Ljava/lang/String;

    .line 780
    .line 781
    invoke-virtual {v0}, Li4/c;->q()Z

    .line 782
    .line 783
    .line 784
    move-result v13

    .line 785
    if-eqz v13, :cond_32

    .line 786
    .line 787
    :goto_15
    move-object v8, v2

    .line 788
    move-object v9, v11

    .line 789
    goto/16 :goto_21

    .line 790
    .line 791
    :cond_32
    iget v13, v0, Li4/c;->b:I

    .line 792
    .line 793
    invoke-virtual {v0, v10}, Li4/c;->m(C)Z

    .line 794
    .line 795
    .line 796
    move-result v10

    .line 797
    if-nez v10, :cond_33

    .line 798
    .line 799
    goto :goto_15

    .line 800
    :cond_33
    invoke-virtual {v0}, Li4/c;->R()V

    .line 801
    .line 802
    .line 803
    const-string v10, "odd"

    .line 804
    .line 805
    invoke-virtual {v0, v10}, Li4/c;->n(Ljava/lang/String;)Z

    .line 806
    .line 807
    .line 808
    move-result v10

    .line 809
    if-eqz v10, :cond_34

    .line 810
    .line 811
    new-instance v8, Lb8/i;

    .line 812
    .line 813
    const/4 v10, 0x4

    .line 814
    const/4 v12, 0x2

    .line 815
    invoke-direct {v8, v12, v3, v10}, Lb8/i;-><init>(III)V

    .line 816
    .line 817
    .line 818
    :goto_16
    move-object v9, v11

    .line 819
    goto/16 :goto_20

    .line 820
    .line 821
    :cond_34
    const/4 v10, 0x2

    .line 822
    const-string v2, "even"

    .line 823
    .line 824
    invoke-virtual {v0, v2}, Li4/c;->n(Ljava/lang/String;)Z

    .line 825
    .line 826
    .line 827
    move-result v2

    .line 828
    if-eqz v2, :cond_35

    .line 829
    .line 830
    new-instance v8, Lb8/i;

    .line 831
    .line 832
    const/4 v2, 0x4

    .line 833
    invoke-direct {v8, v10, v9, v2}, Lb8/i;-><init>(III)V

    .line 834
    .line 835
    .line 836
    goto :goto_16

    .line 837
    :cond_35
    const/16 v2, 0x2b

    .line 838
    .line 839
    invoke-virtual {v0, v2}, Li4/c;->m(C)Z

    .line 840
    .line 841
    .line 842
    move-result v17

    .line 843
    const/16 v2, 0x2d

    .line 844
    .line 845
    if-eqz v17, :cond_36

    .line 846
    .line 847
    goto :goto_17

    .line 848
    :cond_36
    invoke-virtual {v0, v2}, Li4/c;->m(C)Z

    .line 849
    .line 850
    .line 851
    move-result v17

    .line 852
    if-eqz v17, :cond_37

    .line 853
    .line 854
    const/16 v17, -0x1

    .line 855
    .line 856
    goto :goto_18

    .line 857
    :cond_37
    :goto_17
    move/from16 v17, v3

    .line 858
    .line 859
    :goto_18
    iget v3, v0, Li4/c;->b:I

    .line 860
    .line 861
    invoke-static {v3, v8, v12}, Lin/p;->a(IILjava/lang/String;)Lin/p;

    .line 862
    .line 863
    .line 864
    move-result-object v3

    .line 865
    if-eqz v3, :cond_38

    .line 866
    .line 867
    iget v9, v3, Lin/p;->d:I

    .line 868
    .line 869
    iput v9, v0, Li4/c;->b:I

    .line 870
    .line 871
    :cond_38
    const/16 v9, 0x6e

    .line 872
    .line 873
    invoke-virtual {v0, v9}, Li4/c;->m(C)Z

    .line 874
    .line 875
    .line 876
    move-result v9

    .line 877
    if-nez v9, :cond_3a

    .line 878
    .line 879
    const/16 v9, 0x4e

    .line 880
    .line 881
    invoke-virtual {v0, v9}, Li4/c;->m(C)Z

    .line 882
    .line 883
    .line 884
    move-result v9

    .line 885
    if-eqz v9, :cond_39

    .line 886
    .line 887
    goto :goto_19

    .line 888
    :cond_39
    move-object v8, v3

    .line 889
    move-object v9, v11

    .line 890
    move/from16 v2, v17

    .line 891
    .line 892
    const/4 v3, 0x0

    .line 893
    const/16 v10, 0x2b

    .line 894
    .line 895
    const/16 v17, 0x1

    .line 896
    .line 897
    goto :goto_1d

    .line 898
    :cond_3a
    :goto_19
    if-eqz v3, :cond_3b

    .line 899
    .line 900
    move-object v9, v11

    .line 901
    goto :goto_1a

    .line 902
    :cond_3b
    new-instance v3, Lin/p;

    .line 903
    .line 904
    move-object v9, v11

    .line 905
    const-wide/16 v10, 0x1

    .line 906
    .line 907
    iget v15, v0, Li4/c;->b:I

    .line 908
    .line 909
    invoke-direct {v3, v10, v11, v15}, Lin/p;-><init>(JI)V

    .line 910
    .line 911
    .line 912
    :goto_1a
    invoke-virtual {v0}, Li4/c;->R()V

    .line 913
    .line 914
    .line 915
    const/16 v10, 0x2b

    .line 916
    .line 917
    invoke-virtual {v0, v10}, Li4/c;->m(C)Z

    .line 918
    .line 919
    .line 920
    move-result v11

    .line 921
    if-nez v11, :cond_3c

    .line 922
    .line 923
    invoke-virtual {v0, v2}, Li4/c;->m(C)Z

    .line 924
    .line 925
    .line 926
    move-result v11

    .line 927
    if-eqz v11, :cond_3c

    .line 928
    .line 929
    const/4 v2, -0x1

    .line 930
    goto :goto_1b

    .line 931
    :cond_3c
    const/4 v2, 0x1

    .line 932
    :goto_1b
    if-eqz v11, :cond_3e

    .line 933
    .line 934
    invoke-virtual {v0}, Li4/c;->R()V

    .line 935
    .line 936
    .line 937
    iget v11, v0, Li4/c;->b:I

    .line 938
    .line 939
    invoke-static {v11, v8, v12}, Lin/p;->a(IILjava/lang/String;)Lin/p;

    .line 940
    .line 941
    .line 942
    move-result-object v8

    .line 943
    if-eqz v8, :cond_3d

    .line 944
    .line 945
    iget v11, v8, Lin/p;->d:I

    .line 946
    .line 947
    iput v11, v0, Li4/c;->b:I

    .line 948
    .line 949
    goto :goto_1d

    .line 950
    :cond_3d
    iput v13, v0, Li4/c;->b:I

    .line 951
    .line 952
    :goto_1c
    const/4 v8, 0x0

    .line 953
    goto :goto_21

    .line 954
    :cond_3e
    const/4 v8, 0x0

    .line 955
    :goto_1d
    new-instance v11, Lb8/i;

    .line 956
    .line 957
    if-nez v3, :cond_3f

    .line 958
    .line 959
    move-object v12, v11

    .line 960
    const/4 v3, 0x0

    .line 961
    goto :goto_1e

    .line 962
    :cond_3f
    move-object v12, v11

    .line 963
    iget-wide v10, v3, Lin/p;->e:J

    .line 964
    .line 965
    long-to-int v3, v10

    .line 966
    mul-int v17, v17, v3

    .line 967
    .line 968
    move/from16 v3, v17

    .line 969
    .line 970
    :goto_1e
    if-nez v8, :cond_40

    .line 971
    .line 972
    const/4 v2, 0x0

    .line 973
    goto :goto_1f

    .line 974
    :cond_40
    iget-wide v10, v8, Lin/p;->e:J

    .line 975
    .line 976
    long-to-int v8, v10

    .line 977
    mul-int/2addr v2, v8

    .line 978
    :goto_1f
    const/4 v8, 0x4

    .line 979
    invoke-direct {v12, v3, v2, v8}, Lb8/i;-><init>(III)V

    .line 980
    .line 981
    .line 982
    move-object v8, v12

    .line 983
    :goto_20
    invoke-virtual {v0}, Li4/c;->R()V

    .line 984
    .line 985
    .line 986
    const/16 v2, 0x29

    .line 987
    .line 988
    invoke-virtual {v0, v2}, Li4/c;->m(C)Z

    .line 989
    .line 990
    .line 991
    move-result v2

    .line 992
    if-eqz v2, :cond_41

    .line 993
    .line 994
    goto :goto_21

    .line 995
    :cond_41
    iput v13, v0, Li4/c;->b:I

    .line 996
    .line 997
    goto :goto_1c

    .line 998
    :goto_21
    if-eqz v8, :cond_42

    .line 999
    .line 1000
    new-instance v18, Lin/f;

    .line 1001
    .line 1002
    iget v2, v8, Lb8/i;->b:I

    .line 1003
    .line 1004
    iget v3, v8, Lb8/i;->c:I

    .line 1005
    .line 1006
    iget-object v7, v9, Lin/n;->b:Ljava/lang/String;

    .line 1007
    .line 1008
    move/from16 v19, v2

    .line 1009
    .line 1010
    move/from16 v20, v3

    .line 1011
    .line 1012
    move-object/from16 v21, v7

    .line 1013
    .line 1014
    invoke-direct/range {v18 .. v23}, Lin/f;-><init>(IILjava/lang/String;ZZ)V

    .line 1015
    .line 1016
    .line 1017
    invoke-virtual {v4}, Lin/m;->a()V

    .line 1018
    .line 1019
    .line 1020
    goto/16 :goto_10

    .line 1021
    .line 1022
    :cond_42
    new-instance v0, Lin/a;

    .line 1023
    .line 1024
    invoke-virtual {v14, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v1

    .line 1028
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 1029
    .line 1030
    .line 1031
    throw v0

    .line 1032
    :pswitch_b
    move-object v9, v11

    .line 1033
    new-instance v10, Lin/g;

    .line 1034
    .line 1035
    const/4 v2, 0x1

    .line 1036
    invoke-direct {v10, v2}, Lin/g;-><init>(I)V

    .line 1037
    .line 1038
    .line 1039
    invoke-virtual {v4}, Lin/m;->a()V

    .line 1040
    .line 1041
    .line 1042
    goto :goto_22

    .line 1043
    :pswitch_c
    move-object v9, v11

    .line 1044
    new-instance v10, Lin/g;

    .line 1045
    .line 1046
    const/4 v2, 0x2

    .line 1047
    invoke-direct {v10, v2}, Lin/g;-><init>(I)V

    .line 1048
    .line 1049
    .line 1050
    invoke-virtual {v4}, Lin/m;->a()V

    .line 1051
    .line 1052
    .line 1053
    :goto_22
    iget-object v2, v9, Lin/n;->d:Ljava/util/ArrayList;

    .line 1054
    .line 1055
    if-nez v2, :cond_43

    .line 1056
    .line 1057
    new-instance v2, Ljava/util/ArrayList;

    .line 1058
    .line 1059
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1060
    .line 1061
    .line 1062
    iput-object v2, v9, Lin/n;->d:Ljava/util/ArrayList;

    .line 1063
    .line 1064
    :cond_43
    iget-object v2, v9, Lin/n;->d:Ljava/util/ArrayList;

    .line 1065
    .line 1066
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1067
    .line 1068
    .line 1069
    move-object v11, v9

    .line 1070
    const/4 v2, 0x0

    .line 1071
    const/4 v3, 0x1

    .line 1072
    const/4 v8, 0x2

    .line 1073
    const/4 v9, 0x0

    .line 1074
    const/16 v10, 0x2b

    .line 1075
    .line 1076
    goto/16 :goto_3

    .line 1077
    .line 1078
    :cond_44
    new-instance v0, Lin/a;

    .line 1079
    .line 1080
    const-string v1, "Invalid pseudo class"

    .line 1081
    .line 1082
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 1083
    .line 1084
    .line 1085
    throw v0

    .line 1086
    :cond_45
    if-eqz v11, :cond_48

    .line 1087
    .line 1088
    iget-object v2, v4, Lin/m;->a:Ljava/util/ArrayList;

    .line 1089
    .line 1090
    if-nez v2, :cond_46

    .line 1091
    .line 1092
    new-instance v2, Ljava/util/ArrayList;

    .line 1093
    .line 1094
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1095
    .line 1096
    .line 1097
    iput-object v2, v4, Lin/m;->a:Ljava/util/ArrayList;

    .line 1098
    .line 1099
    :cond_46
    iget-object v2, v4, Lin/m;->a:Ljava/util/ArrayList;

    .line 1100
    .line 1101
    invoke-virtual {v2, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1102
    .line 1103
    .line 1104
    invoke-virtual {v0}, Li4/c;->Q()Z

    .line 1105
    .line 1106
    .line 1107
    move-result v2

    .line 1108
    if-nez v2, :cond_47

    .line 1109
    .line 1110
    :goto_23
    const/4 v2, 0x0

    .line 1111
    const/4 v3, 0x1

    .line 1112
    goto/16 :goto_0

    .line 1113
    .line 1114
    :cond_47
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1115
    .line 1116
    .line 1117
    new-instance v4, Lin/m;

    .line 1118
    .line 1119
    invoke-direct {v4}, Lin/m;-><init>()V

    .line 1120
    .line 1121
    .line 1122
    goto :goto_23

    .line 1123
    :cond_48
    iput v5, v0, Li4/c;->b:I

    .line 1124
    .line 1125
    :cond_49
    :goto_24
    iget-object v0, v4, Lin/m;->a:Ljava/util/ArrayList;

    .line 1126
    .line 1127
    if-eqz v0, :cond_4b

    .line 1128
    .line 1129
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1130
    .line 1131
    .line 1132
    move-result v0

    .line 1133
    if-eqz v0, :cond_4a

    .line 1134
    .line 1135
    goto :goto_25

    .line 1136
    :cond_4a
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1137
    .line 1138
    .line 1139
    :cond_4b
    :goto_25
    return-object v1

    .line 1140
    nop

    .line 1141
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_a
        :pswitch_a
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
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method
