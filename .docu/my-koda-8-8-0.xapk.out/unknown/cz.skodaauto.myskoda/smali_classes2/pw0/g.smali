.class public abstract Lpw0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/Set;

.field public static final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/16 v0, 0x2f

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/16 v1, 0x3f

    .line 8
    .line 9
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const/16 v2, 0x23

    .line 14
    .line 15
    invoke-static {v2}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    const/16 v3, 0x40

    .line 20
    .line 21
    invoke-static {v3}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    filled-new-array {v0, v1, v2, v3}, [Ljava/lang/Character;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lpw0/g;->a:Ljava/util/Set;

    .line 34
    .line 35
    sget-object v0, Lio/ktor/utils/io/p0;->b:Ljava/util/List;

    .line 36
    .line 37
    const/4 v0, 0x6

    .line 38
    sput v0, Lpw0/g;->b:I

    .line 39
    .line 40
    const-string v0, "HTTP/1.0"

    .line 41
    .line 42
    const-string v1, "HTTP/1.1"

    .line 43
    .line 44
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    new-instance v1, Lqe/b;

    .line 53
    .line 54
    const/16 v2, 0x15

    .line 55
    .line 56
    invoke-direct {v1, v2}, Lqe/b;-><init>(I)V

    .line 57
    .line 58
    .line 59
    new-instance v2, Lpd0/a;

    .line 60
    .line 61
    const/16 v3, 0x19

    .line 62
    .line 63
    invoke-direct {v2, v3}, Lpd0/a;-><init>(I)V

    .line 64
    .line 65
    .line 66
    invoke-static {v0, v1, v2}, Ljp/gg;->a(Ljava/util/List;Lay0/k;Lay0/n;)Lnm0/b;

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public static final a(Lqw0/c;C)V
    .locals 3

    .line 1
    new-instance v0, Laq/c;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Character with code "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    and-int/lit16 p1, p1, 0xff

    .line 11
    .line 12
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p1, " is not allowed in header names, \n"

    .line 16
    .line 17
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {v0, p0}, Laq/c;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw v0
.end method

.method public static final b(Lqw0/c;Lb8/i;)I
    .locals 5

    .line 1
    iget v0, p1, Lb8/i;->b:I

    .line 2
    .line 3
    iget v1, p1, Lb8/i;->c:I

    .line 4
    .line 5
    :goto_0
    if-ge v0, v1, :cond_5

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lqw0/c;->charAt(I)C

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/16 v3, 0x3a

    .line 12
    .line 13
    if-ne v2, v3, :cond_0

    .line 14
    .line 15
    iget v4, p1, Lb8/i;->b:I

    .line 16
    .line 17
    if-eq v0, v4, :cond_0

    .line 18
    .line 19
    add-int/lit8 p0, v0, 0x1

    .line 20
    .line 21
    iput p0, p1, Lb8/i;->b:I

    .line 22
    .line 23
    return v0

    .line 24
    :cond_0
    const/16 v4, 0x20

    .line 25
    .line 26
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->g(II)I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-lez v4, :cond_2

    .line 31
    .line 32
    const-string v4, "\"(),/:;<=>?@[\\]{}"

    .line 33
    .line 34
    invoke-static {v4, v2}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    :goto_1
    iget p1, p1, Lb8/i;->b:I

    .line 45
    .line 46
    if-eq v2, v3, :cond_4

    .line 47
    .line 48
    if-ne v0, p1, :cond_3

    .line 49
    .line 50
    new-instance p0, Laq/c;

    .line 51
    .line 52
    const-string p1, "Multiline headers via line folding is not supported since it is deprecated as per RFC7230."

    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    invoke-direct {p0, p1, v0}, Laq/c;-><init>(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_3
    invoke-static {p0, v2}, Lpw0/g;->a(Lqw0/c;C)V

    .line 60
    .line 61
    .line 62
    const/4 p0, 0x0

    .line 63
    throw p0

    .line 64
    :cond_4
    new-instance p0, Laq/c;

    .line 65
    .line 66
    const-string p1, "Empty header names are not allowed as per RFC7230."

    .line 67
    .line 68
    const/4 v0, 0x0

    .line 69
    invoke-direct {p0, p1, v0}, Laq/c;-><init>(Ljava/lang/String;Z)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_5
    new-instance v0, Laq/c;

    .line 74
    .line 75
    new-instance v1, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    const-string v2, "No colon in HTTP header in "

    .line 78
    .line 79
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    iget v2, p1, Lb8/i;->b:I

    .line 83
    .line 84
    iget p1, p1, Lb8/i;->c:I

    .line 85
    .line 86
    invoke-virtual {p0, v2, p1}, Lqw0/c;->subSequence(II)Ljava/lang/CharSequence;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string p1, " in builder: \n"

    .line 98
    .line 99
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-direct {v0, p0}, Laq/c;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw v0
.end method

.method public static final c(Lio/ktor/utils/io/t;Lqw0/c;Lb8/i;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p3

    .line 2
    .line 3
    instance-of v1, v0, Lpw0/f;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lpw0/f;

    .line 9
    .line 10
    iget v2, v1, Lpw0/f;->i:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lpw0/f;->i:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lpw0/f;

    .line 23
    .line 24
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object v0, v1, Lpw0/f;->h:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lpw0/f;->i:I

    .line 32
    .line 33
    const/16 v4, 0x2000

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v3, :cond_2

    .line 37
    .line 38
    if-ne v3, v5, :cond_1

    .line 39
    .line 40
    iget-object v3, v1, Lpw0/f;->g:Lpw0/d;

    .line 41
    .line 42
    iget-object v6, v1, Lpw0/f;->f:Lb8/i;

    .line 43
    .line 44
    iget-object v7, v1, Lpw0/f;->e:Lqw0/c;

    .line 45
    .line 46
    iget-object v8, v1, Lpw0/f;->d:Lio/ktor/utils/io/t;

    .line 47
    .line 48
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    .line 50
    .line 51
    move-object/from16 v16, v6

    .line 52
    .line 53
    move-object v6, v1

    .line 54
    move-object/from16 v1, v16

    .line 55
    .line 56
    move-object/from16 v16, v7

    .line 57
    .line 58
    move-object v7, v3

    .line 59
    move-object/from16 v3, v16

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :catchall_0
    move-exception v0

    .line 63
    goto/16 :goto_7

    .line 64
    .line 65
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Lpw0/d;

    .line 77
    .line 78
    move-object/from16 v3, p1

    .line 79
    .line 80
    invoke-direct {v0, v3}, Lpw0/d;-><init>(Lqw0/c;)V

    .line 81
    .line 82
    .line 83
    move-object v7, v0

    .line 84
    move-object v6, v1

    .line 85
    move-object/from16 v0, p0

    .line 86
    .line 87
    move-object/from16 v1, p2

    .line 88
    .line 89
    :goto_1
    :try_start_1
    sget v8, Lpw0/g;->b:I

    .line 90
    .line 91
    iput-object v0, v6, Lpw0/f;->d:Lio/ktor/utils/io/t;

    .line 92
    .line 93
    iput-object v3, v6, Lpw0/f;->e:Lqw0/c;

    .line 94
    .line 95
    iput-object v1, v6, Lpw0/f;->f:Lb8/i;

    .line 96
    .line 97
    iput-object v7, v6, Lpw0/f;->g:Lpw0/d;

    .line 98
    .line 99
    iput v5, v6, Lpw0/f;->i:I

    .line 100
    .line 101
    invoke-static {v0, v3, v4, v8, v6}, Lio/ktor/utils/io/h0;->j(Lio/ktor/utils/io/t;Lqw0/c;IILrx0/c;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    if-ne v8, v2, :cond_3

    .line 106
    .line 107
    return-object v2

    .line 108
    :cond_3
    move-object/from16 v16, v8

    .line 109
    .line 110
    move-object v8, v0

    .line 111
    move-object/from16 v0, v16

    .line 112
    .line 113
    :goto_2
    check-cast v0, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    const/4 v9, 0x0

    .line 120
    if-nez v0, :cond_4

    .line 121
    .line 122
    invoke-virtual {v7}, Lpw0/d;->d()V

    .line 123
    .line 124
    .line 125
    return-object v9

    .line 126
    :catchall_1
    move-exception v0

    .line 127
    move-object v3, v7

    .line 128
    goto/16 :goto_7

    .line 129
    .line 130
    :cond_4
    iget v0, v3, Lqw0/c;->j:I

    .line 131
    .line 132
    iput v0, v1, Lb8/i;->c:I

    .line 133
    .line 134
    iget v10, v1, Lb8/i;->b:I

    .line 135
    .line 136
    sub-int/2addr v0, v10

    .line 137
    if-eqz v0, :cond_c

    .line 138
    .line 139
    if-ge v0, v4, :cond_b

    .line 140
    .line 141
    invoke-static {v3, v1}, Lpw0/g;->b(Lqw0/c;Lb8/i;)I

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    iget v11, v1, Lb8/i;->c:I

    .line 146
    .line 147
    iget v12, v1, Lb8/i;->b:I

    .line 148
    .line 149
    :goto_3
    const/16 v13, 0x9

    .line 150
    .line 151
    if-ge v12, v11, :cond_6

    .line 152
    .line 153
    invoke-virtual {v3, v12}, Lqw0/c;->charAt(I)C

    .line 154
    .line 155
    .line 156
    move-result v14

    .line 157
    invoke-static {v14}, Lry/a;->d(C)Z

    .line 158
    .line 159
    .line 160
    move-result v15

    .line 161
    if-nez v15, :cond_5

    .line 162
    .line 163
    if-ne v14, v13, :cond_6

    .line 164
    .line 165
    :cond_5
    add-int/lit8 v12, v12, 0x1

    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_6
    if-lt v12, v11, :cond_7

    .line 169
    .line 170
    iput v11, v1, Lb8/i;->b:I

    .line 171
    .line 172
    goto :goto_6

    .line 173
    :cond_7
    move v14, v12

    .line 174
    move v15, v14

    .line 175
    :goto_4
    if-ge v14, v11, :cond_a

    .line 176
    .line 177
    invoke-virtual {v3, v14}, Lqw0/c;->charAt(I)C

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    if-eq v4, v13, :cond_9

    .line 182
    .line 183
    const/16 v5, 0xa

    .line 184
    .line 185
    if-eq v4, v5, :cond_8

    .line 186
    .line 187
    const/16 v5, 0xd

    .line 188
    .line 189
    if-eq v4, v5, :cond_8

    .line 190
    .line 191
    const/16 v5, 0x20

    .line 192
    .line 193
    if-eq v4, v5, :cond_9

    .line 194
    .line 195
    move v15, v14

    .line 196
    goto :goto_5

    .line 197
    :cond_8
    invoke-static {v3, v4}, Lpw0/g;->a(Lqw0/c;C)V

    .line 198
    .line 199
    .line 200
    throw v9

    .line 201
    :cond_9
    :goto_5
    add-int/lit8 v14, v14, 0x1

    .line 202
    .line 203
    const/16 v4, 0x2000

    .line 204
    .line 205
    const/4 v5, 0x1

    .line 206
    goto :goto_4

    .line 207
    :cond_a
    iput v12, v1, Lb8/i;->b:I

    .line 208
    .line 209
    add-int/lit8 v15, v15, 0x1

    .line 210
    .line 211
    iput v15, v1, Lb8/i;->c:I

    .line 212
    .line 213
    :goto_6
    iget v4, v1, Lb8/i;->b:I

    .line 214
    .line 215
    iget v5, v1, Lb8/i;->c:I

    .line 216
    .line 217
    iput v11, v1, Lb8/i;->b:I

    .line 218
    .line 219
    invoke-virtual {v7, v10, v0, v4, v5}, Lpw0/d;->c(IIII)V

    .line 220
    .line 221
    .line 222
    move-object v0, v8

    .line 223
    const/16 v4, 0x2000

    .line 224
    .line 225
    const/4 v5, 0x1

    .line 226
    goto/16 :goto_1

    .line 227
    .line 228
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 229
    .line 230
    const-string v1, "Header line length limit exceeded"

    .line 231
    .line 232
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    throw v0

    .line 236
    :cond_c
    sget-object v0, Low0/q;->a:Ljava/util/List;

    .line 237
    .line 238
    const-string v0, "Host"

    .line 239
    .line 240
    invoke-virtual {v7, v0}, Lpw0/d;->a(Ljava/lang/String;)Lqw0/b;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    if-eqz v0, :cond_d

    .line 245
    .line 246
    invoke-static {v0}, Lpw0/g;->d(Lqw0/b;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 247
    .line 248
    .line 249
    :cond_d
    return-object v7

    .line 250
    :goto_7
    invoke-virtual {v3}, Lpw0/d;->d()V

    .line 251
    .line 252
    .line 253
    throw v0
.end method

.method public static final d(Lqw0/b;)V
    .locals 3

    .line 1
    const-string v0, ":"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lly0/p;->E(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_2

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    :goto_0
    invoke-virtual {p0}, Lqw0/b;->length()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-ge v0, v1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lqw0/b;->charAt(I)C

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    sget-object v2, Lpw0/g;->a:Ljava/util/Set;

    .line 25
    .line 26
    invoke-interface {v2, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_0

    .line 31
    .line 32
    add-int/lit8 v0, v0, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    new-instance p0, Laq/c;

    .line 36
    .line 37
    new-instance v0, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v1, "Host cannot contain any of the following symbols: "

    .line 40
    .line 41
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-direct {p0, v0}, Laq/c;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_1
    return-void

    .line 56
    :cond_2
    new-instance v0, Laq/c;

    .line 57
    .line 58
    new-instance v1, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v2, "Host header with \':\' should contains port: "

    .line 61
    .line 62
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-direct {v0, p0}, Laq/c;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v0
.end method
