.class public final Lr11/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# instance fields
.field public final d:Ln11/b;

.field public final e:I

.field public final f:Z


# direct methods
.method public constructor <init>(Ln11/b;IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/o;->d:Ln11/b;

    .line 5
    .line 6
    iput p2, p0, Lr11/o;->e:I

    .line 7
    .line 8
    iput-boolean p3, p0, Lr11/o;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-boolean p0, p0, Lr11/o;->f:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x4

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x2

    .line 8
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    :try_start_0
    iget-object p0, p0, Lr11/o;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p0, p4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0, p2, p3}, Ln11/a;->b(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-gez p0, :cond_0

    .line 12
    .line 13
    neg-int p0, p0

    .line 14
    :cond_0
    rem-int/lit8 p0, p0, 0x64
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catch_0
    const/4 p0, -0x1

    .line 18
    :goto_0
    if-gez p0, :cond_1

    .line 19
    .line 20
    const p0, 0xfffd

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 27
    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/4 p2, 0x2

    .line 31
    invoke-static {p1, p0, p2}, Lr11/u;->a(Ljava/lang/Appendable;II)V

    .line 32
    .line 33
    .line 34
    :goto_1
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lr11/o;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p2, p0}, Lo11/b;->g(Ln11/b;)Z

    .line 4
    .line 5
    .line 6
    move-result p3

    .line 7
    if-eqz p3, :cond_1

    .line 8
    .line 9
    :try_start_0
    invoke-virtual {p2, p0}, Lo11/b;->b(Ln11/b;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-gez p0, :cond_0

    .line 14
    .line 15
    neg-int p0, p0

    .line 16
    :cond_0
    rem-int/lit8 p0, p0, 0x64
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catch_0
    :cond_1
    const/4 p0, -0x1

    .line 20
    :goto_0
    if-gez p0, :cond_2

    .line 21
    .line 22
    const p0, 0xfffd

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_2
    const/4 p2, 0x2

    .line 33
    invoke-static {p1, p0, p2}, Lr11/u;->a(Ljava/lang/Appendable;II)V

    .line 34
    .line 35
    .line 36
    :goto_1
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    iget-object v4, v2, Lr11/s;->a:Ljp/u1;

    .line 10
    .line 11
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    sub-int/2addr v5, v3

    .line 16
    iget-boolean v6, v0, Lr11/o;->f:Z

    .line 17
    .line 18
    iget-object v8, v0, Lr11/o;->d:Ln11/b;

    .line 19
    .line 20
    const/16 v9, 0x39

    .line 21
    .line 22
    const/4 v10, 0x2

    .line 23
    const/16 v12, 0x30

    .line 24
    .line 25
    if-nez v6, :cond_1

    .line 26
    .line 27
    invoke-static {v10, v5}, Ljava/lang/Math;->min(II)I

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-ge v5, v10, :cond_0

    .line 32
    .line 33
    not-int v0, v3

    .line 34
    return v0

    .line 35
    :cond_0
    const/16 v16, 0x1

    .line 36
    .line 37
    goto :goto_4

    .line 38
    :cond_1
    const/4 v6, 0x0

    .line 39
    const/4 v14, 0x0

    .line 40
    const/4 v15, 0x0

    .line 41
    :goto_0
    if-ge v6, v5, :cond_7

    .line 42
    .line 43
    add-int v11, v3, v6

    .line 44
    .line 45
    invoke-interface {v1, v11}, Ljava/lang/CharSequence;->charAt(I)C

    .line 46
    .line 47
    .line 48
    move-result v11

    .line 49
    const/16 v16, 0x1

    .line 50
    .line 51
    if-nez v6, :cond_5

    .line 52
    .line 53
    const/16 v13, 0x2d

    .line 54
    .line 55
    if-eq v11, v13, :cond_2

    .line 56
    .line 57
    const/16 v7, 0x2b

    .line 58
    .line 59
    if-ne v11, v7, :cond_5

    .line 60
    .line 61
    :cond_2
    if-ne v11, v13, :cond_3

    .line 62
    .line 63
    move/from16 v15, v16

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    const/4 v15, 0x0

    .line 67
    :goto_1
    if-eqz v15, :cond_4

    .line 68
    .line 69
    add-int/lit8 v6, v6, 0x1

    .line 70
    .line 71
    :goto_2
    move/from16 v14, v16

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_4
    add-int/lit8 v3, v3, 0x1

    .line 75
    .line 76
    add-int/lit8 v5, v5, -0x1

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_5
    if-lt v11, v12, :cond_8

    .line 80
    .line 81
    if-le v11, v9, :cond_6

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_7
    const/16 v16, 0x1

    .line 88
    .line 89
    :cond_8
    :goto_3
    if-nez v6, :cond_9

    .line 90
    .line 91
    not-int v0, v3

    .line 92
    return v0

    .line 93
    :cond_9
    if-nez v14, :cond_11

    .line 94
    .line 95
    if-eq v6, v10, :cond_a

    .line 96
    .line 97
    goto :goto_9

    .line 98
    :cond_a
    :goto_4
    invoke-interface {v1, v3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    if-lt v5, v12, :cond_10

    .line 103
    .line 104
    if-le v5, v9, :cond_b

    .line 105
    .line 106
    goto :goto_8

    .line 107
    :cond_b
    sub-int/2addr v5, v12

    .line 108
    add-int/lit8 v6, v3, 0x1

    .line 109
    .line 110
    invoke-interface {v1, v6}, Ljava/lang/CharSequence;->charAt(I)C

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-lt v1, v12, :cond_f

    .line 115
    .line 116
    if-le v1, v9, :cond_c

    .line 117
    .line 118
    goto :goto_7

    .line 119
    :cond_c
    shl-int/lit8 v6, v5, 0x3

    .line 120
    .line 121
    shl-int/lit8 v5, v5, 0x1

    .line 122
    .line 123
    add-int/2addr v6, v5

    .line 124
    add-int/2addr v6, v1

    .line 125
    sub-int/2addr v6, v12

    .line 126
    iget v0, v0, Lr11/o;->e:I

    .line 127
    .line 128
    add-int/lit8 v1, v0, -0x32

    .line 129
    .line 130
    const/16 v5, 0x64

    .line 131
    .line 132
    if-ltz v1, :cond_d

    .line 133
    .line 134
    rem-int/lit8 v0, v1, 0x64

    .line 135
    .line 136
    goto :goto_5

    .line 137
    :cond_d
    add-int/lit8 v0, v0, -0x31

    .line 138
    .line 139
    rem-int/2addr v0, v5

    .line 140
    add-int/lit8 v0, v0, 0x63

    .line 141
    .line 142
    :goto_5
    if-ge v6, v0, :cond_e

    .line 143
    .line 144
    move v11, v5

    .line 145
    goto :goto_6

    .line 146
    :cond_e
    const/4 v11, 0x0

    .line 147
    :goto_6
    add-int/2addr v1, v11

    .line 148
    sub-int/2addr v1, v0

    .line 149
    add-int/2addr v1, v6

    .line 150
    invoke-virtual {v2}, Lr11/s;->c()Lr11/q;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    invoke-virtual {v8, v4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    iput-object v2, v0, Lr11/q;->d:Ln11/a;

    .line 159
    .line 160
    iput v1, v0, Lr11/q;->e:I

    .line 161
    .line 162
    const/4 v1, 0x0

    .line 163
    iput-object v1, v0, Lr11/q;->f:Ljava/lang/String;

    .line 164
    .line 165
    iput-object v1, v0, Lr11/q;->g:Ljava/util/Locale;

    .line 166
    .line 167
    add-int/2addr v3, v10

    .line 168
    return v3

    .line 169
    :cond_f
    :goto_7
    not-int v0, v3

    .line 170
    return v0

    .line 171
    :cond_10
    :goto_8
    not-int v0, v3

    .line 172
    return v0

    .line 173
    :cond_11
    :goto_9
    const/16 v0, 0x9

    .line 174
    .line 175
    if-lt v6, v0, :cond_12

    .line 176
    .line 177
    add-int/2addr v6, v3

    .line 178
    invoke-interface {v1, v3, v6}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    goto :goto_c

    .line 191
    :cond_12
    if-eqz v15, :cond_13

    .line 192
    .line 193
    add-int/lit8 v0, v3, 0x1

    .line 194
    .line 195
    goto :goto_a

    .line 196
    :cond_13
    move v0, v3

    .line 197
    :goto_a
    add-int/lit8 v5, v0, 0x1

    .line 198
    .line 199
    :try_start_0
    invoke-interface {v1, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 200
    .line 201
    .line 202
    move-result v0
    :try_end_0
    .catch Ljava/lang/StringIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 203
    sub-int/2addr v0, v12

    .line 204
    add-int/2addr v6, v3

    .line 205
    :goto_b
    if-ge v5, v6, :cond_14

    .line 206
    .line 207
    shl-int/lit8 v3, v0, 0x3

    .line 208
    .line 209
    shl-int/lit8 v0, v0, 0x1

    .line 210
    .line 211
    add-int/2addr v3, v0

    .line 212
    add-int/lit8 v0, v5, 0x1

    .line 213
    .line 214
    invoke-interface {v1, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 215
    .line 216
    .line 217
    move-result v5

    .line 218
    add-int/2addr v5, v3

    .line 219
    add-int/lit8 v3, v5, -0x30

    .line 220
    .line 221
    move v5, v0

    .line 222
    move v0, v3

    .line 223
    goto :goto_b

    .line 224
    :cond_14
    if-eqz v15, :cond_15

    .line 225
    .line 226
    neg-int v0, v0

    .line 227
    :cond_15
    :goto_c
    invoke-virtual {v2}, Lr11/s;->c()Lr11/q;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    invoke-virtual {v8, v4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    iput-object v2, v1, Lr11/q;->d:Ln11/a;

    .line 236
    .line 237
    iput v0, v1, Lr11/q;->e:I

    .line 238
    .line 239
    const/4 v0, 0x0

    .line 240
    iput-object v0, v1, Lr11/q;->f:Ljava/lang/String;

    .line 241
    .line 242
    iput-object v0, v1, Lr11/q;->g:Ljava/util/Locale;

    .line 243
    .line 244
    return v6

    .line 245
    :catch_0
    not-int v0, v3

    .line 246
    return v0
.end method

.method public final e()I
    .locals 0

    .line 1
    const/4 p0, 0x2

    .line 2
    return p0
.end method
