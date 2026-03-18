.class public abstract Lly0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[I

.field public static final b:[I

.field public static final c:[I

.field public static final d:[J


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const/16 v0, 0x100

    .line 2
    .line 3
    new-array v1, v0, [I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    move v3, v2

    .line 7
    :goto_0
    const-string v4, "0123456789abcdef"

    .line 8
    .line 9
    if-ge v3, v0, :cond_0

    .line 10
    .line 11
    shr-int/lit8 v5, v3, 0x4

    .line 12
    .line 13
    invoke-virtual {v4, v5}, Ljava/lang/String;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    shl-int/lit8 v5, v5, 0x8

    .line 18
    .line 19
    and-int/lit8 v6, v3, 0xf

    .line 20
    .line 21
    invoke-virtual {v4, v6}, Ljava/lang/String;->charAt(I)C

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    or-int/2addr v4, v5

    .line 26
    aput v4, v1, v3

    .line 27
    .line 28
    add-int/lit8 v3, v3, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    sput-object v1, Lly0/d;->a:[I

    .line 32
    .line 33
    new-array v1, v0, [I

    .line 34
    .line 35
    move v3, v2

    .line 36
    :goto_1
    const-string v5, "0123456789ABCDEF"

    .line 37
    .line 38
    if-ge v3, v0, :cond_1

    .line 39
    .line 40
    shr-int/lit8 v6, v3, 0x4

    .line 41
    .line 42
    invoke-virtual {v5, v6}, Ljava/lang/String;->charAt(I)C

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    shl-int/lit8 v6, v6, 0x8

    .line 47
    .line 48
    and-int/lit8 v7, v3, 0xf

    .line 49
    .line 50
    invoke-virtual {v5, v7}, Ljava/lang/String;->charAt(I)C

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    or-int/2addr v5, v6

    .line 55
    aput v5, v1, v3

    .line 56
    .line 57
    add-int/lit8 v3, v3, 0x1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    sput-object v1, Lly0/d;->b:[I

    .line 61
    .line 62
    new-array v1, v0, [I

    .line 63
    .line 64
    move v3, v2

    .line 65
    :goto_2
    if-ge v3, v0, :cond_2

    .line 66
    .line 67
    const/4 v6, -0x1

    .line 68
    aput v6, v1, v3

    .line 69
    .line 70
    add-int/lit8 v3, v3, 0x1

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    move v3, v2

    .line 74
    move v6, v3

    .line 75
    :goto_3
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 76
    .line 77
    .line 78
    move-result v7

    .line 79
    if-ge v3, v7, :cond_3

    .line 80
    .line 81
    invoke-interface {v4, v3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    add-int/lit8 v8, v6, 0x1

    .line 86
    .line 87
    aput v6, v1, v7

    .line 88
    .line 89
    add-int/lit8 v3, v3, 0x1

    .line 90
    .line 91
    move v6, v8

    .line 92
    goto :goto_3

    .line 93
    :cond_3
    move v3, v2

    .line 94
    move v6, v3

    .line 95
    :goto_4
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    if-ge v3, v7, :cond_4

    .line 100
    .line 101
    invoke-interface {v5, v3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 102
    .line 103
    .line 104
    move-result v7

    .line 105
    add-int/lit8 v8, v6, 0x1

    .line 106
    .line 107
    aput v6, v1, v7

    .line 108
    .line 109
    add-int/lit8 v3, v3, 0x1

    .line 110
    .line 111
    move v6, v8

    .line 112
    goto :goto_4

    .line 113
    :cond_4
    sput-object v1, Lly0/d;->c:[I

    .line 114
    .line 115
    new-array v1, v0, [J

    .line 116
    .line 117
    move v3, v2

    .line 118
    :goto_5
    if-ge v3, v0, :cond_5

    .line 119
    .line 120
    const-wide/16 v6, -0x1

    .line 121
    .line 122
    aput-wide v6, v1, v3

    .line 123
    .line 124
    add-int/lit8 v3, v3, 0x1

    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_5
    move v0, v2

    .line 128
    move v3, v0

    .line 129
    :goto_6
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    if-ge v0, v6, :cond_6

    .line 134
    .line 135
    invoke-interface {v4, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    add-int/lit8 v7, v3, 0x1

    .line 140
    .line 141
    int-to-long v8, v3

    .line 142
    aput-wide v8, v1, v6

    .line 143
    .line 144
    add-int/lit8 v0, v0, 0x1

    .line 145
    .line 146
    move v3, v7

    .line 147
    goto :goto_6

    .line 148
    :cond_6
    move v0, v2

    .line 149
    :goto_7
    invoke-interface {v5}, Ljava/lang/CharSequence;->length()I

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    if-ge v2, v3, :cond_7

    .line 154
    .line 155
    invoke-interface {v5, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    add-int/lit8 v4, v0, 0x1

    .line 160
    .line 161
    int-to-long v6, v0

    .line 162
    aput-wide v6, v1, v3

    .line 163
    .line 164
    add-int/lit8 v2, v2, 0x1

    .line 165
    .line 166
    move v0, v4

    .line 167
    goto :goto_7

    .line 168
    :cond_7
    sput-object v1, Lly0/d;->d:[J

    .line 169
    .line 170
    return-void
.end method

.method public static final a(J)I
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, v0, p0

    .line 4
    .line 5
    if-gtz v0, :cond_0

    .line 6
    .line 7
    const-wide/32 v0, 0x7fffffff

    .line 8
    .line 9
    .line 10
    cmp-long v0, p0, v0

    .line 11
    .line 12
    if-gtz v0, :cond_0

    .line 13
    .line 14
    long-to-int p0, p0

    .line 15
    return p0

    .line 16
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v2, "The resulting string length is too big: "

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const/16 v2, 0xa

    .line 26
    .line 27
    invoke-static {v2, p0, p1}, Lpw/a;->c(IJ)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw v0
.end method

.method public static final b(IILjava/lang/String;)V
    .locals 2

    .line 1
    sub-int v0, p1, p0

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-lt v0, v1, :cond_2

    .line 5
    .line 6
    const/16 p1, 0x10

    .line 7
    .line 8
    if-le v0, p1, :cond_1

    .line 9
    .line 10
    add-int/2addr v0, p0

    .line 11
    sub-int/2addr v0, p1

    .line 12
    :goto_0
    if-ge p0, v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    const/16 v1, 0x30

    .line 19
    .line 20
    if-ne p1, v1, :cond_0

    .line 21
    .line 22
    add-int/lit8 p0, p0, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p1, Ljava/lang/NumberFormatException;

    .line 26
    .line 27
    const-string v0, "Expected the hexadecimal digit \'0\' at index "

    .line 28
    .line 29
    const-string v1, ", but was \'"

    .line 30
    .line 31
    invoke-static {v0, p0, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p2, p0}, Ljava/lang/String;->charAt(I)C

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, "\'.\nThe result won\'t fit the type being parsed."

    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-direct {p1, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p1

    .line 55
    :cond_1
    return-void

    .line 56
    :cond_2
    const-string v0, "at least"

    .line 57
    .line 58
    invoke-static {p0, p1, v1, p2, v0}, Lly0/d;->i(IIILjava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const/4 p0, 0x0

    .line 62
    throw p0
.end method

.method public static final c([BI[I[CI)I
    .locals 0

    .line 1
    aget-byte p0, p0, p1

    .line 2
    .line 3
    and-int/lit16 p0, p0, 0xff

    .line 4
    .line 5
    aget p0, p2, p0

    .line 6
    .line 7
    shr-int/lit8 p1, p0, 0x8

    .line 8
    .line 9
    int-to-char p1, p1

    .line 10
    aput-char p1, p3, p4

    .line 11
    .line 12
    add-int/lit8 p1, p4, 0x1

    .line 13
    .line 14
    and-int/lit16 p0, p0, 0xff

    .line 15
    .line 16
    int-to-char p0, p0

    .line 17
    aput-char p0, p3, p1

    .line 18
    .line 19
    add-int/lit8 p4, p4, 0x2

    .line 20
    .line 21
    return p4
.end method

.method public static d(Ljava/lang/String;)[B
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lly0/g;->d:Lly0/g;

    .line 4
    .line 5
    const-string v2, "format"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    const/4 v4, 0x0

    .line 19
    invoke-static {v4, v2, v3}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 20
    .line 21
    .line 22
    if-nez v2, :cond_0

    .line 23
    .line 24
    new-array v0, v4, [B

    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_0
    iget-object v1, v1, Lly0/g;->b:Lly0/e;

    .line 28
    .line 29
    iget-boolean v3, v1, Lly0/e;->a:Z

    .line 30
    .line 31
    const/4 v6, 0x1

    .line 32
    const-wide/16 v7, 0x2

    .line 33
    .line 34
    const/4 v9, 0x2

    .line 35
    if-eqz v3, :cond_6

    .line 36
    .line 37
    iget-boolean v3, v1, Lly0/e;->b:Z

    .line 38
    .line 39
    if-eqz v3, :cond_3

    .line 40
    .line 41
    and-int/lit8 v3, v2, 0x1

    .line 42
    .line 43
    if-eqz v3, :cond_1

    .line 44
    .line 45
    move-wide/from16 v18, v7

    .line 46
    .line 47
    :goto_0
    const/4 v10, 0x0

    .line 48
    goto :goto_3

    .line 49
    :cond_1
    shr-int/lit8 v3, v2, 0x1

    .line 50
    .line 51
    new-array v10, v3, [B

    .line 52
    .line 53
    move v11, v4

    .line 54
    move v12, v11

    .line 55
    :goto_1
    if-ge v11, v3, :cond_2

    .line 56
    .line 57
    invoke-static {v12, v0}, Lly0/d;->f(ILjava/lang/String;)B

    .line 58
    .line 59
    .line 60
    move-result v13

    .line 61
    aput-byte v13, v10, v11

    .line 62
    .line 63
    add-int/2addr v12, v9

    .line 64
    add-int/lit8 v11, v11, 0x1

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    move-wide/from16 v18, v7

    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_3
    int-to-long v10, v4

    .line 71
    add-long v12, v10, v7

    .line 72
    .line 73
    add-long/2addr v12, v10

    .line 74
    add-long/2addr v12, v10

    .line 75
    int-to-long v14, v2

    .line 76
    add-long v16, v14, v10

    .line 77
    .line 78
    move-wide/from16 v18, v7

    .line 79
    .line 80
    div-long v7, v16, v12

    .line 81
    .line 82
    long-to-int v3, v7

    .line 83
    int-to-long v7, v3

    .line 84
    mul-long/2addr v7, v12

    .line 85
    sub-long/2addr v7, v10

    .line 86
    cmp-long v7, v7, v14

    .line 87
    .line 88
    if-eqz v7, :cond_4

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_4
    new-array v10, v3, [B

    .line 92
    .line 93
    sub-int/2addr v3, v6

    .line 94
    move v7, v4

    .line 95
    move v8, v7

    .line 96
    :goto_2
    if-ge v7, v3, :cond_5

    .line 97
    .line 98
    invoke-static {v8, v0}, Lly0/d;->f(ILjava/lang/String;)B

    .line 99
    .line 100
    .line 101
    move-result v11

    .line 102
    aput-byte v11, v10, v7

    .line 103
    .line 104
    add-int/lit8 v8, v8, 0x2

    .line 105
    .line 106
    add-int/lit8 v7, v7, 0x1

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_5
    invoke-static {v8, v0}, Lly0/d;->f(ILjava/lang/String;)B

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    aput-byte v7, v10, v3

    .line 114
    .line 115
    :goto_3
    if-eqz v10, :cond_7

    .line 116
    .line 117
    return-object v10

    .line 118
    :cond_6
    move-wide/from16 v18, v7

    .line 119
    .line 120
    :cond_7
    iget-boolean v1, v1, Lly0/e;->c:Z

    .line 121
    .line 122
    if-lez v2, :cond_14

    .line 123
    .line 124
    int-to-long v7, v4

    .line 125
    add-long v10, v7, v18

    .line 126
    .line 127
    add-long/2addr v10, v7

    .line 128
    const v3, 0x7fffffff

    .line 129
    .line 130
    .line 131
    int-to-long v12, v3

    .line 132
    mul-long v14, v10, v12

    .line 133
    .line 134
    const-wide/16 v16, 0x1

    .line 135
    .line 136
    sub-long v18, v12, v16

    .line 137
    .line 138
    mul-long v18, v18, v7

    .line 139
    .line 140
    add-long v14, v18, v14

    .line 141
    .line 142
    int-to-long v3, v2

    .line 143
    invoke-static {v6, v3, v4, v14, v15}, Lly0/d;->n(IJJ)J

    .line 144
    .line 145
    .line 146
    move-result-wide v20

    .line 147
    add-long v16, v14, v16

    .line 148
    .line 149
    mul-long v16, v16, v20

    .line 150
    .line 151
    sub-long v3, v3, v16

    .line 152
    .line 153
    invoke-static {v9, v3, v4, v14, v15}, Lly0/d;->n(IJJ)J

    .line 154
    .line 155
    .line 156
    move-result-wide v16

    .line 157
    move/from16 v23, v6

    .line 158
    .line 159
    const/16 v22, 0x0

    .line 160
    .line 161
    int-to-long v5, v9

    .line 162
    add-long/2addr v14, v5

    .line 163
    mul-long v14, v14, v16

    .line 164
    .line 165
    sub-long/2addr v3, v14

    .line 166
    const/4 v5, 0x0

    .line 167
    invoke-static {v5, v3, v4, v10, v11}, Lly0/d;->n(IJJ)J

    .line 168
    .line 169
    .line 170
    move-result-wide v14

    .line 171
    add-long/2addr v10, v7

    .line 172
    mul-long/2addr v10, v14

    .line 173
    sub-long/2addr v3, v10

    .line 174
    const-wide/16 v6, 0x0

    .line 175
    .line 176
    cmp-long v3, v3, v6

    .line 177
    .line 178
    if-lez v3, :cond_8

    .line 179
    .line 180
    move/from16 v3, v23

    .line 181
    .line 182
    goto :goto_4

    .line 183
    :cond_8
    move v3, v5

    .line 184
    :goto_4
    mul-long v20, v20, v12

    .line 185
    .line 186
    mul-long v16, v16, v12

    .line 187
    .line 188
    add-long v16, v16, v20

    .line 189
    .line 190
    add-long v16, v16, v14

    .line 191
    .line 192
    int-to-long v3, v3

    .line 193
    add-long v3, v16, v3

    .line 194
    .line 195
    long-to-int v3, v3

    .line 196
    new-array v4, v3, [B

    .line 197
    .line 198
    move v6, v5

    .line 199
    move v7, v6

    .line 200
    move v8, v7

    .line 201
    move v10, v8

    .line 202
    :goto_5
    if-ge v6, v2, :cond_12

    .line 203
    .line 204
    const-string v11, ", but was "

    .line 205
    .line 206
    const v12, 0x7fffffff

    .line 207
    .line 208
    .line 209
    if-ne v8, v12, :cond_c

    .line 210
    .line 211
    invoke-virtual {v0, v6}, Ljava/lang/String;->charAt(I)C

    .line 212
    .line 213
    .line 214
    move-result v8

    .line 215
    const/16 v10, 0xd

    .line 216
    .line 217
    const/16 v12, 0xa

    .line 218
    .line 219
    if-ne v8, v10, :cond_a

    .line 220
    .line 221
    add-int/lit8 v8, v6, 0x1

    .line 222
    .line 223
    if-ge v8, v2, :cond_9

    .line 224
    .line 225
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 226
    .line 227
    .line 228
    move-result v10

    .line 229
    if-ne v10, v12, :cond_9

    .line 230
    .line 231
    add-int/lit8 v6, v6, 0x2

    .line 232
    .line 233
    goto :goto_6

    .line 234
    :cond_9
    move v6, v8

    .line 235
    goto :goto_6

    .line 236
    :cond_a
    invoke-virtual {v0, v6}, Ljava/lang/String;->charAt(I)C

    .line 237
    .line 238
    .line 239
    move-result v8

    .line 240
    if-ne v8, v12, :cond_b

    .line 241
    .line 242
    add-int/lit8 v6, v6, 0x1

    .line 243
    .line 244
    :goto_6
    move v8, v5

    .line 245
    move v10, v8

    .line 246
    const v12, 0x7fffffff

    .line 247
    .line 248
    .line 249
    goto :goto_9

    .line 250
    :cond_b
    new-instance v1, Ljava/lang/NumberFormatException;

    .line 251
    .line 252
    const-string v2, "Expected a new line at index "

    .line 253
    .line 254
    invoke-static {v2, v6, v11}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    invoke-virtual {v0, v6}, Ljava/lang/String;->charAt(I)C

    .line 259
    .line 260
    .line 261
    move-result v0

    .line 262
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    invoke-direct {v1, v0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    throw v1

    .line 273
    :cond_c
    if-ne v10, v12, :cond_10

    .line 274
    .line 275
    move v10, v5

    .line 276
    :goto_7
    if-ge v10, v9, :cond_f

    .line 277
    .line 278
    const-string v13, "  "

    .line 279
    .line 280
    invoke-virtual {v13, v10}, Ljava/lang/String;->charAt(I)C

    .line 281
    .line 282
    .line 283
    move-result v13

    .line 284
    add-int v14, v6, v10

    .line 285
    .line 286
    invoke-virtual {v0, v14}, Ljava/lang/String;->charAt(I)C

    .line 287
    .line 288
    .line 289
    move-result v14

    .line 290
    invoke-static {v13, v14, v1}, Lry/a;->c(CCZ)Z

    .line 291
    .line 292
    .line 293
    move-result v13

    .line 294
    if-eqz v13, :cond_d

    .line 295
    .line 296
    add-int/lit8 v10, v10, 0x1

    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_d
    add-int/2addr v9, v6

    .line 300
    if-le v9, v2, :cond_e

    .line 301
    .line 302
    goto :goto_8

    .line 303
    :cond_e
    move v2, v9

    .line 304
    :goto_8
    invoke-virtual {v0, v6, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    const-string v1, "substring(...)"

    .line 309
    .line 310
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    new-instance v1, Ljava/lang/NumberFormatException;

    .line 314
    .line 315
    new-instance v2, Ljava/lang/StringBuilder;

    .line 316
    .line 317
    const-string v3, "Expected group separator \"  \" at index "

    .line 318
    .line 319
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 323
    .line 324
    .line 325
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 326
    .line 327
    .line 328
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 329
    .line 330
    .line 331
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    invoke-direct {v1, v0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    throw v1

    .line 339
    :cond_f
    add-int/lit8 v6, v6, 0x2

    .line 340
    .line 341
    move v10, v5

    .line 342
    :cond_10
    :goto_9
    add-int/lit8 v8, v8, 0x1

    .line 343
    .line 344
    add-int/lit8 v10, v10, 0x1

    .line 345
    .line 346
    add-int/lit8 v11, v2, -0x2

    .line 347
    .line 348
    if-lt v11, v6, :cond_11

    .line 349
    .line 350
    add-int/lit8 v11, v7, 0x1

    .line 351
    .line 352
    invoke-static {v6, v0}, Lly0/d;->f(ILjava/lang/String;)B

    .line 353
    .line 354
    .line 355
    move-result v13

    .line 356
    aput-byte v13, v4, v7

    .line 357
    .line 358
    add-int/lit8 v6, v6, 0x2

    .line 359
    .line 360
    move v7, v11

    .line 361
    goto/16 :goto_5

    .line 362
    .line 363
    :cond_11
    const-string v1, "exactly"

    .line 364
    .line 365
    invoke-static {v6, v2, v9, v0, v1}, Lly0/d;->i(IIILjava/lang/String;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    throw v22

    .line 369
    :cond_12
    if-ne v7, v3, :cond_13

    .line 370
    .line 371
    return-object v4

    .line 372
    :cond_13
    invoke-static {v4, v7}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    const-string v1, "copyOf(...)"

    .line 377
    .line 378
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    return-object v0

    .line 382
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 383
    .line 384
    const-string v1, "Failed requirement."

    .line 385
    .line 386
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 387
    .line 388
    .line 389
    throw v0
.end method

.method public static e(IILjava/lang/String;)J
    .locals 2

    .line 1
    sget-object v0, Lly0/g;->d:Lly0/g;

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "format"

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-static {p0, p1, v1}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 18
    .line 19
    .line 20
    iget-object v0, v0, Lly0/g;->c:Lly0/f;

    .line 21
    .line 22
    iget-boolean v0, v0, Lly0/f;->a:Z

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-static {p0, p1, p2}, Lly0/d;->b(IILjava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {p0, p1, p2}, Lly0/d;->g(IILjava/lang/String;)J

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    return-wide p0

    .line 34
    :cond_0
    sub-int v0, p1, p0

    .line 35
    .line 36
    if-lez v0, :cond_1

    .line 37
    .line 38
    invoke-static {p0, p1, p2}, Lly0/d;->b(IILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {p0, p1, p2}, Lly0/d;->g(IILjava/lang/String;)J

    .line 42
    .line 43
    .line 44
    move-result-wide p0

    .line 45
    return-wide p0

    .line 46
    :cond_1
    invoke-virtual {p2, p0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    const-string p1, "substring(...)"

    .line 51
    .line 52
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    new-instance p1, Ljava/lang/NumberFormatException;

    .line 56
    .line 57
    const-string p2, "Expected a hexadecimal number with prefix \"\" and suffix \"\", but was "

    .line 58
    .line 59
    invoke-virtual {p2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {p1, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p1
.end method

.method public static final f(ILjava/lang/String;)B
    .locals 5

    .line 1
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    ushr-int/lit8 v1, v0, 0x8

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    sget-object v1, Lly0/d;->c:[I

    .line 11
    .line 12
    aget v0, v1, v0

    .line 13
    .line 14
    if-ltz v0, :cond_1

    .line 15
    .line 16
    add-int/lit8 p0, p0, 0x1

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    ushr-int/lit8 v4, v3, 0x8

    .line 23
    .line 24
    if-nez v4, :cond_0

    .line 25
    .line 26
    aget v1, v1, v3

    .line 27
    .line 28
    if-ltz v1, :cond_0

    .line 29
    .line 30
    shl-int/lit8 p0, v0, 0x4

    .line 31
    .line 32
    or-int/2addr p0, v1

    .line 33
    int-to-byte p0, p0

    .line 34
    return p0

    .line 35
    :cond_0
    invoke-static {p0, p1}, Lly0/d;->h(ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v2

    .line 39
    :cond_1
    invoke-static {p0, p1}, Lly0/d;->h(ILjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v2
.end method

.method public static final g(IILjava/lang/String;)J
    .locals 7

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    move-wide v2, v0

    .line 4
    :goto_0
    if-ge p0, p1, :cond_1

    .line 5
    .line 6
    const/4 v4, 0x4

    .line 7
    shl-long/2addr v2, v4

    .line 8
    invoke-virtual {p2, p0}, Ljava/lang/String;->charAt(I)C

    .line 9
    .line 10
    .line 11
    move-result v4

    .line 12
    ushr-int/lit8 v5, v4, 0x8

    .line 13
    .line 14
    if-nez v5, :cond_0

    .line 15
    .line 16
    sget-object v5, Lly0/d;->d:[J

    .line 17
    .line 18
    aget-wide v4, v5, v4

    .line 19
    .line 20
    cmp-long v6, v4, v0

    .line 21
    .line 22
    if-ltz v6, :cond_0

    .line 23
    .line 24
    or-long/2addr v2, v4

    .line 25
    add-int/lit8 p0, p0, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-static {p0, p2}, Lly0/d;->h(ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    throw p0

    .line 33
    :cond_1
    return-wide v2
.end method

.method public static final h(ILjava/lang/String;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/NumberFormatException;

    .line 2
    .line 3
    const-string v1, "Expected a hexadecimal digit at index "

    .line 4
    .line 5
    const-string v2, ", but was "

    .line 6
    .line 7
    invoke-static {v1, p0, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1, p0}, Ljava/lang/String;->charAt(I)C

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-direct {v0, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw v0
.end method

.method public static final i(IIILjava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "null cannot be cast to non-null type java.lang.String"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, p0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p3

    .line 10
    const-string v0, "substring(...)"

    .line 11
    .line 12
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Ljava/lang/NumberFormatException;

    .line 16
    .line 17
    new-instance v1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v2, "Expected "

    .line 20
    .line 21
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const/16 p4, 0x20

    .line 28
    .line 29
    invoke-virtual {v1, p4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string p2, " hexadecimal digits at index "

    .line 36
    .line 37
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p2, ", but was \""

    .line 44
    .line 45
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string p2, "\" of length "

    .line 52
    .line 53
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    sub-int/2addr p1, p0

    .line 57
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-direct {v0, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0
.end method

.method public static final j(Ljava/lang/String;[CI)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    const/4 v2, 0x0

    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-virtual {p0, v2, v0, p1, p2}, Ljava/lang/String;->getChars(II[CI)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    aput-char v0, p1, p2

    .line 24
    .line 25
    :cond_1
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    add-int/2addr p0, p2

    .line 30
    return p0
.end method

.method public static final k(BLly0/g;)Ljava/lang/String;
    .locals 3

    .line 1
    const-string v0, "format"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p1, Lly0/g;->a:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const-string v0, "0123456789ABCDEF"

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string v0, "0123456789abcdef"

    .line 14
    .line 15
    :goto_0
    iget-object p1, p1, Lly0/g;->c:Lly0/f;

    .line 16
    .line 17
    iget-boolean v1, p1, Lly0/f;->b:Z

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    shr-int/lit8 p1, p0, 0x4

    .line 22
    .line 23
    and-int/lit8 p1, p1, 0xf

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Ljava/lang/String;->charAt(I)C

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    and-int/lit8 p0, p0, 0xf

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/String;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    const/4 v0, 0x2

    .line 36
    new-array v0, v0, [C

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    aput-char p1, v0, v1

    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    aput-char p0, v0, p1

    .line 43
    .line 44
    new-instance p0, Ljava/lang/String;

    .line 45
    .line 46
    invoke-direct {p0, v0}, Ljava/lang/String;-><init>([C)V

    .line 47
    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_1
    int-to-long v1, p0

    .line 51
    const/16 p0, 0x8

    .line 52
    .line 53
    invoke-static {v1, v2, p1, v0, p0}, Lly0/d;->m(JLly0/f;Ljava/lang/String;I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public static l([B)Ljava/lang/String;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lly0/g;->d:Lly0/g;

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "format"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    array-length v2, v0

    .line 16
    array-length v3, v0

    .line 17
    const/4 v4, 0x0

    .line 18
    invoke-static {v4, v2, v3}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 19
    .line 20
    .line 21
    const-string v3, ""

    .line 22
    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    return-object v3

    .line 26
    :cond_0
    iget-boolean v5, v1, Lly0/g;->a:Z

    .line 27
    .line 28
    if-eqz v5, :cond_1

    .line 29
    .line 30
    sget-object v5, Lly0/d;->b:[I

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    sget-object v5, Lly0/d;->a:[I

    .line 34
    .line 35
    :goto_0
    iget-object v1, v1, Lly0/g;->b:Lly0/e;

    .line 36
    .line 37
    iget-boolean v6, v1, Lly0/e;->a:Z

    .line 38
    .line 39
    const/4 v7, 0x1

    .line 40
    const-string v8, "Failed requirement."

    .line 41
    .line 42
    const-wide/16 v9, 0x2

    .line 43
    .line 44
    if-eqz v6, :cond_6

    .line 45
    .line 46
    iget-boolean v1, v1, Lly0/e;->b:Z

    .line 47
    .line 48
    if-eqz v1, :cond_3

    .line 49
    .line 50
    int-to-long v6, v2

    .line 51
    mul-long/2addr v6, v9

    .line 52
    invoke-static {v6, v7}, Lly0/d;->a(J)I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    new-array v1, v1, [C

    .line 57
    .line 58
    move v3, v4

    .line 59
    :goto_1
    if-ge v4, v2, :cond_2

    .line 60
    .line 61
    invoke-static {v0, v4, v5, v1, v3}, Lly0/d;->c([BI[I[CI)I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    add-int/lit8 v4, v4, 0x1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    new-instance v0, Ljava/lang/String;

    .line 69
    .line 70
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>([C)V

    .line 71
    .line 72
    .line 73
    return-object v0

    .line 74
    :cond_3
    if-lez v2, :cond_5

    .line 75
    .line 76
    int-to-long v11, v4

    .line 77
    add-long/2addr v9, v11

    .line 78
    add-long/2addr v9, v11

    .line 79
    add-long/2addr v9, v11

    .line 80
    int-to-long v13, v2

    .line 81
    mul-long/2addr v13, v9

    .line 82
    sub-long/2addr v13, v11

    .line 83
    invoke-static {v13, v14}, Lly0/d;->a(J)I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    new-array v1, v1, [C

    .line 88
    .line 89
    invoke-static {v3, v1, v4}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 90
    .line 91
    .line 92
    move-result v6

    .line 93
    invoke-static {v0, v4, v5, v1, v6}, Lly0/d;->c([BI[I[CI)I

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    invoke-static {v3, v1, v4}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    :goto_2
    if-ge v7, v2, :cond_4

    .line 102
    .line 103
    invoke-static {v3, v1, v4}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    invoke-static {v3, v1, v4}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    invoke-static {v0, v7, v5, v1, v4}, Lly0/d;->c([BI[I[CI)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    invoke-static {v3, v1, v4}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    add-int/lit8 v7, v7, 0x1

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_4
    new-instance v0, Ljava/lang/String;

    .line 123
    .line 124
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>([C)V

    .line 125
    .line 126
    .line 127
    return-object v0

    .line 128
    :cond_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 129
    .line 130
    invoke-direct {v0, v8}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw v0

    .line 134
    :cond_6
    if-lez v2, :cond_d

    .line 135
    .line 136
    add-int/lit8 v1, v2, -0x1

    .line 137
    .line 138
    const v6, 0x7fffffff

    .line 139
    .line 140
    .line 141
    div-int v8, v1, v6

    .line 142
    .line 143
    rem-int v11, v2, v6

    .line 144
    .line 145
    if-nez v11, :cond_7

    .line 146
    .line 147
    move v11, v6

    .line 148
    :cond_7
    sub-int/2addr v11, v7

    .line 149
    div-int/2addr v11, v6

    .line 150
    sub-int/2addr v1, v8

    .line 151
    sub-int/2addr v1, v11

    .line 152
    int-to-long v12, v8

    .line 153
    int-to-long v14, v11

    .line 154
    const/4 v8, 0x2

    .line 155
    move v11, v7

    .line 156
    int-to-long v7, v8

    .line 157
    mul-long/2addr v14, v7

    .line 158
    add-long/2addr v14, v12

    .line 159
    int-to-long v7, v1

    .line 160
    int-to-long v12, v4

    .line 161
    mul-long/2addr v7, v12

    .line 162
    add-long/2addr v7, v14

    .line 163
    int-to-long v14, v2

    .line 164
    add-long/2addr v9, v12

    .line 165
    add-long/2addr v9, v12

    .line 166
    mul-long/2addr v9, v14

    .line 167
    add-long/2addr v9, v7

    .line 168
    invoke-static {v9, v10}, Lly0/d;->a(J)I

    .line 169
    .line 170
    .line 171
    move-result v1

    .line 172
    new-array v7, v1, [C

    .line 173
    .line 174
    move v8, v4

    .line 175
    move v9, v8

    .line 176
    move v10, v9

    .line 177
    move v12, v10

    .line 178
    :goto_3
    if-ge v8, v2, :cond_b

    .line 179
    .line 180
    if-ne v10, v6, :cond_8

    .line 181
    .line 182
    add-int/lit8 v10, v9, 0x1

    .line 183
    .line 184
    const/16 v12, 0xa

    .line 185
    .line 186
    aput-char v12, v7, v9

    .line 187
    .line 188
    move v12, v4

    .line 189
    move v9, v10

    .line 190
    move v10, v12

    .line 191
    goto :goto_4

    .line 192
    :cond_8
    if-ne v12, v6, :cond_9

    .line 193
    .line 194
    const-string v12, "  "

    .line 195
    .line 196
    invoke-static {v12, v7, v9}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 197
    .line 198
    .line 199
    move-result v9

    .line 200
    move v12, v4

    .line 201
    :cond_9
    :goto_4
    if-eqz v12, :cond_a

    .line 202
    .line 203
    invoke-static {v3, v7, v9}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 204
    .line 205
    .line 206
    move-result v9

    .line 207
    :cond_a
    invoke-static {v3, v7, v9}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 208
    .line 209
    .line 210
    move-result v9

    .line 211
    invoke-static {v0, v8, v5, v7, v9}, Lly0/d;->c([BI[I[CI)I

    .line 212
    .line 213
    .line 214
    move-result v9

    .line 215
    invoke-static {v3, v7, v9}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 216
    .line 217
    .line 218
    move-result v9

    .line 219
    add-int/lit8 v12, v12, 0x1

    .line 220
    .line 221
    add-int/2addr v10, v11

    .line 222
    add-int/lit8 v8, v8, 0x1

    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_b
    if-ne v9, v1, :cond_c

    .line 226
    .line 227
    new-instance v0, Ljava/lang/String;

    .line 228
    .line 229
    invoke-direct {v0, v7}, Ljava/lang/String;-><init>([C)V

    .line 230
    .line 231
    .line 232
    return-object v0

    .line 233
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 234
    .line 235
    const-string v1, "Check failed."

    .line 236
    .line 237
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    throw v0

    .line 241
    :cond_d
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 242
    .line 243
    invoke-direct {v0, v8}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    throw v0
.end method

.method public static final m(JLly0/f;Ljava/lang/String;I)Ljava/lang/String;
    .locals 10

    .line 1
    shr-int/lit8 v0, p4, 0x2

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    rsub-int/lit8 p2, v0, 0x1

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-gez p2, :cond_0

    .line 10
    .line 11
    move p2, v1

    .line 12
    :cond_0
    int-to-long v2, v1

    .line 13
    int-to-long v4, p2

    .line 14
    add-long/2addr v4, v2

    .line 15
    int-to-long v6, v0

    .line 16
    add-long/2addr v4, v6

    .line 17
    add-long/2addr v4, v2

    .line 18
    invoke-static {v4, v5}, Lly0/d;->a(J)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    new-array v3, v2, [C

    .line 23
    .line 24
    const-string v4, ""

    .line 25
    .line 26
    invoke-static {v4, v3, v1}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-lez p2, :cond_1

    .line 31
    .line 32
    invoke-virtual {p3, v1}, Ljava/lang/String;->charAt(I)C

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    add-int/2addr p2, v5

    .line 37
    invoke-static {v3, v5, p2, v6}, Ljava/util/Arrays;->fill([CIIC)V

    .line 38
    .line 39
    .line 40
    move v5, p2

    .line 41
    :cond_1
    move p2, v1

    .line 42
    :goto_0
    if-ge p2, v0, :cond_2

    .line 43
    .line 44
    add-int/lit8 p4, p4, -0x4

    .line 45
    .line 46
    shr-long v6, p0, p4

    .line 47
    .line 48
    const-wide/16 v8, 0xf

    .line 49
    .line 50
    and-long/2addr v6, v8

    .line 51
    long-to-int v6, v6

    .line 52
    add-int/lit8 v7, v5, 0x1

    .line 53
    .line 54
    invoke-virtual {p3, v6}, Ljava/lang/String;->charAt(I)C

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    aput-char v6, v3, v5

    .line 59
    .line 60
    add-int/lit8 p2, p2, 0x1

    .line 61
    .line 62
    move v5, v7

    .line 63
    goto :goto_0

    .line 64
    :cond_2
    invoke-static {v4, v3, v5}, Lly0/d;->j(Ljava/lang/String;[CI)I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-ne p0, v2, :cond_3

    .line 69
    .line 70
    new-instance p0, Ljava/lang/String;

    .line 71
    .line 72
    invoke-direct {p0, v3}, Ljava/lang/String;-><init>([C)V

    .line 73
    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_3
    invoke-static {v3, v1, p0}, Lly0/w;->k([CII)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0
.end method

.method public static final n(IJJ)J
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-lez v2, :cond_1

    .line 6
    .line 7
    cmp-long v2, p3, v0

    .line 8
    .line 9
    if-gtz v2, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    int-to-long v0, p0

    .line 13
    add-long/2addr p1, v0

    .line 14
    add-long/2addr p3, v0

    .line 15
    div-long/2addr p1, p3

    .line 16
    return-wide p1

    .line 17
    :cond_1
    :goto_0
    return-wide v0
.end method
