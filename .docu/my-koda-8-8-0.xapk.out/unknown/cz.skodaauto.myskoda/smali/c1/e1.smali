.class public final Lc1/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:F

.field public b:D

.field public c:F


# virtual methods
.method public final a(JFF)J
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p4

    .line 4
    .line 5
    iget v2, v0, Lc1/e1;->a:F

    .line 6
    .line 7
    sub-float v2, p3, v2

    .line 8
    .line 9
    move-wide/from16 v3, p1

    .line 10
    .line 11
    long-to-double v3, v3

    .line 12
    const-wide v5, 0x408f400000000000L    # 1000.0

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    div-double/2addr v3, v5

    .line 18
    iget v5, v0, Lc1/e1;->c:F

    .line 19
    .line 20
    float-to-double v6, v5

    .line 21
    float-to-double v8, v5

    .line 22
    mul-double/2addr v6, v8

    .line 23
    neg-float v8, v5

    .line 24
    float-to-double v8, v8

    .line 25
    iget-wide v10, v0, Lc1/e1;->b:D

    .line 26
    .line 27
    mul-double/2addr v8, v10

    .line 28
    const/high16 v12, 0x3f800000    # 1.0f

    .line 29
    .line 30
    cmpl-float v13, v5, v12

    .line 31
    .line 32
    const/4 v14, 0x1

    .line 33
    if-lez v13, :cond_0

    .line 34
    .line 35
    int-to-double v12, v14

    .line 36
    sub-double/2addr v6, v12

    .line 37
    invoke-static {v6, v7}, Ljava/lang/Math;->sqrt(D)D

    .line 38
    .line 39
    .line 40
    move-result-wide v5

    .line 41
    mul-double/2addr v5, v10

    .line 42
    add-double v10, v8, v5

    .line 43
    .line 44
    sub-double/2addr v8, v5

    .line 45
    float-to-double v5, v2

    .line 46
    mul-double v12, v8, v5

    .line 47
    .line 48
    float-to-double v1, v1

    .line 49
    sub-double/2addr v12, v1

    .line 50
    sub-double v1, v8, v10

    .line 51
    .line 52
    div-double/2addr v12, v1

    .line 53
    sub-double/2addr v5, v12

    .line 54
    mul-double v1, v8, v3

    .line 55
    .line 56
    invoke-static {v1, v2}, Ljava/lang/Math;->exp(D)D

    .line 57
    .line 58
    .line 59
    move-result-wide v14

    .line 60
    mul-double/2addr v14, v5

    .line 61
    mul-double/2addr v3, v10

    .line 62
    invoke-static {v3, v4}, Ljava/lang/Math;->exp(D)D

    .line 63
    .line 64
    .line 65
    move-result-wide v16

    .line 66
    mul-double v16, v16, v12

    .line 67
    .line 68
    add-double v16, v16, v14

    .line 69
    .line 70
    mul-double/2addr v5, v8

    .line 71
    invoke-static {v1, v2}, Ljava/lang/Math;->exp(D)D

    .line 72
    .line 73
    .line 74
    move-result-wide v1

    .line 75
    mul-double/2addr v1, v5

    .line 76
    mul-double/2addr v12, v10

    .line 77
    invoke-static {v3, v4}, Ljava/lang/Math;->exp(D)D

    .line 78
    .line 79
    .line 80
    move-result-wide v3

    .line 81
    mul-double/2addr v3, v12

    .line 82
    :goto_0
    add-double/2addr v3, v1

    .line 83
    goto :goto_1

    .line 84
    :cond_0
    cmpg-float v5, v5, v12

    .line 85
    .line 86
    if-nez v5, :cond_1

    .line 87
    .line 88
    float-to-double v5, v1

    .line 89
    float-to-double v1, v2

    .line 90
    mul-double v7, v10, v1

    .line 91
    .line 92
    add-double/2addr v7, v5

    .line 93
    neg-double v5, v10

    .line 94
    mul-double/2addr v5, v3

    .line 95
    mul-double/2addr v3, v7

    .line 96
    add-double/2addr v3, v1

    .line 97
    invoke-static {v5, v6}, Ljava/lang/Math;->exp(D)D

    .line 98
    .line 99
    .line 100
    move-result-wide v1

    .line 101
    mul-double v16, v1, v3

    .line 102
    .line 103
    invoke-static {v5, v6}, Ljava/lang/Math;->exp(D)D

    .line 104
    .line 105
    .line 106
    move-result-wide v1

    .line 107
    mul-double/2addr v1, v3

    .line 108
    iget-wide v3, v0, Lc1/e1;->b:D

    .line 109
    .line 110
    neg-double v3, v3

    .line 111
    mul-double/2addr v1, v3

    .line 112
    invoke-static {v5, v6}, Ljava/lang/Math;->exp(D)D

    .line 113
    .line 114
    .line 115
    move-result-wide v3

    .line 116
    mul-double/2addr v3, v7

    .line 117
    goto :goto_0

    .line 118
    :cond_1
    int-to-double v12, v14

    .line 119
    sub-double v5, v12, v6

    .line 120
    .line 121
    invoke-static {v5, v6}, Ljava/lang/Math;->sqrt(D)D

    .line 122
    .line 123
    .line 124
    move-result-wide v5

    .line 125
    mul-double/2addr v5, v10

    .line 126
    div-double/2addr v12, v5

    .line 127
    neg-double v10, v8

    .line 128
    float-to-double v14, v2

    .line 129
    mul-double/2addr v10, v14

    .line 130
    float-to-double v1, v1

    .line 131
    add-double/2addr v10, v1

    .line 132
    mul-double/2addr v10, v12

    .line 133
    mul-double v1, v5, v3

    .line 134
    .line 135
    mul-double/2addr v3, v8

    .line 136
    invoke-static {v3, v4}, Ljava/lang/Math;->exp(D)D

    .line 137
    .line 138
    .line 139
    move-result-wide v12

    .line 140
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 141
    .line 142
    .line 143
    move-result-wide v16

    .line 144
    mul-double v16, v16, v14

    .line 145
    .line 146
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 147
    .line 148
    .line 149
    move-result-wide v18

    .line 150
    mul-double v18, v18, v10

    .line 151
    .line 152
    add-double v18, v18, v16

    .line 153
    .line 154
    mul-double v16, v18, v12

    .line 155
    .line 156
    mul-double v8, v8, v16

    .line 157
    .line 158
    invoke-static {v3, v4}, Ljava/lang/Math;->exp(D)D

    .line 159
    .line 160
    .line 161
    move-result-wide v3

    .line 162
    neg-double v12, v5

    .line 163
    mul-double/2addr v12, v14

    .line 164
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 165
    .line 166
    .line 167
    move-result-wide v14

    .line 168
    mul-double/2addr v14, v12

    .line 169
    mul-double/2addr v5, v10

    .line 170
    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    .line 171
    .line 172
    .line 173
    move-result-wide v1

    .line 174
    mul-double/2addr v1, v5

    .line 175
    add-double/2addr v1, v14

    .line 176
    mul-double/2addr v1, v3

    .line 177
    add-double v3, v1, v8

    .line 178
    .line 179
    :goto_1
    iget v0, v0, Lc1/e1;->a:F

    .line 180
    .line 181
    float-to-double v0, v0

    .line 182
    add-double v0, v16, v0

    .line 183
    .line 184
    double-to-float v0, v0

    .line 185
    double-to-float v1, v3

    .line 186
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    int-to-long v2, v0

    .line 191
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    int-to-long v0, v0

    .line 196
    const/16 v4, 0x20

    .line 197
    .line 198
    shl-long/2addr v2, v4

    .line 199
    const-wide v4, 0xffffffffL

    .line 200
    .line 201
    .line 202
    .line 203
    .line 204
    and-long/2addr v0, v4

    .line 205
    or-long/2addr v0, v2

    .line 206
    return-wide v0
.end method
