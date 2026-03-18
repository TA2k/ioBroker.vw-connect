.class public abstract Llp/fe;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/ArrayList;)Z
    .locals 14

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x2

    .line 6
    const/4 v2, 0x1

    .line 7
    if-ge v0, v1, :cond_0

    .line 8
    .line 9
    goto/16 :goto_4

    .line 10
    .line 11
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x0

    .line 16
    const-wide v3, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    const/16 v5, 0x20

    .line 22
    .line 23
    if-gt v0, v2, :cond_1

    .line 24
    .line 25
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 26
    .line 27
    goto/16 :goto_1

    .line 28
    .line 29
    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    move v8, v1

    .line 43
    :goto_0
    if-ge v8, v7, :cond_2

    .line 44
    .line 45
    add-int/lit8 v8, v8, 0x1

    .line 46
    .line 47
    invoke-virtual {p0, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v9

    .line 51
    move-object v10, v9

    .line 52
    check-cast v10, Ld4/q;

    .line 53
    .line 54
    check-cast v6, Ld4/q;

    .line 55
    .line 56
    invoke-virtual {v6}, Ld4/q;->g()Ld3/c;

    .line 57
    .line 58
    .line 59
    move-result-object v11

    .line 60
    invoke-virtual {v11}, Ld3/c;->b()J

    .line 61
    .line 62
    .line 63
    move-result-wide v11

    .line 64
    shr-long/2addr v11, v5

    .line 65
    long-to-int v11, v11

    .line 66
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 67
    .line 68
    .line 69
    move-result v11

    .line 70
    invoke-virtual {v10}, Ld4/q;->g()Ld3/c;

    .line 71
    .line 72
    .line 73
    move-result-object v12

    .line 74
    invoke-virtual {v12}, Ld3/c;->b()J

    .line 75
    .line 76
    .line 77
    move-result-wide v12

    .line 78
    shr-long/2addr v12, v5

    .line 79
    long-to-int v12, v12

    .line 80
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result v12

    .line 84
    sub-float/2addr v11, v12

    .line 85
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    invoke-virtual {v6}, Ld4/q;->g()Ld3/c;

    .line 90
    .line 91
    .line 92
    move-result-object v6

    .line 93
    invoke-virtual {v6}, Ld3/c;->b()J

    .line 94
    .line 95
    .line 96
    move-result-wide v12

    .line 97
    and-long/2addr v12, v3

    .line 98
    long-to-int v6, v12

    .line 99
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    invoke-virtual {v10}, Ld4/q;->g()Ld3/c;

    .line 104
    .line 105
    .line 106
    move-result-object v10

    .line 107
    invoke-virtual {v10}, Ld3/c;->b()J

    .line 108
    .line 109
    .line 110
    move-result-wide v12

    .line 111
    and-long/2addr v12, v3

    .line 112
    long-to-int v10, v12

    .line 113
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    sub-float/2addr v6, v10

    .line 118
    invoke-static {v6}, Ljava/lang/Math;->abs(F)F

    .line 119
    .line 120
    .line 121
    move-result v6

    .line 122
    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 123
    .line 124
    .line 125
    move-result v10

    .line 126
    int-to-long v10, v10

    .line 127
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 128
    .line 129
    .line 130
    move-result v6

    .line 131
    int-to-long v12, v6

    .line 132
    shl-long/2addr v10, v5

    .line 133
    and-long/2addr v12, v3

    .line 134
    or-long/2addr v10, v12

    .line 135
    new-instance v6, Ld3/b;

    .line 136
    .line 137
    invoke-direct {v6, v10, v11}, Ld3/b;-><init>(J)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-object v6, v9

    .line 144
    goto :goto_0

    .line 145
    :cond_2
    move-object p0, v0

    .line 146
    :goto_1
    move-object v0, p0

    .line 147
    check-cast v0, Ljava/util/Collection;

    .line 148
    .line 149
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    if-ne v0, v2, :cond_3

    .line 154
    .line 155
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    check-cast p0, Ld3/b;

    .line 160
    .line 161
    iget-wide v6, p0, Ld3/b;->a:J

    .line 162
    .line 163
    goto :goto_3

    .line 164
    :cond_3
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    if-eqz v0, :cond_4

    .line 169
    .line 170
    const-string v0, "Empty collection can\'t be reduced."

    .line 171
    .line 172
    invoke-static {v0}, Lv4/a;->c(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    :cond_4
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 180
    .line 181
    .line 182
    move-result v6

    .line 183
    if-gt v2, v6, :cond_5

    .line 184
    .line 185
    move v7, v2

    .line 186
    :goto_2
    invoke-interface {p0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v8

    .line 190
    check-cast v8, Ld3/b;

    .line 191
    .line 192
    iget-wide v8, v8, Ld3/b;->a:J

    .line 193
    .line 194
    check-cast v0, Ld3/b;

    .line 195
    .line 196
    iget-wide v10, v0, Ld3/b;->a:J

    .line 197
    .line 198
    invoke-static {v10, v11, v8, v9}, Ld3/b;->h(JJ)J

    .line 199
    .line 200
    .line 201
    move-result-wide v8

    .line 202
    new-instance v0, Ld3/b;

    .line 203
    .line 204
    invoke-direct {v0, v8, v9}, Ld3/b;-><init>(J)V

    .line 205
    .line 206
    .line 207
    if-eq v7, v6, :cond_5

    .line 208
    .line 209
    add-int/lit8 v7, v7, 0x1

    .line 210
    .line 211
    goto :goto_2

    .line 212
    :cond_5
    check-cast v0, Ld3/b;

    .line 213
    .line 214
    iget-wide v6, v0, Ld3/b;->a:J

    .line 215
    .line 216
    :goto_3
    shr-long v8, v6, v5

    .line 217
    .line 218
    long-to-int p0, v8

    .line 219
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    and-long/2addr v3, v6

    .line 224
    long-to-int v0, v3

    .line 225
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 226
    .line 227
    .line 228
    move-result v0

    .line 229
    cmpg-float p0, v0, p0

    .line 230
    .line 231
    if-gez p0, :cond_6

    .line 232
    .line 233
    :goto_4
    return v2

    .line 234
    :cond_6
    return v1
.end method

.method public static b(J)B
    .locals 4

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    shr-long v0, p0, v0

    .line 4
    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long v0, v0, v2

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    const-string v1, "out of range: %s"

    .line 15
    .line 16
    invoke-static {p0, p1, v1, v0}, Lkp/i9;->b(JLjava/lang/String;Z)V

    .line 17
    .line 18
    .line 19
    long-to-int p0, p0

    .line 20
    int-to-byte p0, p0

    .line 21
    return p0
.end method
