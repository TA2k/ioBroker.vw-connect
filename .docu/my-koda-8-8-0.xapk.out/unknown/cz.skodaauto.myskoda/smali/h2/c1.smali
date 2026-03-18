.class public abstract Lh2/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    int-to-float v0, v0

    .line 3
    sput v0, Lh2/c1;->a:F

    .line 4
    .line 5
    return-void
.end method

.method public static a(JJJJJJLl2/o;)Lh2/b1;
    .locals 33

    .line 1
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 2
    .line 3
    move-object/from16 v1, p12

    .line 4
    .line 5
    check-cast v1, Ll2/t;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lh2/f1;

    .line 12
    .line 13
    iget-object v1, v0, Lh2/f1;->Z:Lh2/b1;

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    new-instance v2, Lh2/b1;

    .line 18
    .line 19
    sget-object v1, Lk2/h;->c:Lk2/l;

    .line 20
    .line 21
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v3

    .line 25
    sget-wide v5, Le3/s;->h:J

    .line 26
    .line 27
    sget-object v1, Lk2/h;->a:Lk2/l;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v7

    .line 33
    sget-object v9, Lk2/h;->b:Lk2/l;

    .line 34
    .line 35
    invoke-static {v0, v9}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 36
    .line 37
    .line 38
    move-result-wide v10

    .line 39
    const v12, 0x3ec28f5c    # 0.38f

    .line 40
    .line 41
    .line 42
    invoke-static {v10, v11, v12}, Le3/s;->b(JF)J

    .line 43
    .line 44
    .line 45
    move-result-wide v10

    .line 46
    invoke-static {v0, v9}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 47
    .line 48
    .line 49
    move-result-wide v13

    .line 50
    invoke-static {v13, v14, v12}, Le3/s;->b(JF)J

    .line 51
    .line 52
    .line 53
    move-result-wide v15

    .line 54
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 55
    .line 56
    .line 57
    move-result-wide v17

    .line 58
    sget-object v1, Lk2/h;->f:Lk2/l;

    .line 59
    .line 60
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 61
    .line 62
    .line 63
    move-result-wide v19

    .line 64
    invoke-static {v0, v9}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 65
    .line 66
    .line 67
    move-result-wide v13

    .line 68
    invoke-static {v13, v14, v12}, Le3/s;->b(JF)J

    .line 69
    .line 70
    .line 71
    move-result-wide v21

    .line 72
    sget-object v1, Lk2/h;->e:Lk2/l;

    .line 73
    .line 74
    invoke-static {v0, v1}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 75
    .line 76
    .line 77
    move-result-wide v13

    .line 78
    invoke-static {v13, v14, v12}, Le3/s;->b(JF)J

    .line 79
    .line 80
    .line 81
    move-result-wide v23

    .line 82
    invoke-static {v0, v9}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 83
    .line 84
    .line 85
    move-result-wide v13

    .line 86
    invoke-static {v13, v14, v12}, Le3/s;->b(JF)J

    .line 87
    .line 88
    .line 89
    move-result-wide v25

    .line 90
    move-wide v11, v10

    .line 91
    move-wide v9, v5

    .line 92
    move-wide v13, v5

    .line 93
    invoke-direct/range {v2 .. v26}, Lh2/b1;-><init>(JJJJJJJJJJJJ)V

    .line 94
    .line 95
    .line 96
    iput-object v2, v0, Lh2/f1;->Z:Lh2/b1;

    .line 97
    .line 98
    move-object v1, v2

    .line 99
    :cond_0
    sget-wide v2, Le3/s;->h:J

    .line 100
    .line 101
    const-wide/16 v4, 0x10

    .line 102
    .line 103
    cmp-long v0, p4, v4

    .line 104
    .line 105
    if-eqz v0, :cond_1

    .line 106
    .line 107
    move-wide/from16 v9, p4

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_1
    iget-wide v6, v1, Lh2/b1;->a:J

    .line 111
    .line 112
    move-wide v9, v6

    .line 113
    :goto_0
    cmp-long v0, v2, v4

    .line 114
    .line 115
    if-eqz v0, :cond_2

    .line 116
    .line 117
    move-wide v11, v2

    .line 118
    goto :goto_1

    .line 119
    :cond_2
    iget-wide v6, v1, Lh2/b1;->b:J

    .line 120
    .line 121
    move-wide v11, v6

    .line 122
    :goto_1
    cmp-long v6, p0, v4

    .line 123
    .line 124
    if-eqz v6, :cond_3

    .line 125
    .line 126
    move-wide/from16 v13, p0

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_3
    iget-wide v7, v1, Lh2/b1;->c:J

    .line 130
    .line 131
    move-wide v13, v7

    .line 132
    :goto_2
    if-eqz v0, :cond_4

    .line 133
    .line 134
    move-wide v15, v2

    .line 135
    goto :goto_3

    .line 136
    :cond_4
    iget-wide v7, v1, Lh2/b1;->d:J

    .line 137
    .line 138
    move-wide v15, v7

    .line 139
    :goto_3
    cmp-long v7, p6, v4

    .line 140
    .line 141
    if-eqz v7, :cond_5

    .line 142
    .line 143
    move-wide/from16 v17, v4

    .line 144
    .line 145
    move-wide/from16 v4, p6

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_5
    move-wide/from16 v17, v4

    .line 149
    .line 150
    iget-wide v4, v1, Lh2/b1;->e:J

    .line 151
    .line 152
    :goto_4
    if-eqz v0, :cond_6

    .line 153
    .line 154
    :goto_5
    move-wide/from16 v19, v2

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_6
    iget-wide v2, v1, Lh2/b1;->f:J

    .line 158
    .line 159
    goto :goto_5

    .line 160
    :goto_6
    cmp-long v0, p10, v17

    .line 161
    .line 162
    if-eqz v0, :cond_7

    .line 163
    .line 164
    move-wide/from16 v21, p10

    .line 165
    .line 166
    goto :goto_7

    .line 167
    :cond_7
    iget-wide v2, v1, Lh2/b1;->g:J

    .line 168
    .line 169
    move-wide/from16 v21, v2

    .line 170
    .line 171
    :goto_7
    if-eqz v6, :cond_8

    .line 172
    .line 173
    move-wide/from16 v23, p0

    .line 174
    .line 175
    goto :goto_8

    .line 176
    :cond_8
    iget-wide v2, v1, Lh2/b1;->h:J

    .line 177
    .line 178
    move-wide/from16 v23, v2

    .line 179
    .line 180
    :goto_8
    cmp-long v2, p2, v17

    .line 181
    .line 182
    if-eqz v2, :cond_9

    .line 183
    .line 184
    move-wide/from16 v25, p2

    .line 185
    .line 186
    goto :goto_9

    .line 187
    :cond_9
    iget-wide v2, v1, Lh2/b1;->i:J

    .line 188
    .line 189
    move-wide/from16 v25, v2

    .line 190
    .line 191
    :goto_9
    if-eqz v7, :cond_a

    .line 192
    .line 193
    move-wide/from16 v27, p6

    .line 194
    .line 195
    goto :goto_a

    .line 196
    :cond_a
    iget-wide v2, v1, Lh2/b1;->j:J

    .line 197
    .line 198
    move-wide/from16 v27, v2

    .line 199
    .line 200
    :goto_a
    cmp-long v2, p8, v17

    .line 201
    .line 202
    if-eqz v2, :cond_b

    .line 203
    .line 204
    move-wide/from16 v29, p8

    .line 205
    .line 206
    goto :goto_b

    .line 207
    :cond_b
    iget-wide v2, v1, Lh2/b1;->k:J

    .line 208
    .line 209
    move-wide/from16 v29, v2

    .line 210
    .line 211
    :goto_b
    if-eqz v0, :cond_c

    .line 212
    .line 213
    move-wide/from16 v31, p10

    .line 214
    .line 215
    goto :goto_c

    .line 216
    :cond_c
    iget-wide v0, v1, Lh2/b1;->l:J

    .line 217
    .line 218
    move-wide/from16 v31, v0

    .line 219
    .line 220
    :goto_c
    new-instance v8, Lh2/b1;

    .line 221
    .line 222
    move-wide/from16 v17, v4

    .line 223
    .line 224
    invoke-direct/range {v8 .. v32}, Lh2/b1;-><init>(JJJJJJJJJJJJ)V

    .line 225
    .line 226
    .line 227
    return-object v8
.end method
