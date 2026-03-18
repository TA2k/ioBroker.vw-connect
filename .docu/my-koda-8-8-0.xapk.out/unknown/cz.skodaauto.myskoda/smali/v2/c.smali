.class public final Lv2/c;
.super Lv2/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final o:Lv2/b;

.field public p:Z


# direct methods
.method public constructor <init>(JLv2/j;Lay0/k;Lay0/k;Lv2/b;)V
    .locals 0

    .line 1
    invoke-direct/range {p0 .. p5}, Lv2/b;-><init>(JLv2/j;Lay0/k;Lay0/k;)V

    .line 2
    .line 3
    .line 4
    iput-object p6, p0, Lv2/c;->o:Lv2/b;

    .line 5
    .line 6
    invoke-virtual {p6}, Lv2/b;->k()V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0}, Lv2/b;->c()V

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Lv2/c;->p:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    iput-boolean v0, p0, Lv2/c;->p:Z

    .line 14
    .line 15
    iget-object p0, p0, Lv2/c;->o:Lv2/b;

    .line 16
    .line 17
    invoke-virtual {p0}, Lv2/b;->l()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public final w()Lv2/p;
    .locals 11

    .line 1
    iget-object v0, p0, Lv2/c;->o:Lv2/b;

    .line 2
    .line 3
    iget-boolean v1, v0, Lv2/b;->m:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-boolean v1, v0, Lv2/f;->c:Z

    .line 8
    .line 9
    if-eqz v1, :cond_1

    .line 10
    .line 11
    :cond_0
    move-object v2, p0

    .line 12
    goto/16 :goto_7

    .line 13
    .line 14
    :cond_1
    iget-object v5, p0, Lv2/b;->h:Landroidx/collection/r0;

    .line 15
    .line 16
    iget-wide v8, p0, Lv2/f;->b:J

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v5, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 22
    .line 23
    .line 24
    move-result-wide v2

    .line 25
    iget-object v0, p0, Lv2/c;->o:Lv2/b;

    .line 26
    .line 27
    invoke-virtual {v0}, Lv2/f;->d()Lv2/j;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-static {v2, v3, p0, v0}, Lv2/l;->c(JLv2/b;Lv2/j;)Ljava/util/HashMap;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    move-object v6, v0

    .line 36
    goto :goto_0

    .line 37
    :cond_2
    move-object v6, v1

    .line 38
    :goto_0
    sget-object v10, Lv2/l;->c:Ljava/lang/Object;

    .line 39
    .line 40
    monitor-enter v10

    .line 41
    :try_start_0
    invoke-static {p0}, Lv2/l;->d(Lv2/f;)V

    .line 42
    .line 43
    .line 44
    if-eqz v5, :cond_3

    .line 45
    .line 46
    iget v0, v5, Landroidx/collection/r0;->d:I

    .line 47
    .line 48
    if-nez v0, :cond_4

    .line 49
    .line 50
    :cond_3
    move-object v2, p0

    .line 51
    goto :goto_1

    .line 52
    :cond_4
    iget-object v0, p0, Lv2/c;->o:Lv2/b;

    .line 53
    .line 54
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 55
    .line 56
    .line 57
    move-result-wide v3

    .line 58
    iget-object v0, p0, Lv2/c;->o:Lv2/b;

    .line 59
    .line 60
    invoke-virtual {v0}, Lv2/f;->d()Lv2/j;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    move-object v2, p0

    .line 65
    invoke-virtual/range {v2 .. v7}, Lv2/b;->z(JLandroidx/collection/r0;Ljava/util/HashMap;Lv2/j;)Lv2/p;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    sget-object v0, Lv2/h;->b:Lv2/h;

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    if-nez v0, :cond_5

    .line 76
    .line 77
    monitor-exit v10

    .line 78
    return-object p0

    .line 79
    :cond_5
    :try_start_1
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 80
    .line 81
    invoke-virtual {p0}, Lv2/b;->x()Landroidx/collection/r0;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-eqz p0, :cond_6

    .line 86
    .line 87
    invoke-virtual {p0, v5}, Landroidx/collection/r0;->j(Landroidx/collection/r0;)V

    .line 88
    .line 89
    .line 90
    goto :goto_2

    .line 91
    :catchall_0
    move-exception v0

    .line 92
    move-object p0, v0

    .line 93
    goto/16 :goto_6

    .line 94
    .line 95
    :cond_6
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 96
    .line 97
    invoke-virtual {p0, v5}, Lv2/b;->B(Landroidx/collection/r0;)V

    .line 98
    .line 99
    .line 100
    iput-object v1, v2, Lv2/b;->h:Landroidx/collection/r0;

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :goto_1
    invoke-virtual {v2}, Lv2/f;->a()V

    .line 104
    .line 105
    .line 106
    :goto_2
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 107
    .line 108
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 109
    .line 110
    .line 111
    move-result-wide v0

    .line 112
    invoke-static {v0, v1, v8, v9}, Lkotlin/jvm/internal/m;->h(JJ)I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-gez p0, :cond_7

    .line 117
    .line 118
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 119
    .line 120
    invoke-virtual {p0}, Lv2/b;->v()V

    .line 121
    .line 122
    .line 123
    :cond_7
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 124
    .line 125
    invoke-virtual {p0}, Lv2/f;->d()Lv2/j;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-virtual {v0, v8, v9}, Lv2/j;->e(J)Lv2/j;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    iget-object v1, v2, Lv2/b;->j:Lv2/j;

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Lv2/j;->c(Lv2/j;)Lv2/j;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    invoke-virtual {p0, v0}, Lv2/f;->r(Lv2/j;)V

    .line 140
    .line 141
    .line 142
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 143
    .line 144
    invoke-virtual {p0, v8, v9}, Lv2/b;->A(J)V

    .line 145
    .line 146
    .line 147
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 148
    .line 149
    iget v0, v2, Lv2/f;->d:I

    .line 150
    .line 151
    const/4 v1, -0x1

    .line 152
    iput v1, v2, Lv2/f;->d:I

    .line 153
    .line 154
    if-ltz v0, :cond_8

    .line 155
    .line 156
    iget-object v1, p0, Lv2/b;->k:[I

    .line 157
    .line 158
    const-string v3, "<this>"

    .line 159
    .line 160
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    array-length v3, v1

    .line 164
    add-int/lit8 v4, v3, 0x1

    .line 165
    .line 166
    invoke-static {v1, v4}, Ljava/util/Arrays;->copyOf([II)[I

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    aput v0, v1, v3

    .line 171
    .line 172
    iput-object v1, p0, Lv2/b;->k:[I

    .line 173
    .line 174
    goto :goto_3

    .line 175
    :cond_8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    :goto_3
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 179
    .line 180
    iget-object v0, v2, Lv2/b;->j:Lv2/j;

    .line 181
    .line 182
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    monitor-enter v10
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 186
    :try_start_2
    iget-object v1, p0, Lv2/b;->j:Lv2/j;

    .line 187
    .line 188
    invoke-virtual {v1, v0}, Lv2/j;->i(Lv2/j;)Lv2/j;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    iput-object v0, p0, Lv2/b;->j:Lv2/j;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 193
    .line 194
    :try_start_3
    monitor-exit v10

    .line 195
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 196
    .line 197
    iget-object v0, v2, Lv2/b;->k:[I

    .line 198
    .line 199
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 200
    .line 201
    .line 202
    array-length v1, v0

    .line 203
    if-nez v1, :cond_9

    .line 204
    .line 205
    goto :goto_5

    .line 206
    :cond_9
    iget-object v1, p0, Lv2/b;->k:[I

    .line 207
    .line 208
    array-length v3, v1

    .line 209
    if-nez v3, :cond_a

    .line 210
    .line 211
    goto :goto_4

    .line 212
    :cond_a
    array-length v3, v1

    .line 213
    array-length v4, v0

    .line 214
    add-int v5, v3, v4

    .line 215
    .line 216
    invoke-static {v1, v5}, Ljava/util/Arrays;->copyOf([II)[I

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    const/4 v5, 0x0

    .line 221
    invoke-static {v0, v5, v1, v3, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 222
    .line 223
    .line 224
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    move-object v0, v1

    .line 228
    :goto_4
    iput-object v0, p0, Lv2/b;->k:[I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 229
    .line 230
    :goto_5
    monitor-exit v10

    .line 231
    const/4 p0, 0x1

    .line 232
    iput-boolean p0, v2, Lv2/b;->m:Z

    .line 233
    .line 234
    iget-boolean v0, v2, Lv2/c;->p:Z

    .line 235
    .line 236
    if-nez v0, :cond_b

    .line 237
    .line 238
    iput-boolean p0, v2, Lv2/c;->p:Z

    .line 239
    .line 240
    iget-object p0, v2, Lv2/c;->o:Lv2/b;

    .line 241
    .line 242
    invoke-virtual {p0}, Lv2/b;->l()V

    .line 243
    .line 244
    .line 245
    :cond_b
    sget-object p0, Lv2/h;->b:Lv2/h;

    .line 246
    .line 247
    return-object p0

    .line 248
    :catchall_1
    move-exception v0

    .line 249
    move-object p0, v0

    .line 250
    :try_start_4
    monitor-exit v10

    .line 251
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 252
    :goto_6
    monitor-exit v10

    .line 253
    throw p0

    .line 254
    :goto_7
    new-instance p0, Lv2/g;

    .line 255
    .line 256
    invoke-direct {p0, v2}, Lv2/g;-><init>(Lv2/b;)V

    .line 257
    .line 258
    .line 259
    return-object p0
.end method
