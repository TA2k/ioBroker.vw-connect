.class public final Llo/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/e;


# instance fields
.field public final d:Llo/g;

.field public final e:I

.field public final f:Llo/b;

.field public final g:J

.field public final h:J


# direct methods
.method public constructor <init>(Llo/g;ILlo/b;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llo/w;->d:Llo/g;

    .line 5
    .line 6
    iput p2, p0, Llo/w;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Llo/w;->f:Llo/b;

    .line 9
    .line 10
    iput-wide p4, p0, Llo/w;->g:J

    .line 11
    .line 12
    iput-wide p6, p0, Llo/w;->h:J

    .line 13
    .line 14
    return-void
.end method

.method public static a(Llo/s;Lno/e;I)Lno/g;
    .locals 4

    .line 1
    iget-object p1, p1, Lno/e;->v:Lno/j0;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    move-object p1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object p1, p1, Lno/j0;->g:Lno/g;

    .line 9
    .line 10
    :goto_0
    if-eqz p1, :cond_6

    .line 11
    .line 12
    iget-boolean v1, p1, Lno/g;->e:Z

    .line 13
    .line 14
    if-eqz v1, :cond_6

    .line 15
    .line 16
    iget-object v1, p1, Lno/g;->g:[I

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-nez v1, :cond_3

    .line 20
    .line 21
    iget-object v1, p1, Lno/g;->i:[I

    .line 22
    .line 23
    if-nez v1, :cond_1

    .line 24
    .line 25
    goto :goto_3

    .line 26
    :cond_1
    :goto_1
    array-length v3, v1

    .line 27
    if-ge v2, v3, :cond_4

    .line 28
    .line 29
    aget v3, v1, v2

    .line 30
    .line 31
    if-ne v3, p2, :cond_2

    .line 32
    .line 33
    goto :goto_4

    .line 34
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_3
    :goto_2
    array-length v3, v1

    .line 38
    if-ge v2, v3, :cond_6

    .line 39
    .line 40
    aget v3, v1, v2

    .line 41
    .line 42
    if-ne v3, p2, :cond_5

    .line 43
    .line 44
    :cond_4
    :goto_3
    iget p0, p0, Llo/s;->n:I

    .line 45
    .line 46
    iget p2, p1, Lno/g;->h:I

    .line 47
    .line 48
    if-ge p0, p2, :cond_6

    .line 49
    .line 50
    return-object p1

    .line 51
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_6
    :goto_4
    return-object v0
.end method


# virtual methods
.method public final onComplete(Laq/j;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Llo/w;->d:Llo/g;

    .line 4
    .line 5
    invoke-virtual {v1}, Llo/g;->b()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto/16 :goto_8

    .line 12
    .line 13
    :cond_0
    invoke-static {}, Lno/n;->e()Lno/n;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-object v1, v1, Lno/n;->a:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lno/o;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iget-boolean v2, v1, Lno/o;->e:Z

    .line 24
    .line 25
    if-eqz v2, :cond_b

    .line 26
    .line 27
    :cond_1
    iget-object v2, v0, Llo/w;->d:Llo/g;

    .line 28
    .line 29
    iget-object v3, v0, Llo/w;->f:Llo/b;

    .line 30
    .line 31
    iget-object v2, v2, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 32
    .line 33
    invoke-virtual {v2, v3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Llo/s;

    .line 38
    .line 39
    if-eqz v2, :cond_b

    .line 40
    .line 41
    iget-object v3, v2, Llo/s;->d:Lko/c;

    .line 42
    .line 43
    instance-of v4, v3, Lno/e;

    .line 44
    .line 45
    if-eqz v4, :cond_b

    .line 46
    .line 47
    check-cast v3, Lno/e;

    .line 48
    .line 49
    iget-wide v4, v0, Llo/w;->g:J

    .line 50
    .line 51
    const-wide/16 v6, 0x0

    .line 52
    .line 53
    cmp-long v4, v4, v6

    .line 54
    .line 55
    const/4 v5, 0x1

    .line 56
    const/4 v8, 0x0

    .line 57
    if-lez v4, :cond_2

    .line 58
    .line 59
    move v4, v5

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    move v4, v8

    .line 62
    :goto_0
    iget v9, v3, Lno/e;->q:I

    .line 63
    .line 64
    const/16 v10, 0x64

    .line 65
    .line 66
    if-eqz v1, :cond_5

    .line 67
    .line 68
    iget-boolean v11, v1, Lno/o;->f:Z

    .line 69
    .line 70
    and-int/2addr v4, v11

    .line 71
    iget v11, v1, Lno/o;->g:I

    .line 72
    .line 73
    iget v12, v1, Lno/o;->h:I

    .line 74
    .line 75
    iget v1, v1, Lno/o;->d:I

    .line 76
    .line 77
    iget-object v13, v3, Lno/e;->v:Lno/j0;

    .line 78
    .line 79
    if-eqz v13, :cond_4

    .line 80
    .line 81
    invoke-virtual {v3}, Lno/e;->b()Z

    .line 82
    .line 83
    .line 84
    move-result v13

    .line 85
    if-nez v13, :cond_4

    .line 86
    .line 87
    iget v4, v0, Llo/w;->e:I

    .line 88
    .line 89
    invoke-static {v2, v3, v4}, Llo/w;->a(Llo/s;Lno/e;I)Lno/g;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    if-eqz v2, :cond_b

    .line 94
    .line 95
    iget-boolean v3, v2, Lno/g;->f:Z

    .line 96
    .line 97
    if-eqz v3, :cond_3

    .line 98
    .line 99
    iget-wide v3, v0, Llo/w;->g:J

    .line 100
    .line 101
    cmp-long v3, v3, v6

    .line 102
    .line 103
    if-lez v3, :cond_3

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_3
    move v5, v8

    .line 107
    :goto_1
    iget v12, v2, Lno/g;->h:I

    .line 108
    .line 109
    move v4, v5

    .line 110
    :cond_4
    move v2, v11

    .line 111
    move v3, v12

    .line 112
    goto :goto_2

    .line 113
    :cond_5
    const/16 v11, 0x1388

    .line 114
    .line 115
    move v1, v8

    .line 116
    move v3, v10

    .line 117
    move v2, v11

    .line 118
    :goto_2
    iget-object v5, v0, Llo/w;->d:Llo/g;

    .line 119
    .line 120
    invoke-virtual/range {p1 .. p1}, Laq/j;->i()Z

    .line 121
    .line 122
    .line 123
    move-result v11

    .line 124
    const/4 v12, -0x1

    .line 125
    if-eqz v11, :cond_6

    .line 126
    .line 127
    move v11, v8

    .line 128
    goto :goto_5

    .line 129
    :cond_6
    move-object/from16 v8, p1

    .line 130
    .line 131
    check-cast v8, Laq/t;

    .line 132
    .line 133
    iget-boolean v8, v8, Laq/t;->d:Z

    .line 134
    .line 135
    if-eqz v8, :cond_7

    .line 136
    .line 137
    :goto_3
    move v11, v10

    .line 138
    :goto_4
    move v8, v12

    .line 139
    goto :goto_5

    .line 140
    :cond_7
    invoke-virtual/range {p1 .. p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 141
    .line 142
    .line 143
    move-result-object v8

    .line 144
    instance-of v10, v8, Lko/e;

    .line 145
    .line 146
    if-eqz v10, :cond_9

    .line 147
    .line 148
    check-cast v8, Lko/e;

    .line 149
    .line 150
    iget-object v8, v8, Lko/e;->d:Lcom/google/android/gms/common/api/Status;

    .line 151
    .line 152
    iget v10, v8, Lcom/google/android/gms/common/api/Status;->d:I

    .line 153
    .line 154
    iget-object v8, v8, Lcom/google/android/gms/common/api/Status;->g:Ljo/b;

    .line 155
    .line 156
    if-nez v8, :cond_8

    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_8
    iget v8, v8, Ljo/b;->e:I

    .line 160
    .line 161
    move v11, v10

    .line 162
    goto :goto_5

    .line 163
    :cond_9
    const/16 v8, 0x65

    .line 164
    .line 165
    move v11, v8

    .line 166
    goto :goto_4

    .line 167
    :goto_5
    if-eqz v4, :cond_a

    .line 168
    .line 169
    iget-wide v6, v0, Llo/w;->g:J

    .line 170
    .line 171
    iget-wide v12, v0, Llo/w;->h:J

    .line 172
    .line 173
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 174
    .line 175
    .line 176
    move-result-wide v14

    .line 177
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 178
    .line 179
    .line 180
    move-result-wide v16

    .line 181
    sub-long v12, v16, v12

    .line 182
    .line 183
    long-to-int v12, v12

    .line 184
    move-wide v15, v14

    .line 185
    move-wide v13, v6

    .line 186
    :goto_6
    move/from16 v20, v12

    .line 187
    .line 188
    goto :goto_7

    .line 189
    :cond_a
    move-wide v13, v6

    .line 190
    move-wide v15, v13

    .line 191
    goto :goto_6

    .line 192
    :goto_7
    iget v10, v0, Llo/w;->e:I

    .line 193
    .line 194
    move/from16 v19, v9

    .line 195
    .line 196
    new-instance v9, Lno/l;

    .line 197
    .line 198
    const/16 v17, 0x0

    .line 199
    .line 200
    const/16 v18, 0x0

    .line 201
    .line 202
    move v12, v8

    .line 203
    invoke-direct/range {v9 .. v20}, Lno/l;-><init>(IIIJJLjava/lang/String;Ljava/lang/String;II)V

    .line 204
    .line 205
    .line 206
    int-to-long v6, v2

    .line 207
    new-instance v12, Llo/x;

    .line 208
    .line 209
    move v14, v1

    .line 210
    move/from16 v17, v3

    .line 211
    .line 212
    move-wide v15, v6

    .line 213
    move-object v13, v9

    .line 214
    invoke-direct/range {v12 .. v17}, Llo/x;-><init>(Lno/l;IJI)V

    .line 215
    .line 216
    .line 217
    iget-object v0, v5, Llo/g;->q:Lbp/c;

    .line 218
    .line 219
    const/16 v1, 0x12

    .line 220
    .line 221
    invoke-virtual {v0, v1, v12}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    invoke-virtual {v0, v1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 226
    .line 227
    .line 228
    :cond_b
    :goto_8
    return-void
.end method
