.class public final Ldu/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljp/ug;


# instance fields
.field public a:J

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# virtual methods
.method public a()Ldu/e;
    .locals 8

    .line 1
    new-instance v0, Ldu/e;

    .line 2
    .line 3
    iget-object v1, p0, Ldu/d;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lorg/json/JSONObject;

    .line 6
    .line 7
    iget-object v2, p0, Ldu/d;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Ljava/util/Date;

    .line 10
    .line 11
    iget-object v3, p0, Ldu/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v3, Lorg/json/JSONArray;

    .line 14
    .line 15
    iget-object v4, p0, Ldu/d;->c:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v4, Lorg/json/JSONObject;

    .line 18
    .line 19
    iget-wide v5, p0, Ldu/d;->a:J

    .line 20
    .line 21
    iget-object p0, p0, Ldu/d;->f:Ljava/lang/Object;

    .line 22
    .line 23
    move-object v7, p0

    .line 24
    check-cast v7, Lorg/json/JSONArray;

    .line 25
    .line 26
    invoke-direct/range {v0 .. v7}, Ldu/e;-><init>(Lorg/json/JSONObject;Ljava/util/Date;Lorg/json/JSONArray;Lorg/json/JSONObject;JLorg/json/JSONArray;)V

    .line 27
    .line 28
    .line 29
    return-object v0
.end method

.method public h()Lbb/g0;
    .locals 11

    .line 1
    iget-object v0, p0, Ldu/d;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llv/e;

    .line 4
    .line 5
    iget-wide v1, p0, Ldu/d;->a:J

    .line 6
    .line 7
    iget-object v3, p0, Ldu/d;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Ljp/ac;

    .line 10
    .line 11
    iget-object v4, p0, Ldu/d;->d:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v4, Lin/o;

    .line 14
    .line 15
    iget-object v5, p0, Ldu/d;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v5, Lin/o;

    .line 18
    .line 19
    iget-object p0, p0, Ldu/d;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lmv/a;

    .line 22
    .line 23
    new-instance v6, Landroidx/lifecycle/c1;

    .line 24
    .line 25
    const/16 v7, 0xc

    .line 26
    .line 27
    invoke-direct {v6, v7}, Landroidx/lifecycle/c1;-><init>(I)V

    .line 28
    .line 29
    .line 30
    new-instance v7, Landroidx/lifecycle/c1;

    .line 31
    .line 32
    const/16 v8, 0xb

    .line 33
    .line 34
    invoke-direct {v7, v8}, Landroidx/lifecycle/c1;-><init>(I)V

    .line 35
    .line 36
    .line 37
    const-wide v8, 0x7fffffffffffffffL

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    and-long/2addr v1, v8

    .line 43
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    iput-object v1, v7, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 48
    .line 49
    iput-object v3, v7, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 50
    .line 51
    sget-boolean v1, Llv/e;->n:Z

    .line 52
    .line 53
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    iput-object v1, v7, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 58
    .line 59
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 60
    .line 61
    iput-object v1, v7, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 62
    .line 63
    iput-object v1, v7, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 64
    .line 65
    new-instance v1, Ljp/ob;

    .line 66
    .line 67
    invoke-direct {v1, v7}, Ljp/ob;-><init>(Landroidx/lifecycle/c1;)V

    .line 68
    .line 69
    .line 70
    iput-object v1, v6, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 71
    .line 72
    iget-object v1, v0, Llv/e;->h:Lhv/b;

    .line 73
    .line 74
    invoke-static {v1}, Llv/a;->a(Lhv/b;)Ljp/pg;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    iput-object v1, v6, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 79
    .line 80
    invoke-virtual {v4}, Lin/o;->s()Ljp/c0;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    iput-object v1, v6, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 85
    .line 86
    invoke-virtual {v5}, Lin/o;->s()Ljp/c0;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    iput-object v1, v6, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 91
    .line 92
    iget v1, p0, Lmv/a;->f:I

    .line 93
    .line 94
    const/16 v2, 0x23

    .line 95
    .line 96
    const v3, 0x32315659

    .line 97
    .line 98
    .line 99
    const/16 v4, 0x11

    .line 100
    .line 101
    const/4 v5, 0x0

    .line 102
    const/4 v7, -0x1

    .line 103
    if-ne v1, v7, :cond_0

    .line 104
    .line 105
    iget-object p0, p0, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 106
    .line 107
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getAllocationByteCount()I

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    goto :goto_0

    .line 115
    :cond_0
    if-eq v1, v4, :cond_8

    .line 116
    .line 117
    if-eq v1, v3, :cond_8

    .line 118
    .line 119
    if-eq v1, v2, :cond_1

    .line 120
    .line 121
    move p0, v5

    .line 122
    goto :goto_0

    .line 123
    :cond_1
    invoke-virtual {p0}, Lmv/a;->b()[Landroid/media/Image$Plane;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    aget-object p0, p0, v5

    .line 131
    .line 132
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-virtual {p0}, Ljava/nio/Buffer;->limit()I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    mul-int/lit8 p0, p0, 0x3

    .line 141
    .line 142
    div-int/lit8 p0, p0, 0x2

    .line 143
    .line 144
    :goto_0
    new-instance v8, Lb81/a;

    .line 145
    .line 146
    const/16 v9, 0xc

    .line 147
    .line 148
    const/4 v10, 0x0

    .line 149
    invoke-direct {v8, v9, v10}, Lb81/a;-><init>(IZ)V

    .line 150
    .line 151
    .line 152
    if-eq v1, v7, :cond_6

    .line 153
    .line 154
    if-eq v1, v2, :cond_5

    .line 155
    .line 156
    if-eq v1, v3, :cond_4

    .line 157
    .line 158
    const/16 v2, 0x10

    .line 159
    .line 160
    if-eq v1, v2, :cond_3

    .line 161
    .line 162
    if-eq v1, v4, :cond_2

    .line 163
    .line 164
    sget-object v1, Ljp/jb;->e:Ljp/jb;

    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_2
    sget-object v1, Ljp/jb;->g:Ljp/jb;

    .line 168
    .line 169
    goto :goto_1

    .line 170
    :cond_3
    sget-object v1, Ljp/jb;->f:Ljp/jb;

    .line 171
    .line 172
    goto :goto_1

    .line 173
    :cond_4
    sget-object v1, Ljp/jb;->h:Ljp/jb;

    .line 174
    .line 175
    goto :goto_1

    .line 176
    :cond_5
    sget-object v1, Ljp/jb;->i:Ljp/jb;

    .line 177
    .line 178
    goto :goto_1

    .line 179
    :cond_6
    sget-object v1, Ljp/jb;->j:Ljp/jb;

    .line 180
    .line 181
    :goto_1
    iput-object v1, v8, Lb81/a;->e:Ljava/lang/Object;

    .line 182
    .line 183
    const v1, 0x7fffffff

    .line 184
    .line 185
    .line 186
    and-int/2addr p0, v1

    .line 187
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    iput-object p0, v8, Lb81/a;->f:Ljava/lang/Object;

    .line 192
    .line 193
    new-instance p0, Ljp/kb;

    .line 194
    .line 195
    invoke-direct {p0, v8}, Ljp/kb;-><init>(Lb81/a;)V

    .line 196
    .line 197
    .line 198
    iput-object p0, v6, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 199
    .line 200
    new-instance p0, Lin/z1;

    .line 201
    .line 202
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 203
    .line 204
    .line 205
    iget-boolean v0, v0, Llv/e;->m:Z

    .line 206
    .line 207
    if-eqz v0, :cond_7

    .line 208
    .line 209
    sget-object v0, Ljp/zb;->f:Ljp/zb;

    .line 210
    .line 211
    goto :goto_2

    .line 212
    :cond_7
    sget-object v0, Ljp/zb;->e:Ljp/zb;

    .line 213
    .line 214
    :goto_2
    iput-object v0, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 215
    .line 216
    new-instance v0, Ljp/mc;

    .line 217
    .line 218
    invoke-direct {v0, v6}, Ljp/mc;-><init>(Landroidx/lifecycle/c1;)V

    .line 219
    .line 220
    .line 221
    iput-object v0, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 222
    .line 223
    new-instance v0, Lbb/g0;

    .line 224
    .line 225
    invoke-direct {v0, p0, v5}, Lbb/g0;-><init>(Lin/z1;I)V

    .line 226
    .line 227
    .line 228
    return-object v0

    .line 229
    :cond_8
    const/4 p0, 0x0

    .line 230
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    throw p0
.end method
