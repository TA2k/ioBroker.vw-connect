.class public final Lp11/m;
.super Lp11/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final v1:Lp11/m;

.field public static final w1:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lp11/m;->w1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    sget-object v0, Ln11/f;->e:Ln11/n;

    .line 9
    .line 10
    invoke-static {v0}, Lp11/m;->f0(Ln11/f;)Lp11/m;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lp11/m;->v1:Lp11/m;

    .line 15
    .line 16
    return-void
.end method

.method public static f0(Ln11/f;)Lp11/m;
    .locals 4

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    sget-object v0, Lp11/m;->w1:Ljava/util/concurrent/ConcurrentHashMap;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, [Lp11/m;

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x7

    .line 18
    new-array v1, v1, [Lp11/m;

    .line 19
    .line 20
    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, [Lp11/m;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    move-object v1, v0

    .line 29
    :cond_1
    const/4 v0, 0x3

    .line 30
    :try_start_0
    aget-object v2, v1, v0
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 31
    .line 32
    if-nez v2, :cond_4

    .line 33
    .line 34
    monitor-enter v1

    .line 35
    :try_start_1
    aget-object v2, v1, v0

    .line 36
    .line 37
    if-nez v2, :cond_3

    .line 38
    .line 39
    sget-object v2, Ln11/f;->e:Ln11/n;

    .line 40
    .line 41
    if-ne p0, v2, :cond_2

    .line 42
    .line 43
    new-instance p0, Lp11/m;

    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    invoke-direct {p0, v2}, Lp11/e;-><init>(Lp11/r;)V

    .line 47
    .line 48
    .line 49
    move-object v2, p0

    .line 50
    goto :goto_0

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    goto :goto_1

    .line 53
    :cond_2
    invoke-static {v2}, Lp11/m;->f0(Ln11/f;)Lp11/m;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    new-instance v3, Lp11/m;

    .line 58
    .line 59
    invoke-static {v2, p0}, Lp11/r;->R(Ljp/u1;Ln11/f;)Lp11/r;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {v3, p0}, Lp11/e;-><init>(Lp11/r;)V

    .line 64
    .line 65
    .line 66
    move-object v2, v3

    .line 67
    :goto_0
    aput-object v2, v1, v0

    .line 68
    .line 69
    :cond_3
    monitor-exit v1

    .line 70
    return-object v2

    .line 71
    :goto_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 72
    throw p0

    .line 73
    :cond_4
    return-object v2

    .line 74
    :catch_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    const-string v0, "Invalid min days in first week: 4"

    .line 77
    .line 78
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0
.end method


# virtual methods
.method public final I()Ljp/u1;
    .locals 0

    .line 1
    sget-object p0, Lp11/m;->v1:Lp11/m;

    .line 2
    .line 3
    return-object p0
.end method

.method public final J(Ln11/f;)Ljp/u1;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    :cond_0
    invoke-virtual {p0}, Lp11/e;->m()Ln11/f;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-ne p1, v0, :cond_1

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_1
    invoke-static {p1}, Lp11/m;->f0(Ln11/f;)Lp11/m;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final O(Lp11/a;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lp11/b;->d:Ljp/u1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lq11/g;->d:Lq11/g;

    .line 6
    .line 7
    iput-object v0, p1, Lp11/a;->a:Ln11/g;

    .line 8
    .line 9
    sget-object v0, Lp11/e;->R:Lq11/j;

    .line 10
    .line 11
    iput-object v0, p1, Lp11/a;->b:Ln11/g;

    .line 12
    .line 13
    sget-object v0, Lp11/e;->S:Lq11/j;

    .line 14
    .line 15
    iput-object v0, p1, Lp11/a;->c:Ln11/g;

    .line 16
    .line 17
    sget-object v0, Lp11/e;->T:Lq11/j;

    .line 18
    .line 19
    iput-object v0, p1, Lp11/a;->d:Ln11/g;

    .line 20
    .line 21
    sget-object v0, Lp11/e;->U:Lq11/j;

    .line 22
    .line 23
    iput-object v0, p1, Lp11/a;->e:Ln11/g;

    .line 24
    .line 25
    sget-object v0, Lp11/e;->V:Lq11/j;

    .line 26
    .line 27
    iput-object v0, p1, Lp11/a;->f:Ln11/g;

    .line 28
    .line 29
    sget-object v0, Lp11/e;->W:Lq11/j;

    .line 30
    .line 31
    iput-object v0, p1, Lp11/a;->g:Ln11/g;

    .line 32
    .line 33
    sget-object v0, Lp11/e;->X:Lq11/i;

    .line 34
    .line 35
    iput-object v0, p1, Lp11/a;->m:Ln11/a;

    .line 36
    .line 37
    sget-object v0, Lp11/e;->Y:Lq11/i;

    .line 38
    .line 39
    iput-object v0, p1, Lp11/a;->n:Ln11/a;

    .line 40
    .line 41
    sget-object v0, Lp11/e;->Z:Lq11/i;

    .line 42
    .line 43
    iput-object v0, p1, Lp11/a;->o:Ln11/a;

    .line 44
    .line 45
    sget-object v0, Lp11/e;->a0:Lq11/i;

    .line 46
    .line 47
    iput-object v0, p1, Lp11/a;->p:Ln11/a;

    .line 48
    .line 49
    sget-object v0, Lp11/e;->b0:Lq11/i;

    .line 50
    .line 51
    iput-object v0, p1, Lp11/a;->q:Ln11/a;

    .line 52
    .line 53
    sget-object v0, Lp11/e;->c0:Lq11/i;

    .line 54
    .line 55
    iput-object v0, p1, Lp11/a;->r:Ln11/a;

    .line 56
    .line 57
    sget-object v0, Lp11/e;->d0:Lq11/i;

    .line 58
    .line 59
    iput-object v0, p1, Lp11/a;->s:Ln11/a;

    .line 60
    .line 61
    sget-object v0, Lp11/e;->e0:Lq11/i;

    .line 62
    .line 63
    iput-object v0, p1, Lp11/a;->u:Ln11/a;

    .line 64
    .line 65
    sget-object v0, Lp11/e;->f0:Lq11/o;

    .line 66
    .line 67
    iput-object v0, p1, Lp11/a;->t:Ln11/a;

    .line 68
    .line 69
    sget-object v0, Lp11/e;->g0:Lq11/o;

    .line 70
    .line 71
    iput-object v0, p1, Lp11/a;->v:Ln11/a;

    .line 72
    .line 73
    sget-object v0, Lp11/e;->q1:Lp11/d;

    .line 74
    .line 75
    iput-object v0, p1, Lp11/a;->w:Ln11/a;

    .line 76
    .line 77
    new-instance v0, Lp11/h;

    .line 78
    .line 79
    const/4 v1, 0x1

    .line 80
    invoke-direct {v0, p0, v1}, Lp11/h;-><init>(Lp11/m;I)V

    .line 81
    .line 82
    .line 83
    iput-object v0, p1, Lp11/a;->E:Ln11/a;

    .line 84
    .line 85
    new-instance v2, Lp11/l;

    .line 86
    .line 87
    invoke-direct {v2, v0, p0}, Lp11/l;-><init>(Lp11/h;Lp11/m;)V

    .line 88
    .line 89
    .line 90
    iput-object v2, p1, Lp11/a;->F:Ln11/a;

    .line 91
    .line 92
    new-instance v0, Lq11/h;

    .line 93
    .line 94
    const/16 v3, 0x63

    .line 95
    .line 96
    sget-object v4, Ln11/b;->i:Ln11/b;

    .line 97
    .line 98
    invoke-direct {v0, v2, v4, v3}, Lq11/h;-><init>(Lq11/c;Ln11/b;I)V

    .line 99
    .line 100
    .line 101
    new-instance v2, Lq11/d;

    .line 102
    .line 103
    sget-object v3, Ln11/b;->h:Ln11/b;

    .line 104
    .line 105
    invoke-direct {v2, v0}, Lq11/d;-><init>(Ln11/a;)V

    .line 106
    .line 107
    .line 108
    iput-object v2, p1, Lp11/a;->H:Ln11/a;

    .line 109
    .line 110
    iget-object v0, v2, Lq11/d;->g:Lq11/l;

    .line 111
    .line 112
    iput-object v0, p1, Lp11/a;->k:Ln11/g;

    .line 113
    .line 114
    new-instance v0, Lq11/k;

    .line 115
    .line 116
    iget-object v3, v2, Lq11/c;->e:Ln11/a;

    .line 117
    .line 118
    invoke-virtual {v3}, Ln11/a;->i()Ln11/g;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    iget-object v4, v2, Lq11/a;->d:Ln11/b;

    .line 123
    .line 124
    invoke-direct {v0, v2, v3, v4}, Lq11/k;-><init>(Lq11/d;Ln11/g;Ln11/b;)V

    .line 125
    .line 126
    .line 127
    new-instance v2, Lq11/h;

    .line 128
    .line 129
    sget-object v3, Ln11/b;->k:Ln11/b;

    .line 130
    .line 131
    invoke-direct {v2, v0, v3, v1}, Lq11/h;-><init>(Lq11/c;Ln11/b;I)V

    .line 132
    .line 133
    .line 134
    iput-object v2, p1, Lp11/a;->G:Ln11/a;

    .line 135
    .line 136
    new-instance v0, Lp11/i;

    .line 137
    .line 138
    invoke-direct {v0, p0}, Lp11/i;-><init>(Lp11/m;)V

    .line 139
    .line 140
    .line 141
    iput-object v0, p1, Lp11/a;->I:Ln11/a;

    .line 142
    .line 143
    new-instance v0, Lp11/f;

    .line 144
    .line 145
    iget-object v2, p1, Lp11/a;->f:Ln11/g;

    .line 146
    .line 147
    const/4 v3, 0x3

    .line 148
    invoke-direct {v0, p0, v2, v3}, Lp11/f;-><init>(Lp11/m;Ln11/g;I)V

    .line 149
    .line 150
    .line 151
    iput-object v0, p1, Lp11/a;->x:Ln11/a;

    .line 152
    .line 153
    new-instance v0, Lp11/f;

    .line 154
    .line 155
    iget-object v2, p1, Lp11/a;->f:Ln11/g;

    .line 156
    .line 157
    const/4 v3, 0x0

    .line 158
    invoke-direct {v0, p0, v2, v3}, Lp11/f;-><init>(Lp11/m;Ln11/g;I)V

    .line 159
    .line 160
    .line 161
    iput-object v0, p1, Lp11/a;->y:Ln11/a;

    .line 162
    .line 163
    new-instance v0, Lp11/f;

    .line 164
    .line 165
    iget-object v2, p1, Lp11/a;->f:Ln11/g;

    .line 166
    .line 167
    invoke-direct {v0, p0, v2, v1}, Lp11/f;-><init>(Lp11/m;Ln11/g;I)V

    .line 168
    .line 169
    .line 170
    iput-object v0, p1, Lp11/a;->z:Ln11/a;

    .line 171
    .line 172
    new-instance v0, Lp11/k;

    .line 173
    .line 174
    invoke-direct {v0, p0}, Lp11/k;-><init>(Lp11/m;)V

    .line 175
    .line 176
    .line 177
    iput-object v0, p1, Lp11/a;->D:Ln11/a;

    .line 178
    .line 179
    new-instance v0, Lp11/h;

    .line 180
    .line 181
    invoke-direct {v0, p0, v3}, Lp11/h;-><init>(Lp11/m;I)V

    .line 182
    .line 183
    .line 184
    iput-object v0, p1, Lp11/a;->B:Ln11/a;

    .line 185
    .line 186
    new-instance v0, Lp11/f;

    .line 187
    .line 188
    iget-object v2, p1, Lp11/a;->g:Ln11/g;

    .line 189
    .line 190
    const/4 v3, 0x2

    .line 191
    invoke-direct {v0, p0, v2, v3}, Lp11/f;-><init>(Lp11/m;Ln11/g;I)V

    .line 192
    .line 193
    .line 194
    iput-object v0, p1, Lp11/a;->A:Ln11/a;

    .line 195
    .line 196
    new-instance p0, Lq11/k;

    .line 197
    .line 198
    iget-object v0, p1, Lp11/a;->B:Ln11/a;

    .line 199
    .line 200
    iget-object v2, p1, Lp11/a;->k:Ln11/g;

    .line 201
    .line 202
    sget-object v3, Ln11/b;->p:Ln11/b;

    .line 203
    .line 204
    invoke-direct {p0, v0, v2}, Lq11/k;-><init>(Ln11/a;Ln11/g;)V

    .line 205
    .line 206
    .line 207
    new-instance v0, Lq11/h;

    .line 208
    .line 209
    invoke-direct {v0, p0, v3, v1}, Lq11/h;-><init>(Lq11/c;Ln11/b;I)V

    .line 210
    .line 211
    .line 212
    iput-object v0, p1, Lp11/a;->C:Ln11/a;

    .line 213
    .line 214
    iget-object p0, p1, Lp11/a;->E:Ln11/a;

    .line 215
    .line 216
    invoke-virtual {p0}, Ln11/a;->i()Ln11/g;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    iput-object p0, p1, Lp11/a;->j:Ln11/g;

    .line 221
    .line 222
    iget-object p0, p1, Lp11/a;->D:Ln11/a;

    .line 223
    .line 224
    invoke-virtual {p0}, Ln11/a;->i()Ln11/g;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    iput-object p0, p1, Lp11/a;->i:Ln11/g;

    .line 229
    .line 230
    iget-object p0, p1, Lp11/a;->B:Ln11/a;

    .line 231
    .line 232
    invoke-virtual {p0}, Ln11/a;->i()Ln11/g;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    iput-object p0, p1, Lp11/a;->h:Ln11/g;

    .line 237
    .line 238
    :cond_0
    return-void
.end method

.method public final a0(I)Z
    .locals 0

    .line 1
    and-int/lit8 p0, p1, 0x3

    .line 2
    .line 3
    if-nez p0, :cond_1

    .line 4
    .line 5
    rem-int/lit8 p0, p1, 0x64

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    rem-int/lit16 p1, p1, 0x190

    .line 10
    .line 11
    if-nez p1, :cond_1

    .line 12
    .line 13
    :cond_0
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_1
    const/4 p0, 0x0

    .line 16
    return p0
.end method
