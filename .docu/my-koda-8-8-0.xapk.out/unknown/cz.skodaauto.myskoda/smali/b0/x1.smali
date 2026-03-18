.class public final Lb0/x1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Landroid/util/Size;

.field public final c:Lb0/y;

.field public final d:Lh0/b0;

.field public final e:Z

.field public final f:Ly4/k;

.field public final g:Ly4/h;

.field public final h:Ly4/k;

.field public final i:Ly4/h;

.field public final j:Ly4/h;

.field public final k:Lb0/u1;

.field public l:Lb0/j;

.field public m:Lb0/w1;

.field public n:Ljava/util/concurrent/Executor;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 2
    .line 3
    return-void
.end method

.method public constructor <init>(Landroid/util/Size;Lh0/b0;ZLb0/y;Lp0/e;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lb0/x1;->a:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p1, p0, Lb0/x1;->b:Landroid/util/Size;

    .line 12
    .line 13
    iput-object p2, p0, Lb0/x1;->d:Lh0/b0;

    .line 14
    .line 15
    iput-boolean p3, p0, Lb0/x1;->e:Z

    .line 16
    .line 17
    invoke-virtual {p4}, Lb0/y;->b()Z

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    const-string p3, "SurfaceRequest\'s DynamicRange must always be fully specified."

    .line 22
    .line 23
    invoke-static {p2, p3}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iput-object p4, p0, Lb0/x1;->c:Lb0/y;

    .line 27
    .line 28
    new-instance p2, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string p3, "SurfaceRequest[size: "

    .line 31
    .line 32
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p3, ", id: "

    .line 39
    .line 40
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result p3

    .line 47
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p3, "]"

    .line 51
    .line 52
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    new-instance p3, Ljava/util/concurrent/atomic/AtomicReference;

    .line 60
    .line 61
    const/4 p4, 0x0

    .line 62
    invoke-direct {p3, p4}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    new-instance v0, Lb0/r1;

    .line 66
    .line 67
    const/4 v1, 0x0

    .line 68
    invoke-direct {v0, p3, p2, v1}, Lb0/r1;-><init>(Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;I)V

    .line 69
    .line 70
    .line 71
    invoke-static {v0}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {p3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p3

    .line 79
    check-cast p3, Ly4/h;

    .line 80
    .line 81
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    iput-object p3, p0, Lb0/x1;->j:Ly4/h;

    .line 85
    .line 86
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 87
    .line 88
    invoke-direct {v1, p4}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    new-instance v2, Lb0/r1;

    .line 92
    .line 93
    const/4 v3, 0x1

    .line 94
    invoke-direct {v2, v1, p2, v3}, Lb0/r1;-><init>(Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;I)V

    .line 95
    .line 96
    .line 97
    invoke-static {v2}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    iput-object v2, p0, Lb0/x1;->h:Ly4/k;

    .line 102
    .line 103
    new-instance v3, Lb0/x;

    .line 104
    .line 105
    const/4 v4, 0x1

    .line 106
    invoke-direct {v3, v4, p3, v0}, Lb0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 110
    .line 111
    .line 112
    move-result-object p3

    .line 113
    new-instance v0, Lk0/g;

    .line 114
    .line 115
    const/4 v4, 0x0

    .line 116
    invoke-direct {v0, v4, v2, v3}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v2, p3, v0}, Ly4/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p3

    .line 126
    check-cast p3, Ly4/h;

    .line 127
    .line 128
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 132
    .line 133
    invoke-direct {v0, p4}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    new-instance v1, Lb0/r1;

    .line 137
    .line 138
    const/4 v2, 0x2

    .line 139
    invoke-direct {v1, v0, p2, v2}, Lb0/r1;-><init>(Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;I)V

    .line 140
    .line 141
    .line 142
    invoke-static {v1}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    iput-object v1, p0, Lb0/x1;->f:Ly4/k;

    .line 147
    .line 148
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Ly4/h;

    .line 153
    .line 154
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    iput-object v0, p0, Lb0/x1;->g:Ly4/h;

    .line 158
    .line 159
    new-instance v0, Lb0/u1;

    .line 160
    .line 161
    invoke-direct {v0, p0, p1}, Lb0/u1;-><init>(Lb0/x1;Landroid/util/Size;)V

    .line 162
    .line 163
    .line 164
    iput-object v0, p0, Lb0/x1;->k:Lb0/u1;

    .line 165
    .line 166
    iget-object p1, v0, Lh0/t0;->e:Ly4/k;

    .line 167
    .line 168
    invoke-static {p1}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    new-instance v0, Lgw0/c;

    .line 173
    .line 174
    const/4 v2, 0x3

    .line 175
    invoke-direct {v0, p1, p3, p2, v2}, Lgw0/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 179
    .line 180
    .line 181
    move-result-object p2

    .line 182
    new-instance p3, Lk0/g;

    .line 183
    .line 184
    const/4 v2, 0x0

    .line 185
    invoke-direct {p3, v2, v1, v0}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v1, p2, p3}, Ly4/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 189
    .line 190
    .line 191
    new-instance p2, Lb0/s1;

    .line 192
    .line 193
    const/4 p3, 0x0

    .line 194
    invoke-direct {p2, p0, p3}, Lb0/s1;-><init>(Lb0/x1;I)V

    .line 195
    .line 196
    .line 197
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 198
    .line 199
    .line 200
    move-result-object p3

    .line 201
    invoke-interface {p1, p3, p2}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 202
    .line 203
    .line 204
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    new-instance p2, Ljava/util/concurrent/atomic/AtomicReference;

    .line 209
    .line 210
    invoke-direct {p2, p4}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    new-instance p3, La0/h;

    .line 214
    .line 215
    const/4 p4, 0x3

    .line 216
    invoke-direct {p3, p4, p0, p2}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    invoke-static {p3}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 220
    .line 221
    .line 222
    move-result-object p3

    .line 223
    new-instance p4, Laq/a;

    .line 224
    .line 225
    const/4 v0, 0x4

    .line 226
    invoke-direct {p4, p5, v0}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 227
    .line 228
    .line 229
    new-instance p5, Lk0/g;

    .line 230
    .line 231
    const/4 v0, 0x0

    .line 232
    invoke-direct {p5, v0, p3, p4}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p3, p1, p5}, Ly4/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    check-cast p1, Ly4/h;

    .line 243
    .line 244
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 245
    .line 246
    .line 247
    iput-object p1, p0, Lb0/x1;->i:Ly4/h;

    .line 248
    .line 249
    return-void
.end method


# virtual methods
.method public final a(Landroid/view/Surface;Ljava/util/concurrent/Executor;Lc6/a;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/Surface;->isValid()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance p0, Lb0/t1;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-direct {p0, p3, p1, v0}, Lb0/t1;-><init>(Lc6/a;Landroid/view/Surface;I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p2, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-object v0, p0, Lb0/x1;->g:Ly4/h;

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_2

    .line 24
    .line 25
    iget-object v0, p0, Lb0/x1;->f:Ly4/k;

    .line 26
    .line 27
    invoke-virtual {v0}, Ly4/k;->isCancelled()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    iget-object p0, v0, Ly4/k;->e:Ly4/j;

    .line 35
    .line 36
    invoke-virtual {p0}, Ly4/g;->isDone()Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    const/4 v1, 0x0

    .line 41
    invoke-static {v1, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 42
    .line 43
    .line 44
    :try_start_0
    invoke-virtual {v0}, Ly4/k;->get()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    new-instance p0, Lb0/t1;

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    invoke-direct {p0, p3, p1, v0}, Lb0/t1;-><init>(Lc6/a;Landroid/view/Surface;I)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p2, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :catch_0
    new-instance p0, Lb0/t1;

    .line 58
    .line 59
    const/4 v0, 0x2

    .line 60
    invoke-direct {p0, p3, p1, v0}, Lb0/t1;-><init>(Lc6/a;Landroid/view/Surface;I)V

    .line 61
    .line 62
    .line 63
    invoke-interface {p2, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_2
    :goto_0
    new-instance v0, Lb0/x;

    .line 68
    .line 69
    const/4 v1, 0x2

    .line 70
    invoke-direct {v0, v1, p3, p1}, Lb0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    new-instance p1, Lk0/g;

    .line 74
    .line 75
    const/4 p3, 0x0

    .line 76
    iget-object p0, p0, Lb0/x1;->h:Ly4/k;

    .line 77
    .line 78
    invoke-direct {p1, p3, p0, v0}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0, p2, p1}, Ly4/k;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 82
    .line 83
    .line 84
    return-void
.end method

.method public final b(Ljava/util/concurrent/Executor;Lb0/w1;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/x1;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p2, p0, Lb0/x1;->m:Lb0/w1;

    .line 5
    .line 6
    iput-object p1, p0, Lb0/x1;->n:Ljava/util/concurrent/Executor;

    .line 7
    .line 8
    iget-object p0, p0, Lb0/x1;->l:Lb0/j;

    .line 9
    .line 10
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    new-instance v0, Lb0/q1;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, p2, p0, v1}, Lb0/q1;-><init>(Lb0/w1;Lb0/j;I)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    throw p0
.end method

.method public final c()Z
    .locals 2

    .line 1
    new-instance v0, Lb0/l;

    .line 2
    .line 3
    const-string v1, "Surface request will not complete."

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lb0/x1;->g:Ly4/h;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method
