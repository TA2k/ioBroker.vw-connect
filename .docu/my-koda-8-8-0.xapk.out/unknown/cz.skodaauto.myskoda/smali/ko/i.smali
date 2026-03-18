.class public abstract Lko/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Ljava/lang/String;

.field public final f:Lc2/k;

.field public final g:Lko/b;

.field public final h:Llo/b;

.field public final i:Landroid/os/Looper;

.field public final j:I

.field public final k:Llo/u;

.field public final l:Llo/a;

.field public final m:Llo/g;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "Null context is not permitted."

    .line 5
    .line 6
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    const-string v0, "Api must not be null."

    .line 10
    .line 11
    invoke-static {p3, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "Settings must not be null; use Settings.DEFAULT_SETTINGS instead."

    .line 15
    .line 16
    invoke-static {p5, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "The provided context did not have an application context."

    .line 24
    .line 25
    invoke-static {v0, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lko/i;->d:Landroid/content/Context;

    .line 29
    .line 30
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 31
    .line 32
    const/16 v2, 0x1e

    .line 33
    .line 34
    if-lt v1, v2, :cond_0

    .line 35
    .line 36
    invoke-static {p1}, Ld6/t1;->i(Landroid/content/Context;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 p1, 0x0

    .line 42
    :goto_0
    iput-object p1, p0, Lko/i;->e:Ljava/lang/String;

    .line 43
    .line 44
    iput-object p3, p0, Lko/i;->f:Lc2/k;

    .line 45
    .line 46
    iput-object p4, p0, Lko/i;->g:Lko/b;

    .line 47
    .line 48
    iget-object v1, p5, Lko/h;->b:Landroid/os/Looper;

    .line 49
    .line 50
    iput-object v1, p0, Lko/i;->i:Landroid/os/Looper;

    .line 51
    .line 52
    new-instance v1, Llo/b;

    .line 53
    .line 54
    invoke-direct {v1, p3, p4, p1}, Llo/b;-><init>(Lc2/k;Lko/b;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iput-object v1, p0, Lko/i;->h:Llo/b;

    .line 58
    .line 59
    new-instance p1, Llo/u;

    .line 60
    .line 61
    invoke-direct {p1, p0}, Llo/u;-><init>(Lko/i;)V

    .line 62
    .line 63
    .line 64
    iput-object p1, p0, Lko/i;->k:Llo/u;

    .line 65
    .line 66
    invoke-static {v0}, Llo/g;->g(Landroid/content/Context;)Llo/g;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Lko/i;->m:Llo/g;

    .line 71
    .line 72
    iget-object p3, p1, Llo/g;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 73
    .line 74
    invoke-virtual {p3}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    .line 75
    .line 76
    .line 77
    move-result p3

    .line 78
    iput p3, p0, Lko/i;->j:I

    .line 79
    .line 80
    iget-object p3, p5, Lko/h;->a:Llo/a;

    .line 81
    .line 82
    iput-object p3, p0, Lko/i;->l:Llo/a;

    .line 83
    .line 84
    if-eqz p2, :cond_6

    .line 85
    .line 86
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 87
    .line 88
    .line 89
    move-result-object p3

    .line 90
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 91
    .line 92
    .line 93
    move-result-object p4

    .line 94
    if-ne p3, p4, :cond_6

    .line 95
    .line 96
    const-string p3, "SLifecycleFragmentImpl"

    .line 97
    .line 98
    sget-object p4, Llo/i0;->e:Ljava/util/WeakHashMap;

    .line 99
    .line 100
    invoke-virtual {p4, p2}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p5

    .line 104
    check-cast p5, Ljava/lang/ref/WeakReference;

    .line 105
    .line 106
    if-eqz p5, :cond_1

    .line 107
    .line 108
    invoke-virtual {p5}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p5

    .line 112
    check-cast p5, Llo/i0;

    .line 113
    .line 114
    if-nez p5, :cond_4

    .line 115
    .line 116
    :cond_1
    :try_start_0
    invoke-virtual {p2}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 117
    .line 118
    .line 119
    move-result-object p5

    .line 120
    invoke-virtual {p5, p3}, Landroidx/fragment/app/j1;->D(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 121
    .line 122
    .line 123
    move-result-object p5

    .line 124
    check-cast p5, Llo/i0;
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    .line 125
    .line 126
    if-eqz p5, :cond_2

    .line 127
    .line 128
    invoke-virtual {p5}, Landroidx/fragment/app/j0;->isRemoving()Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-eqz v0, :cond_3

    .line 133
    .line 134
    :cond_2
    new-instance p5, Llo/i0;

    .line 135
    .line 136
    invoke-direct {p5}, Llo/i0;-><init>()V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p2}, Landroidx/fragment/app/o0;->getSupportFragmentManager()Landroidx/fragment/app/j1;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    new-instance v2, Landroidx/fragment/app/a;

    .line 147
    .line 148
    invoke-direct {v2, v0}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 149
    .line 150
    .line 151
    const/4 v0, 0x0

    .line 152
    const/4 v3, 0x1

    .line 153
    invoke-virtual {v2, v0, p5, p3, v3}, Landroidx/fragment/app/a;->f(ILandroidx/fragment/app/j0;Ljava/lang/String;I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2, v3, v3}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 157
    .line 158
    .line 159
    :cond_3
    new-instance p3, Ljava/lang/ref/WeakReference;

    .line 160
    .line 161
    invoke-direct {p3, p5}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p4, p2, p3}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    :cond_4
    invoke-interface {p5}, Llo/j;->a()Llo/p;

    .line 168
    .line 169
    .line 170
    move-result-object p2

    .line 171
    if-nez p2, :cond_5

    .line 172
    .line 173
    new-instance p2, Llo/p;

    .line 174
    .line 175
    sget-object p3, Ljo/e;->c:Ljava/lang/Object;

    .line 176
    .line 177
    invoke-direct {p2, p5, p1}, Llo/p;-><init>(Llo/j;Llo/g;)V

    .line 178
    .line 179
    .line 180
    :cond_5
    iget-object p3, p2, Llo/p;->i:Landroidx/collection/g;

    .line 181
    .line 182
    invoke-virtual {p3, v1}, Landroidx/collection/g;->add(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    invoke-virtual {p1, p2}, Llo/g;->a(Llo/p;)V

    .line 186
    .line 187
    .line 188
    goto :goto_1

    .line 189
    :catch_0
    move-exception p0

    .line 190
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 191
    .line 192
    const-string p2, "Fragment with tag SLifecycleFragmentImpl is not a SupportLifecycleFragmentImpl"

    .line 193
    .line 194
    invoke-direct {p1, p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 195
    .line 196
    .line 197
    throw p1

    .line 198
    :cond_6
    :goto_1
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 199
    .line 200
    const/4 p2, 0x7

    .line 201
    invoke-virtual {p1, p2, p0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    invoke-virtual {p1, p0}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 206
    .line 207
    .line 208
    return-void
.end method


# virtual methods
.method public final b()Lil/g;
    .locals 4

    .line 1
    new-instance v0, Lil/g;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lil/g;-><init>(IZ)V

    .line 7
    .line 8
    .line 9
    sget-object v1, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 10
    .line 11
    iget-object v2, v0, Lil/g;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Landroidx/collection/g;

    .line 14
    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    new-instance v2, Landroidx/collection/g;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-direct {v2, v3}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iput-object v2, v0, Lil/g;->e:Ljava/lang/Object;

    .line 24
    .line 25
    :cond_0
    iget-object v2, v0, Lil/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v2, Landroidx/collection/g;

    .line 28
    .line 29
    invoke-virtual {v2, v1}, Landroidx/collection/g;->addAll(Ljava/util/Collection;)Z

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lko/i;->d:Landroid/content/Context;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    iput-object v1, v0, Lil/g;->g:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    iput-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 49
    .line 50
    return-object v0
.end method

.method public final c(Lb81/d;)Laq/t;
    .locals 5

    .line 1
    iget-object v0, p1, Lb81/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lw7/o;

    .line 4
    .line 5
    iget-object v0, v0, Lw7/o;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lis/b;

    .line 8
    .line 9
    iget-object v0, v0, Lis/b;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Llo/k;

    .line 12
    .line 13
    const-string v1, "Listener has already been released."

    .line 14
    .line 15
    invoke-static {v0, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lb81/a;

    .line 21
    .line 22
    iget-object v0, v0, Lb81/a;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Llo/k;

    .line 25
    .line 26
    invoke-static {v0, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p1, Lb81/d;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, Lw7/o;

    .line 32
    .line 33
    iget-object p1, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Lb81/a;

    .line 36
    .line 37
    iget-object v1, p0, Lko/i;->m:Llo/g;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    new-instance v2, Laq/k;

    .line 43
    .line 44
    invoke-direct {v2}, Laq/k;-><init>()V

    .line 45
    .line 46
    .line 47
    iget v3, v0, Lw7/o;->b:I

    .line 48
    .line 49
    invoke-virtual {v1, v2, v3, p0}, Llo/g;->f(Laq/k;ILko/i;)V

    .line 50
    .line 51
    .line 52
    new-instance v3, Llo/d0;

    .line 53
    .line 54
    new-instance v4, Llo/z;

    .line 55
    .line 56
    invoke-direct {v4, v0, p1}, Llo/z;-><init>(Lw7/o;Lb81/a;)V

    .line 57
    .line 58
    .line 59
    invoke-direct {v3, v4, v2}, Llo/d0;-><init>(Llo/z;Laq/k;)V

    .line 60
    .line 61
    .line 62
    iget-object p1, v1, Llo/g;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 63
    .line 64
    new-instance v0, Llo/y;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    invoke-direct {v0, v3, p1, p0}, Llo/y;-><init>(Llo/f0;ILko/i;)V

    .line 71
    .line 72
    .line 73
    iget-object p0, v1, Llo/g;->q:Lbp/c;

    .line 74
    .line 75
    const/16 p1, 0x8

    .line 76
    .line 77
    invoke-virtual {p0, p1, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 82
    .line 83
    .line 84
    iget-object p0, v2, Laq/k;->a:Laq/t;

    .line 85
    .line 86
    return-object p0
.end method

.method public final d(Llo/k;I)Laq/t;
    .locals 3

    .line 1
    const-string v0, "Listener key cannot be null."

    .line 2
    .line 3
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lko/i;->m:Llo/g;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    new-instance v1, Laq/k;

    .line 12
    .line 13
    invoke-direct {v1}, Laq/k;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1, p2, p0}, Llo/g;->f(Laq/k;ILko/i;)V

    .line 17
    .line 18
    .line 19
    new-instance p2, Llo/d0;

    .line 20
    .line 21
    invoke-direct {p2, p1, v1}, Llo/d0;-><init>(Llo/k;Laq/k;)V

    .line 22
    .line 23
    .line 24
    iget-object p1, v0, Llo/g;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 25
    .line 26
    new-instance v2, Llo/y;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    invoke-direct {v2, p2, p1, p0}, Llo/y;-><init>(Llo/f0;ILko/i;)V

    .line 33
    .line 34
    .line 35
    iget-object p0, v0, Llo/g;->q:Lbp/c;

    .line 36
    .line 37
    const/16 p1, 0xd

    .line 38
    .line 39
    invoke-virtual {p0, p1, v2}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 44
    .line 45
    .line 46
    iget-object p0, v1, Laq/k;->a:Laq/t;

    .line 47
    .line 48
    return-object p0
.end method

.method public final e(ILhr/b0;)Laq/t;
    .locals 4

    .line 1
    new-instance v0, Laq/k;

    .line 2
    .line 3
    invoke-direct {v0}, Laq/k;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lko/i;->m:Llo/g;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget v2, p2, Lhr/b0;->e:I

    .line 12
    .line 13
    invoke-virtual {v1, v0, v2, p0}, Llo/g;->f(Laq/k;ILko/i;)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Llo/e0;

    .line 17
    .line 18
    iget-object v3, p0, Lko/i;->l:Llo/a;

    .line 19
    .line 20
    invoke-direct {v2, p1, p2, v0, v3}, Llo/e0;-><init>(ILhr/b0;Laq/k;Llo/a;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, v1, Llo/g;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 24
    .line 25
    new-instance p2, Llo/y;

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-direct {p2, v2, p1, p0}, Llo/y;-><init>(Llo/f0;ILko/i;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, v1, Llo/g;->q:Lbp/c;

    .line 35
    .line 36
    const/4 p1, 0x4

    .line 37
    invoke-virtual {p0, p1, p2}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 42
    .line 43
    .line 44
    iget-object p0, v0, Laq/k;->a:Laq/t;

    .line 45
    .line 46
    return-object p0
.end method
