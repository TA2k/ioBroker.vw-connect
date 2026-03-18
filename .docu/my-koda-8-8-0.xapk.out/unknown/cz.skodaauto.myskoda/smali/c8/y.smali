.class public final Lc8/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final l0:Ljava/lang/Object;

.field public static m0:Ljava/util/concurrent/ScheduledExecutorService;

.field public static n0:I


# instance fields
.field public A:Lt7/c;

.field public B:Lc8/u;

.field public C:Lc8/u;

.field public D:Lt7/g0;

.field public E:Z

.field public F:J

.field public G:J

.field public H:J

.field public I:J

.field public J:I

.field public K:Z

.field public L:Z

.field public M:J

.field public N:F

.field public O:Ljava/nio/ByteBuffer;

.field public P:I

.field public Q:Ljava/nio/ByteBuffer;

.field public R:Z

.field public S:Z

.field public T:Z

.field public U:Z

.field public V:Z

.field public W:I

.field public X:Z

.field public Y:Lt7/d;

.field public Z:La0/j;

.field public final a:Landroid/content/Context;

.field public a0:Z

.field public final b:Lgw0/c;

.field public b0:J

.field public final c:Lc8/q;

.field public c0:J

.field public final d:Lc8/e0;

.field public d0:Z

.field public final e:Lu7/j;

.field public e0:Z

.field public final f:Lc8/d0;

.field public f0:Landroid/os/Looper;

.field public final g:Lhr/x0;

.field public g0:J

.field public final h:Lc8/p;

.field public h0:J

.field public final i:Ljava/util/ArrayDeque;

.field public i0:Landroid/os/Handler;

.field public j:I

.field public j0:Landroid/content/Context;

.field public k:Lgw0/c;

.field public final k0:Z

.field public final l:Las/e;

.field public final m:Las/e;

.field public final n:Lc8/z;

.field public final o:Lc2/k;

.field public final p:Lc8/z;

.field public final q:I

.field public r:Lb8/k;

.field public s:Laq/a;

.field public t:Lc8/t;

.field public u:Lc8/t;

.field public v:Lu7/c;

.field public w:Landroid/media/AudioTrack;

.field public x:Lc8/b;

.field public y:Lc8/f;

.field public z:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc8/y;->l0:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lc8/s;)V
    .locals 10

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lc8/s;->a:Landroid/content/Context;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    :goto_0
    iput-object v2, p0, Lc8/y;->a:Landroid/content/Context;

    .line 16
    .line 17
    sget-object v3, Lt7/c;->b:Lt7/c;

    .line 18
    .line 19
    iput-object v3, p0, Lc8/y;->A:Lt7/c;

    .line 20
    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    iget-object v1, p1, Lc8/s;->b:Lc8/b;

    .line 25
    .line 26
    :goto_1
    iput-object v1, p0, Lc8/y;->x:Lc8/b;

    .line 27
    .line 28
    iget-object v1, p1, Lc8/s;->c:Lgw0/c;

    .line 29
    .line 30
    iput-object v1, p0, Lc8/y;->b:Lgw0/c;

    .line 31
    .line 32
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    iput v2, p0, Lc8/y;->j:I

    .line 36
    .line 37
    iget-object v3, p1, Lc8/s;->e:Lc8/z;

    .line 38
    .line 39
    iput-object v3, p0, Lc8/y;->n:Lc8/z;

    .line 40
    .line 41
    iget-object v3, p1, Lc8/s;->g:Lc2/k;

    .line 42
    .line 43
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    iput-object v3, p0, Lc8/y;->o:Lc2/k;

    .line 47
    .line 48
    new-instance v3, Lc8/p;

    .line 49
    .line 50
    new-instance v4, Lbu/c;

    .line 51
    .line 52
    const/16 v5, 0x9

    .line 53
    .line 54
    invoke-direct {v4, p0, v5}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 55
    .line 56
    .line 57
    invoke-direct {v3, v4}, Lc8/p;-><init>(Lbu/c;)V

    .line 58
    .line 59
    .line 60
    iput-object v3, p0, Lc8/y;->h:Lc8/p;

    .line 61
    .line 62
    new-instance v3, Lc8/q;

    .line 63
    .line 64
    invoke-direct {v3}, Lu7/g;-><init>()V

    .line 65
    .line 66
    .line 67
    iput-object v3, p0, Lc8/y;->c:Lc8/q;

    .line 68
    .line 69
    new-instance v4, Lc8/e0;

    .line 70
    .line 71
    invoke-direct {v4}, Lu7/g;-><init>()V

    .line 72
    .line 73
    .line 74
    sget-object v5, Lw7/w;->b:[B

    .line 75
    .line 76
    iput-object v5, v4, Lc8/e0;->m:[B

    .line 77
    .line 78
    iput-object v4, p0, Lc8/y;->d:Lc8/e0;

    .line 79
    .line 80
    new-instance v5, Lu7/j;

    .line 81
    .line 82
    invoke-direct {v5}, Lu7/g;-><init>()V

    .line 83
    .line 84
    .line 85
    iput-object v5, p0, Lc8/y;->e:Lu7/j;

    .line 86
    .line 87
    new-instance v5, Lc8/d0;

    .line 88
    .line 89
    invoke-direct {v5}, Lu7/g;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object v5, p0, Lc8/y;->f:Lc8/d0;

    .line 93
    .line 94
    invoke-static {v4, v3}, Lhr/h0;->v(Ljava/lang/Object;Ljava/lang/Object;)Lhr/x0;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    iput-object v3, p0, Lc8/y;->g:Lhr/x0;

    .line 99
    .line 100
    const/high16 v3, 0x3f800000    # 1.0f

    .line 101
    .line 102
    iput v3, p0, Lc8/y;->N:F

    .line 103
    .line 104
    iput v2, p0, Lc8/y;->W:I

    .line 105
    .line 106
    new-instance v3, Lt7/d;

    .line 107
    .line 108
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 109
    .line 110
    .line 111
    iput-object v3, p0, Lc8/y;->Y:Lt7/d;

    .line 112
    .line 113
    new-instance v4, Lc8/u;

    .line 114
    .line 115
    sget-object v5, Lt7/g0;->d:Lt7/g0;

    .line 116
    .line 117
    const-wide/16 v6, 0x0

    .line 118
    .line 119
    const-wide/16 v8, 0x0

    .line 120
    .line 121
    invoke-direct/range {v4 .. v9}, Lc8/u;-><init>(Lt7/g0;JJ)V

    .line 122
    .line 123
    .line 124
    iput-object v4, p0, Lc8/y;->C:Lc8/u;

    .line 125
    .line 126
    iput-object v5, p0, Lc8/y;->D:Lt7/g0;

    .line 127
    .line 128
    iput-boolean v2, p0, Lc8/y;->E:Z

    .line 129
    .line 130
    new-instance v2, Ljava/util/ArrayDeque;

    .line 131
    .line 132
    invoke-direct {v2}, Ljava/util/ArrayDeque;-><init>()V

    .line 133
    .line 134
    .line 135
    iput-object v2, p0, Lc8/y;->i:Ljava/util/ArrayDeque;

    .line 136
    .line 137
    new-instance v2, Las/e;

    .line 138
    .line 139
    const/4 v3, 0x1

    .line 140
    invoke-direct {v2, v3}, Las/e;-><init>(I)V

    .line 141
    .line 142
    .line 143
    iput-object v2, p0, Lc8/y;->l:Las/e;

    .line 144
    .line 145
    new-instance v2, Las/e;

    .line 146
    .line 147
    invoke-direct {v2, v3}, Las/e;-><init>(I)V

    .line 148
    .line 149
    .line 150
    iput-object v2, p0, Lc8/y;->m:Las/e;

    .line 151
    .line 152
    iget-object p1, p1, Lc8/s;->f:Lc8/z;

    .line 153
    .line 154
    iput-object p1, p0, Lc8/y;->p:Lc8/z;

    .line 155
    .line 156
    const/16 p1, 0x22

    .line 157
    .line 158
    const/4 v2, -0x1

    .line 159
    if-lt v1, p1, :cond_3

    .line 160
    .line 161
    if-nez v0, :cond_2

    .line 162
    .line 163
    goto :goto_2

    .line 164
    :cond_2
    invoke-static {v0}, Lc2/h;->b(Landroid/content/Context;)I

    .line 165
    .line 166
    .line 167
    move-result p1

    .line 168
    if-eqz p1, :cond_3

    .line 169
    .line 170
    if-eq p1, v2, :cond_3

    .line 171
    .line 172
    move v2, p1

    .line 173
    :cond_3
    :goto_2
    iput v2, p0, Lc8/y;->q:I

    .line 174
    .line 175
    const/4 p1, 0x1

    .line 176
    iput-boolean p1, p0, Lc8/y;->k0:Z

    .line 177
    .line 178
    return-void
.end method

.method public static p(Landroid/media/AudioTrack;)Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/media/AudioTrack;->isOffloadedPlayback()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method


# virtual methods
.method public final a(J)V
    .locals 9

    .line 1
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lc8/y;->b:Lgw0/c;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-boolean v3, v0, Lc8/t;->j:Z

    .line 9
    .line 10
    if-eqz v3, :cond_0

    .line 11
    .line 12
    sget-object v0, Lt7/g0;->d:Lt7/g0;

    .line 13
    .line 14
    :goto_0
    move-object v4, v0

    .line 15
    goto :goto_4

    .line 16
    :cond_0
    iget-boolean v3, p0, Lc8/y;->a0:Z

    .line 17
    .line 18
    if-nez v3, :cond_4

    .line 19
    .line 20
    iget v3, v0, Lc8/t;->c:I

    .line 21
    .line 22
    if-nez v3, :cond_4

    .line 23
    .line 24
    iget-object v0, v0, Lc8/t;->a:Lt7/o;

    .line 25
    .line 26
    iget v0, v0, Lt7/o;->H:I

    .line 27
    .line 28
    iget-object v0, p0, Lc8/y;->D:Lt7/g0;

    .line 29
    .line 30
    iget-object v3, v2, Lgw0/c;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v3, Lu7/i;

    .line 33
    .line 34
    iget v4, v0, Lt7/g0;->a:F

    .line 35
    .line 36
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    cmpl-float v6, v4, v5

    .line 41
    .line 42
    const/4 v7, 0x1

    .line 43
    if-lez v6, :cond_1

    .line 44
    .line 45
    move v6, v7

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    move v6, v1

    .line 48
    :goto_1
    invoke-static {v6}, Lw7/a;->c(Z)V

    .line 49
    .line 50
    .line 51
    iget v6, v3, Lu7/i;->c:F

    .line 52
    .line 53
    cmpl-float v6, v6, v4

    .line 54
    .line 55
    if-eqz v6, :cond_2

    .line 56
    .line 57
    iput v4, v3, Lu7/i;->c:F

    .line 58
    .line 59
    iput-boolean v7, v3, Lu7/i;->i:Z

    .line 60
    .line 61
    :cond_2
    iget v4, v0, Lt7/g0;->b:F

    .line 62
    .line 63
    cmpl-float v5, v4, v5

    .line 64
    .line 65
    if-lez v5, :cond_3

    .line 66
    .line 67
    move v5, v7

    .line 68
    goto :goto_2

    .line 69
    :cond_3
    move v5, v1

    .line 70
    :goto_2
    invoke-static {v5}, Lw7/a;->c(Z)V

    .line 71
    .line 72
    .line 73
    iget v5, v3, Lu7/i;->d:F

    .line 74
    .line 75
    cmpl-float v5, v5, v4

    .line 76
    .line 77
    if-eqz v5, :cond_5

    .line 78
    .line 79
    iput v4, v3, Lu7/i;->d:F

    .line 80
    .line 81
    iput-boolean v7, v3, Lu7/i;->i:Z

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_4
    sget-object v0, Lt7/g0;->d:Lt7/g0;

    .line 85
    .line 86
    :cond_5
    :goto_3
    iput-object v0, p0, Lc8/y;->D:Lt7/g0;

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :goto_4
    iget-boolean v0, p0, Lc8/y;->a0:Z

    .line 90
    .line 91
    if-nez v0, :cond_6

    .line 92
    .line 93
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 94
    .line 95
    iget v3, v0, Lc8/t;->c:I

    .line 96
    .line 97
    if-nez v3, :cond_6

    .line 98
    .line 99
    iget-object v0, v0, Lc8/t;->a:Lt7/o;

    .line 100
    .line 101
    iget v0, v0, Lt7/o;->H:I

    .line 102
    .line 103
    iget-boolean v1, p0, Lc8/y;->E:Z

    .line 104
    .line 105
    iget-object v0, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v0, Lc8/c0;

    .line 108
    .line 109
    iput-boolean v1, v0, Lc8/c0;->o:Z

    .line 110
    .line 111
    :cond_6
    iput-boolean v1, p0, Lc8/y;->E:Z

    .line 112
    .line 113
    new-instance v3, Lc8/u;

    .line 114
    .line 115
    const-wide/16 v0, 0x0

    .line 116
    .line 117
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->max(JJ)J

    .line 118
    .line 119
    .line 120
    move-result-wide v5

    .line 121
    iget-object p1, p0, Lc8/y;->u:Lc8/t;

    .line 122
    .line 123
    invoke-virtual {p0}, Lc8/y;->k()J

    .line 124
    .line 125
    .line 126
    move-result-wide v0

    .line 127
    iget p1, p1, Lc8/t;->e:I

    .line 128
    .line 129
    invoke-static {p1, v0, v1}, Lw7/w;->H(IJ)J

    .line 130
    .line 131
    .line 132
    move-result-wide v7

    .line 133
    invoke-direct/range {v3 .. v8}, Lc8/u;-><init>(Lt7/g0;JJ)V

    .line 134
    .line 135
    .line 136
    iget-object p1, p0, Lc8/y;->i:Ljava/util/ArrayDeque;

    .line 137
    .line 138
    invoke-virtual {p1, v3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    iget-object p1, p0, Lc8/y;->u:Lc8/t;

    .line 142
    .line 143
    iget-object p1, p1, Lc8/t;->i:Lu7/c;

    .line 144
    .line 145
    iput-object p1, p0, Lc8/y;->v:Lu7/c;

    .line 146
    .line 147
    invoke-virtual {p1}, Lu7/c;->a()V

    .line 148
    .line 149
    .line 150
    iget-object p1, p0, Lc8/y;->s:Laq/a;

    .line 151
    .line 152
    if-eqz p1, :cond_7

    .line 153
    .line 154
    iget-boolean p0, p0, Lc8/y;->E:Z

    .line 155
    .line 156
    iget-object p1, p1, Laq/a;->e:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast p1, Lc8/a0;

    .line 159
    .line 160
    iget-object p1, p1, Lc8/a0;->Q1:Lb81/d;

    .line 161
    .line 162
    iget-object p2, p1, Lb81/d;->e:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast p2, Landroid/os/Handler;

    .line 165
    .line 166
    if-eqz p2, :cond_7

    .line 167
    .line 168
    new-instance v0, La0/b;

    .line 169
    .line 170
    const/4 v1, 0x1

    .line 171
    invoke-direct {v0, p1, p0, v1}, La0/b;-><init>(Ljava/lang/Object;ZI)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {p2, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 175
    .line 176
    .line 177
    :cond_7
    return-void
.end method

.method public final b(Lc8/j;Lt7/c;ILt7/o;Landroid/content/Context;)Landroid/media/AudioTrack;
    .locals 10

    .line 1
    :try_start_0
    iget-object p0, p0, Lc8/y;->p:Lc8/z;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3, p5}, Lc8/z;->a(Lc8/j;Lt7/c;ILandroid/content/Context;)Landroid/media/AudioTrack;

    .line 4
    .line 5
    .line 6
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1

    .line 7
    invoke-virtual {p0}, Landroid/media/AudioTrack;->getState()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 p2, 0x1

    .line 12
    if-ne v1, p2, :cond_0

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    :try_start_1
    invoke-virtual {p0}, Landroid/media/AudioTrack;->release()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 16
    .line 17
    .line 18
    :catch_0
    new-instance v0, Lc8/l;

    .line 19
    .line 20
    iget v2, p1, Lc8/j;->b:I

    .line 21
    .line 22
    iget v3, p1, Lc8/j;->c:I

    .line 23
    .line 24
    iget v4, p1, Lc8/j;->a:I

    .line 25
    .line 26
    iget v5, p1, Lc8/j;->f:I

    .line 27
    .line 28
    iget-boolean v7, p1, Lc8/j;->e:Z

    .line 29
    .line 30
    const/4 v8, 0x0

    .line 31
    move-object v6, p4

    .line 32
    invoke-direct/range {v0 .. v8}, Lc8/l;-><init>(IIIIILt7/o;ZLjava/lang/RuntimeException;)V

    .line 33
    .line 34
    .line 35
    throw v0

    .line 36
    :catch_1
    move-exception v0

    .line 37
    move-object v6, p4

    .line 38
    move-object p0, v0

    .line 39
    move-object v9, p0

    .line 40
    new-instance v1, Lc8/l;

    .line 41
    .line 42
    iget v3, p1, Lc8/j;->b:I

    .line 43
    .line 44
    iget v4, p1, Lc8/j;->c:I

    .line 45
    .line 46
    iget v5, p1, Lc8/j;->a:I

    .line 47
    .line 48
    move-object v7, v6

    .line 49
    iget v6, p1, Lc8/j;->f:I

    .line 50
    .line 51
    iget-boolean v8, p1, Lc8/j;->e:Z

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    invoke-direct/range {v1 .. v9}, Lc8/l;-><init>(IIIIILt7/o;ZLjava/lang/RuntimeException;)V

    .line 55
    .line 56
    .line 57
    throw v1
.end method

.method public final c(Lc8/t;)Landroid/media/AudioTrack;
    .locals 8

    .line 1
    :try_start_0
    iget v0, p0, Lc8/y;->W:I

    .line 2
    .line 3
    iget v1, p0, Lc8/y;->q:I
    :try_end_0
    .catch Lc8/l; {:try_start_0 .. :try_end_0} :catch_2

    .line 4
    .line 5
    const/4 v2, -0x1

    .line 6
    if-eq v1, v2, :cond_1

    .line 7
    .line 8
    :try_start_1
    iget-object v2, p0, Lc8/y;->a:Landroid/content/Context;

    .line 9
    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 13
    .line 14
    const/16 v4, 0x22

    .line 15
    .line 16
    if-lt v3, v4, :cond_1

    .line 17
    .line 18
    iget-object v0, p0, Lc8/y;->j0:Landroid/content/Context;

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    invoke-static {v2, v1}, Lc2/h;->f(Landroid/content/Context;I)Landroid/content/Context;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    iput-object v0, p0, Lc8/y;->j0:Landroid/content/Context;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catch_0
    move-exception v0

    .line 30
    move-object p1, v0

    .line 31
    move-object v2, p0

    .line 32
    goto :goto_3

    .line 33
    :cond_0
    :goto_0
    iget-object v0, p0, Lc8/y;->j0:Landroid/content/Context;
    :try_end_1
    .catch Lc8/l; {:try_start_1 .. :try_end_1} :catch_0

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    move-object v7, v0

    .line 37
    move v5, v1

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/4 v1, 0x0

    .line 40
    move v5, v0

    .line 41
    move-object v7, v1

    .line 42
    :goto_1
    :try_start_2
    invoke-virtual {p1}, Lc8/t;->a()Lc8/j;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    iget-object v4, p0, Lc8/y;->A:Lt7/c;

    .line 47
    .line 48
    iget-object v6, p1, Lc8/t;->a:Lt7/o;
    :try_end_2
    .catch Lc8/l; {:try_start_2 .. :try_end_2} :catch_2

    .line 49
    .line 50
    move-object v2, p0

    .line 51
    :try_start_3
    invoke-virtual/range {v2 .. v7}, Lc8/y;->b(Lc8/j;Lt7/c;ILt7/o;Landroid/content/Context;)Landroid/media/AudioTrack;

    .line 52
    .line 53
    .line 54
    move-result-object p0
    :try_end_3
    .catch Lc8/l; {:try_start_3 .. :try_end_3} :catch_1

    .line 55
    return-object p0

    .line 56
    :catch_1
    move-exception v0

    .line 57
    :goto_2
    move-object p1, v0

    .line 58
    goto :goto_3

    .line 59
    :catch_2
    move-exception v0

    .line 60
    move-object v2, p0

    .line 61
    goto :goto_2

    .line 62
    :goto_3
    iget-object p0, v2, Lc8/y;->s:Laq/a;

    .line 63
    .line 64
    if-eqz p0, :cond_2

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Laq/a;->B(Ljava/lang/Exception;)V

    .line 67
    .line 68
    .line 69
    :cond_2
    throw p1
.end method

.method public final d(Lt7/o;[I)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-virtual {v0}, Lc8/y;->q()V

    .line 6
    .line 7
    .line 8
    iget-object v1, v2, Lt7/o;->n:Ljava/lang/String;

    .line 9
    .line 10
    iget v3, v2, Lt7/o;->G:I

    .line 11
    .line 12
    iget v4, v2, Lt7/o;->F:I

    .line 13
    .line 14
    iget v5, v2, Lt7/o;->H:I

    .line 15
    .line 16
    const-string v6, "audio/raw"

    .line 17
    .line 18
    invoke-virtual {v6, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    iget-object v9, v0, Lc8/y;->p:Lc8/z;

    .line 23
    .line 24
    const/4 v10, 0x1

    .line 25
    const/4 v11, -0x1

    .line 26
    if-eqz v6, :cond_4

    .line 27
    .line 28
    invoke-static {v5}, Lw7/w;->A(I)Z

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    invoke-static {v6}, Lw7/a;->c(Z)V

    .line 33
    .line 34
    .line 35
    invoke-static {v5}, Lw7/w;->n(I)I

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    mul-int/2addr v6, v4

    .line 40
    new-instance v12, Lhr/e0;

    .line 41
    .line 42
    const/4 v13, 0x4

    .line 43
    invoke-direct {v12, v13}, Lhr/b0;-><init>(I)V

    .line 44
    .line 45
    .line 46
    iget-object v13, v0, Lc8/y;->g:Lhr/x0;

    .line 47
    .line 48
    invoke-virtual {v12, v13}, Lhr/b0;->d(Ljava/lang/Iterable;)V

    .line 49
    .line 50
    .line 51
    iget-object v13, v0, Lc8/y;->e:Lu7/j;

    .line 52
    .line 53
    invoke-virtual {v12, v13}, Lhr/b0;->a(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    iget-object v13, v0, Lc8/y;->b:Lgw0/c;

    .line 57
    .line 58
    iget-object v13, v13, Lgw0/c;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v13, [Lu7/f;

    .line 61
    .line 62
    invoke-virtual {v12, v13}, Lhr/b0;->b([Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    new-instance v13, Lu7/c;

    .line 66
    .line 67
    invoke-virtual {v12}, Lhr/e0;->i()Lhr/x0;

    .line 68
    .line 69
    .line 70
    move-result-object v12

    .line 71
    invoke-direct {v13, v12}, Lu7/c;-><init>(Lhr/h0;)V

    .line 72
    .line 73
    .line 74
    iget-object v12, v0, Lc8/y;->v:Lu7/c;

    .line 75
    .line 76
    invoke-virtual {v13, v12}, Lu7/c;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v12

    .line 80
    if-eqz v12, :cond_0

    .line 81
    .line 82
    iget-object v13, v0, Lc8/y;->v:Lu7/c;

    .line 83
    .line 84
    :cond_0
    iget v12, v2, Lt7/o;->I:I

    .line 85
    .line 86
    iget v14, v2, Lt7/o;->J:I

    .line 87
    .line 88
    iget-object v15, v0, Lc8/y;->d:Lc8/e0;

    .line 89
    .line 90
    iput v12, v15, Lc8/e0;->i:I

    .line 91
    .line 92
    iput v14, v15, Lc8/e0;->j:I

    .line 93
    .line 94
    iget-object v12, v0, Lc8/y;->c:Lc8/q;

    .line 95
    .line 96
    move-object/from16 v14, p2

    .line 97
    .line 98
    iput-object v14, v12, Lc8/q;->i:[I

    .line 99
    .line 100
    new-instance v12, Lu7/d;

    .line 101
    .line 102
    invoke-direct {v12, v3, v4, v5}, Lu7/d;-><init>(III)V

    .line 103
    .line 104
    .line 105
    :try_start_0
    iget-object v3, v13, Lu7/c;->a:Lhr/h0;

    .line 106
    .line 107
    sget-object v4, Lu7/d;->e:Lu7/d;

    .line 108
    .line 109
    invoke-virtual {v12, v4}, Lu7/d;->equals(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-nez v4, :cond_3

    .line 114
    .line 115
    const/4 v4, 0x0

    .line 116
    :goto_0
    invoke-virtual {v3}, Ljava/util/AbstractCollection;->size()I

    .line 117
    .line 118
    .line 119
    move-result v5

    .line 120
    if-ge v4, v5, :cond_2

    .line 121
    .line 122
    invoke-interface {v3, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v5

    .line 126
    check-cast v5, Lu7/f;

    .line 127
    .line 128
    invoke-interface {v5, v12}, Lu7/f;->f(Lu7/d;)Lu7/d;

    .line 129
    .line 130
    .line 131
    move-result-object v14

    .line 132
    invoke-interface {v5}, Lu7/f;->a()Z

    .line 133
    .line 134
    .line 135
    move-result v5

    .line 136
    if-eqz v5, :cond_1

    .line 137
    .line 138
    sget-object v5, Lu7/d;->e:Lu7/d;

    .line 139
    .line 140
    invoke-virtual {v14, v5}, Lu7/d;->equals(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v5

    .line 144
    xor-int/lit8 v5, v5, 0x1

    .line 145
    .line 146
    invoke-static {v5}, Lw7/a;->j(Z)V
    :try_end_0
    .catch Lu7/e; {:try_start_0 .. :try_end_0} :catch_0

    .line 147
    .line 148
    .line 149
    move-object v12, v14

    .line 150
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 151
    .line 152
    goto :goto_0

    .line 153
    :cond_2
    iget v3, v12, Lu7/d;->b:I

    .line 154
    .line 155
    iget v4, v12, Lu7/d;->c:I

    .line 156
    .line 157
    iget v5, v12, Lu7/d;->a:I

    .line 158
    .line 159
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    invoke-static {v3}, Lw7/w;->m(I)I

    .line 163
    .line 164
    .line 165
    move-result v9

    .line 166
    invoke-static {v4}, Lw7/w;->n(I)I

    .line 167
    .line 168
    .line 169
    move-result v12

    .line 170
    mul-int/2addr v12, v3

    .line 171
    move v3, v6

    .line 172
    const/4 v14, 0x0

    .line 173
    const/4 v15, 0x0

    .line 174
    move v6, v5

    .line 175
    move v5, v12

    .line 176
    const/4 v12, 0x0

    .line 177
    goto/16 :goto_2

    .line 178
    .line 179
    :cond_3
    :try_start_1
    new-instance v0, Lu7/e;

    .line 180
    .line 181
    invoke-direct {v0, v12}, Lu7/e;-><init>(Lu7/d;)V

    .line 182
    .line 183
    .line 184
    throw v0
    :try_end_1
    .catch Lu7/e; {:try_start_1 .. :try_end_1} :catch_0

    .line 185
    :catch_0
    move-exception v0

    .line 186
    new-instance v1, Lc8/k;

    .line 187
    .line 188
    invoke-direct {v1, v0, v2}, Lc8/k;-><init>(Lu7/e;Lt7/o;)V

    .line 189
    .line 190
    .line 191
    throw v1

    .line 192
    :cond_4
    new-instance v13, Lu7/c;

    .line 193
    .line 194
    sget-object v5, Lhr/x0;->h:Lhr/x0;

    .line 195
    .line 196
    invoke-direct {v13, v5}, Lu7/c;-><init>(Lhr/h0;)V

    .line 197
    .line 198
    .line 199
    iget v5, v0, Lc8/y;->j:I

    .line 200
    .line 201
    if-eqz v5, :cond_5

    .line 202
    .line 203
    invoke-virtual/range {p0 .. p1}, Lc8/y;->h(Lt7/o;)Lc8/h;

    .line 204
    .line 205
    .line 206
    move-result-object v5

    .line 207
    goto :goto_1

    .line 208
    :cond_5
    sget-object v5, Lc8/h;->d:Lc8/h;

    .line 209
    .line 210
    :goto_1
    iget v6, v0, Lc8/y;->j:I

    .line 211
    .line 212
    if-eqz v6, :cond_6

    .line 213
    .line 214
    iget-boolean v6, v5, Lc8/h;->a:Z

    .line 215
    .line 216
    if-eqz v6, :cond_6

    .line 217
    .line 218
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    iget-object v6, v2, Lt7/o;->k:Ljava/lang/String;

    .line 222
    .line 223
    invoke-static {v1, v6}, Lt7/d0;->c(Ljava/lang/String;Ljava/lang/String;)I

    .line 224
    .line 225
    .line 226
    move-result v6

    .line 227
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    invoke-static {v4}, Lw7/w;->m(I)I

    .line 231
    .line 232
    .line 233
    move-result v9

    .line 234
    iget-boolean v4, v5, Lc8/h;->b:Z

    .line 235
    .line 236
    move v12, v4

    .line 237
    move v4, v6

    .line 238
    move v14, v10

    .line 239
    move v15, v14

    .line 240
    move v5, v11

    .line 241
    move v6, v3

    .line 242
    move v3, v5

    .line 243
    goto :goto_2

    .line 244
    :cond_6
    iget-object v4, v0, Lc8/y;->x:Lc8/b;

    .line 245
    .line 246
    iget-object v5, v0, Lc8/y;->A:Lt7/c;

    .line 247
    .line 248
    invoke-virtual {v4, v2, v5}, Lc8/b;->d(Lt7/o;Lt7/c;)Landroid/util/Pair;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    if-eqz v4, :cond_1a

    .line 253
    .line 254
    iget-object v5, v4, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v5, Ljava/lang/Integer;

    .line 257
    .line 258
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 259
    .line 260
    .line 261
    move-result v5

    .line 262
    iget-object v4, v4, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v4, Ljava/lang/Integer;

    .line 265
    .line 266
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 267
    .line 268
    .line 269
    move-result v9

    .line 270
    move v6, v3

    .line 271
    move v4, v5

    .line 272
    move v3, v11

    .line 273
    move v5, v3

    .line 274
    const/4 v12, 0x0

    .line 275
    const/4 v14, 0x2

    .line 276
    const/4 v15, 0x0

    .line 277
    :goto_2
    const-string v8, ") for: "

    .line 278
    .line 279
    if-eqz v4, :cond_19

    .line 280
    .line 281
    if-eqz v9, :cond_18

    .line 282
    .line 283
    iget v8, v2, Lt7/o;->j:I

    .line 284
    .line 285
    const-string v7, "audio/vnd.dts.hd;profile=lbr"

    .line 286
    .line 287
    invoke-virtual {v7, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    move-result v1

    .line 291
    if-eqz v1, :cond_7

    .line 292
    .line 293
    if-ne v8, v11, :cond_7

    .line 294
    .line 295
    const v8, 0xbb800

    .line 296
    .line 297
    .line 298
    :cond_7
    invoke-static {v6, v9, v4}, Landroid/media/AudioTrack;->getMinBufferSize(III)I

    .line 299
    .line 300
    .line 301
    move-result v1

    .line 302
    const/4 v7, -0x2

    .line 303
    if-eq v1, v7, :cond_8

    .line 304
    .line 305
    move v7, v10

    .line 306
    goto :goto_3

    .line 307
    :cond_8
    const/4 v7, 0x0

    .line 308
    :goto_3
    invoke-static {v7}, Lw7/a;->j(Z)V

    .line 309
    .line 310
    .line 311
    if-eq v5, v11, :cond_9

    .line 312
    .line 313
    move v7, v5

    .line 314
    goto :goto_4

    .line 315
    :cond_9
    move v7, v10

    .line 316
    :goto_4
    if-eqz v15, :cond_a

    .line 317
    .line 318
    const-wide/high16 v17, 0x4020000000000000L    # 8.0

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_a
    const-wide/high16 v17, 0x3ff0000000000000L    # 1.0

    .line 322
    .line 323
    :goto_5
    iget-object v11, v0, Lc8/y;->n:Lc8/z;

    .line 324
    .line 325
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 326
    .line 327
    .line 328
    const-wide/32 v20, 0xf4240

    .line 329
    .line 330
    .line 331
    if-eqz v14, :cond_16

    .line 332
    .line 333
    if-eq v14, v10, :cond_14

    .line 334
    .line 335
    move/from16 v22, v10

    .line 336
    .line 337
    const/4 v10, 0x2

    .line 338
    if-ne v14, v10, :cond_13

    .line 339
    .line 340
    const/4 v10, 0x5

    .line 341
    const/16 v11, 0x8

    .line 342
    .line 343
    if-ne v4, v10, :cond_b

    .line 344
    .line 345
    const v10, 0x7a120

    .line 346
    .line 347
    .line 348
    :goto_6
    move/from16 v19, v11

    .line 349
    .line 350
    :goto_7
    const/4 v11, -0x1

    .line 351
    goto :goto_8

    .line 352
    :cond_b
    if-ne v4, v11, :cond_c

    .line 353
    .line 354
    const v10, 0xf4240

    .line 355
    .line 356
    .line 357
    goto :goto_6

    .line 358
    :cond_c
    move/from16 v19, v11

    .line 359
    .line 360
    const v10, 0x3d090

    .line 361
    .line 362
    .line 363
    goto :goto_7

    .line 364
    :goto_8
    if-eq v8, v11, :cond_11

    .line 365
    .line 366
    sget-object v11, Ljava/math/RoundingMode;->CEILING:Ljava/math/RoundingMode;

    .line 367
    .line 368
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 369
    .line 370
    .line 371
    div-int/lit8 v16, v8, 0x8

    .line 372
    .line 373
    mul-int v23, v19, v16

    .line 374
    .line 375
    sub-int v23, v8, v23

    .line 376
    .line 377
    if-nez v23, :cond_d

    .line 378
    .line 379
    goto :goto_a

    .line 380
    :cond_d
    xor-int/lit8 v8, v8, 0x8

    .line 381
    .line 382
    shr-int/lit8 v8, v8, 0x1f

    .line 383
    .line 384
    or-int/lit8 v8, v8, 0x1

    .line 385
    .line 386
    sget-object v24, Ljr/c;->a:[I

    .line 387
    .line 388
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 389
    .line 390
    .line 391
    move-result v11

    .line 392
    aget v11, v24, v11

    .line 393
    .line 394
    packed-switch v11, :pswitch_data_0

    .line 395
    .line 396
    .line 397
    new-instance v0, Ljava/lang/AssertionError;

    .line 398
    .line 399
    invoke-direct {v0}, Ljava/lang/AssertionError;-><init>()V

    .line 400
    .line 401
    .line 402
    throw v0

    .line 403
    :pswitch_0
    invoke-static/range {v23 .. v23}, Ljava/lang/Math;->abs(I)I

    .line 404
    .line 405
    .line 406
    move-result v11

    .line 407
    invoke-static/range {v19 .. v19}, Ljava/lang/Math;->abs(I)I

    .line 408
    .line 409
    .line 410
    move-result v19

    .line 411
    sub-int v19, v19, v11

    .line 412
    .line 413
    sub-int v11, v11, v19

    .line 414
    .line 415
    if-nez v11, :cond_e

    .line 416
    .line 417
    sget-object v8, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 418
    .line 419
    sget-object v8, Ljava/math/RoundingMode;->HALF_EVEN:Ljava/math/RoundingMode;

    .line 420
    .line 421
    goto :goto_a

    .line 422
    :cond_e
    if-lez v11, :cond_f

    .line 423
    .line 424
    goto :goto_9

    .line 425
    :pswitch_1
    if-lez v8, :cond_f

    .line 426
    .line 427
    goto :goto_9

    .line 428
    :pswitch_2
    if-gez v8, :cond_f

    .line 429
    .line 430
    :goto_9
    :pswitch_3
    add-int v16, v16, v8

    .line 431
    .line 432
    goto :goto_a

    .line 433
    :pswitch_4
    if-nez v23, :cond_10

    .line 434
    .line 435
    :cond_f
    :goto_a
    :pswitch_5
    move/from16 v8, v16

    .line 436
    .line 437
    goto :goto_c

    .line 438
    :cond_10
    new-instance v0, Ljava/lang/ArithmeticException;

    .line 439
    .line 440
    const-string v1, "mode was UNNECESSARY, but rounding was necessary"

    .line 441
    .line 442
    invoke-direct {v0, v1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    throw v0

    .line 446
    :cond_11
    invoke-static {v4}, Lo8/b;->i(I)I

    .line 447
    .line 448
    .line 449
    move-result v8

    .line 450
    const v11, -0x7fffffff

    .line 451
    .line 452
    .line 453
    if-eq v8, v11, :cond_12

    .line 454
    .line 455
    move/from16 v11, v22

    .line 456
    .line 457
    goto :goto_b

    .line 458
    :cond_12
    const/4 v11, 0x0

    .line 459
    :goto_b
    invoke-static {v11}, Lw7/a;->j(Z)V

    .line 460
    .line 461
    .line 462
    :goto_c
    int-to-long v10, v10

    .line 463
    move/from16 v19, v3

    .line 464
    .line 465
    int-to-long v2, v8

    .line 466
    mul-long/2addr v10, v2

    .line 467
    div-long v10, v10, v20

    .line 468
    .line 469
    invoke-static {v10, v11}, Llp/de;->c(J)I

    .line 470
    .line 471
    .line 472
    move-result v2

    .line 473
    :goto_d
    move/from16 p2, v4

    .line 474
    .line 475
    goto :goto_f

    .line 476
    :cond_13
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 477
    .line 478
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 479
    .line 480
    .line 481
    throw v0

    .line 482
    :cond_14
    move/from16 v19, v3

    .line 483
    .line 484
    move/from16 v22, v10

    .line 485
    .line 486
    invoke-static {v4}, Lo8/b;->i(I)I

    .line 487
    .line 488
    .line 489
    move-result v2

    .line 490
    const v11, -0x7fffffff

    .line 491
    .line 492
    .line 493
    if-eq v2, v11, :cond_15

    .line 494
    .line 495
    move/from16 v3, v22

    .line 496
    .line 497
    goto :goto_e

    .line 498
    :cond_15
    const/4 v3, 0x0

    .line 499
    :goto_e
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 500
    .line 501
    .line 502
    const v3, 0x2faf080

    .line 503
    .line 504
    .line 505
    int-to-long v10, v3

    .line 506
    int-to-long v2, v2

    .line 507
    mul-long/2addr v10, v2

    .line 508
    div-long v10, v10, v20

    .line 509
    .line 510
    invoke-static {v10, v11}, Llp/de;->c(J)I

    .line 511
    .line 512
    .line 513
    move-result v2

    .line 514
    goto :goto_d

    .line 515
    :cond_16
    move/from16 v19, v3

    .line 516
    .line 517
    move/from16 v22, v10

    .line 518
    .line 519
    mul-int/lit8 v2, v1, 0x4

    .line 520
    .line 521
    const v3, 0x3d090

    .line 522
    .line 523
    .line 524
    int-to-long v10, v3

    .line 525
    move/from16 p2, v4

    .line 526
    .line 527
    int-to-long v3, v6

    .line 528
    mul-long/2addr v10, v3

    .line 529
    move-wide/from16 v23, v3

    .line 530
    .line 531
    int-to-long v3, v7

    .line 532
    mul-long/2addr v10, v3

    .line 533
    div-long v10, v10, v20

    .line 534
    .line 535
    invoke-static {v10, v11}, Llp/de;->c(J)I

    .line 536
    .line 537
    .line 538
    move-result v8

    .line 539
    const v10, 0xb71b0

    .line 540
    .line 541
    .line 542
    int-to-long v10, v10

    .line 543
    mul-long v10, v10, v23

    .line 544
    .line 545
    mul-long/2addr v10, v3

    .line 546
    div-long v10, v10, v20

    .line 547
    .line 548
    invoke-static {v10, v11}, Llp/de;->c(J)I

    .line 549
    .line 550
    .line 551
    move-result v3

    .line 552
    invoke-static {v2, v8, v3}, Lw7/w;->g(III)I

    .line 553
    .line 554
    .line 555
    move-result v2

    .line 556
    :goto_f
    int-to-double v2, v2

    .line 557
    mul-double v2, v2, v17

    .line 558
    .line 559
    double-to-int v2, v2

    .line 560
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 561
    .line 562
    .line 563
    move-result v1

    .line 564
    add-int/2addr v1, v7

    .line 565
    add-int/lit8 v1, v1, -0x1

    .line 566
    .line 567
    div-int/2addr v1, v7

    .line 568
    mul-int/2addr v1, v7

    .line 569
    const/4 v2, 0x0

    .line 570
    iput-boolean v2, v0, Lc8/y;->d0:Z

    .line 571
    .line 572
    move v7, v9

    .line 573
    move v9, v1

    .line 574
    new-instance v1, Lc8/t;

    .line 575
    .line 576
    move-object v10, v13

    .line 577
    iget-boolean v13, v0, Lc8/y;->a0:Z

    .line 578
    .line 579
    move-object/from16 v2, p1

    .line 580
    .line 581
    move/from16 v8, p2

    .line 582
    .line 583
    move v4, v14

    .line 584
    move v11, v15

    .line 585
    move/from16 v3, v19

    .line 586
    .line 587
    invoke-direct/range {v1 .. v13}, Lc8/t;-><init>(Lt7/o;IIIIIIILu7/c;ZZZ)V

    .line 588
    .line 589
    .line 590
    invoke-virtual {v0}, Lc8/y;->o()Z

    .line 591
    .line 592
    .line 593
    move-result v2

    .line 594
    if-eqz v2, :cond_17

    .line 595
    .line 596
    iput-object v1, v0, Lc8/y;->t:Lc8/t;

    .line 597
    .line 598
    return-void

    .line 599
    :cond_17
    iput-object v1, v0, Lc8/y;->u:Lc8/t;

    .line 600
    .line 601
    return-void

    .line 602
    :cond_18
    move v4, v14

    .line 603
    new-instance v0, Lc8/k;

    .line 604
    .line 605
    new-instance v1, Ljava/lang/StringBuilder;

    .line 606
    .line 607
    const-string v3, "Invalid output channel config (mode="

    .line 608
    .line 609
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 610
    .line 611
    .line 612
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 613
    .line 614
    .line 615
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 616
    .line 617
    .line 618
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 619
    .line 620
    .line 621
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 622
    .line 623
    .line 624
    move-result-object v1

    .line 625
    invoke-direct {v0, v1, v2}, Lc8/k;-><init>(Ljava/lang/String;Lt7/o;)V

    .line 626
    .line 627
    .line 628
    throw v0

    .line 629
    :cond_19
    move v4, v14

    .line 630
    new-instance v0, Lc8/k;

    .line 631
    .line 632
    new-instance v1, Ljava/lang/StringBuilder;

    .line 633
    .line 634
    const-string v3, "Invalid output encoding (mode="

    .line 635
    .line 636
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 640
    .line 641
    .line 642
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 643
    .line 644
    .line 645
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 646
    .line 647
    .line 648
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 649
    .line 650
    .line 651
    move-result-object v1

    .line 652
    invoke-direct {v0, v1, v2}, Lc8/k;-><init>(Ljava/lang/String;Lt7/o;)V

    .line 653
    .line 654
    .line 655
    throw v0

    .line 656
    :cond_1a
    new-instance v0, Lc8/k;

    .line 657
    .line 658
    new-instance v1, Ljava/lang/StringBuilder;

    .line 659
    .line 660
    const-string v3, "Unable to configure passthrough for: "

    .line 661
    .line 662
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 663
    .line 664
    .line 665
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 666
    .line 667
    .line 668
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 669
    .line 670
    .line 671
    move-result-object v1

    .line 672
    invoke-direct {v0, v1, v2}, Lc8/k;-><init>(Ljava/lang/String;Lt7/o;)V

    .line 673
    .line 674
    .line 675
    throw v0

    .line 676
    nop

    .line 677
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_5
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final e(J)V
    .locals 12

    .line 1
    iget-object v0, p0, Lc8/y;->m:Las/e;

    .line 2
    .line 3
    iget-object v1, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    goto/16 :goto_8

    .line 8
    .line 9
    :cond_0
    iget-object v1, v0, Las/e;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Ljava/lang/Exception;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x1

    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    sget-object v1, Lc8/y;->l0:Ljava/lang/Object;

    .line 19
    .line 20
    monitor-enter v1

    .line 21
    :try_start_0
    sget v4, Lc8/y;->n0:I

    .line 22
    .line 23
    if-lez v4, :cond_2

    .line 24
    .line 25
    move v4, v3

    .line 26
    goto :goto_0

    .line 27
    :cond_2
    move v4, v2

    .line 28
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    if-eqz v4, :cond_3

    .line 30
    .line 31
    goto/16 :goto_8

    .line 32
    .line 33
    :cond_3
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 34
    .line 35
    .line 36
    move-result-wide v4

    .line 37
    iget-wide v6, v0, Las/e;->b:J

    .line 38
    .line 39
    cmp-long v1, v4, v6

    .line 40
    .line 41
    if-gez v1, :cond_4

    .line 42
    .line 43
    goto/16 :goto_8

    .line 44
    .line 45
    :cond_4
    :goto_1
    iget-object v1, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/nio/Buffer;->remaining()I

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    iget-boolean v1, p0, Lc8/y;->a0:Z

    .line 52
    .line 53
    const-wide v10, -0x7fffffffffffffffL    # -4.9E-324

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    if-eqz v1, :cond_7

    .line 59
    .line 60
    cmp-long v1, p1, v10

    .line 61
    .line 62
    if-eqz v1, :cond_5

    .line 63
    .line 64
    move v1, v3

    .line 65
    goto :goto_2

    .line 66
    :cond_5
    move v1, v2

    .line 67
    :goto_2
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 68
    .line 69
    .line 70
    const-wide/high16 v4, -0x8000000000000000L

    .line 71
    .line 72
    cmp-long v1, p1, v4

    .line 73
    .line 74
    if-nez v1, :cond_6

    .line 75
    .line 76
    iget-wide p1, p0, Lc8/y;->b0:J

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_6
    iput-wide p1, p0, Lc8/y;->b0:J

    .line 80
    .line 81
    :goto_3
    iget-object v4, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 82
    .line 83
    iget-object v5, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 84
    .line 85
    const-wide/16 v7, 0x3e8

    .line 86
    .line 87
    mul-long v8, p1, v7

    .line 88
    .line 89
    const/4 v7, 0x1

    .line 90
    invoke-virtual/range {v4 .. v9}, Landroid/media/AudioTrack;->write(Ljava/nio/ByteBuffer;IIJ)I

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    goto :goto_4

    .line 95
    :cond_7
    iget-object p1, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 96
    .line 97
    iget-object p2, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 98
    .line 99
    invoke-virtual {p1, p2, v6, v3}, Landroid/media/AudioTrack;->write(Ljava/nio/ByteBuffer;II)I

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    :goto_4
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 104
    .line 105
    .line 106
    move-result-wide v4

    .line 107
    iput-wide v4, p0, Lc8/y;->c0:J

    .line 108
    .line 109
    const-wide/16 v4, 0x0

    .line 110
    .line 111
    if-gez p1, :cond_f

    .line 112
    .line 113
    const/4 p2, -0x6

    .line 114
    if-eq p1, p2, :cond_8

    .line 115
    .line 116
    const/16 p2, -0x20

    .line 117
    .line 118
    if-ne p1, p2, :cond_b

    .line 119
    .line 120
    :cond_8
    invoke-virtual {p0}, Lc8/y;->k()J

    .line 121
    .line 122
    .line 123
    move-result-wide v6

    .line 124
    cmp-long p2, v6, v4

    .line 125
    .line 126
    if-lez p2, :cond_a

    .line 127
    .line 128
    :cond_9
    :goto_5
    move v2, v3

    .line 129
    goto :goto_6

    .line 130
    :cond_a
    iget-object p2, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 131
    .line 132
    invoke-static {p2}, Lc8/y;->p(Landroid/media/AudioTrack;)Z

    .line 133
    .line 134
    .line 135
    move-result p2

    .line 136
    if-eqz p2, :cond_b

    .line 137
    .line 138
    iget-object p2, p0, Lc8/y;->u:Lc8/t;

    .line 139
    .line 140
    iget p2, p2, Lc8/t;->c:I

    .line 141
    .line 142
    if-ne p2, v3, :cond_9

    .line 143
    .line 144
    iput-boolean v3, p0, Lc8/y;->d0:Z

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_b
    :goto_6
    new-instance p2, Lc8/m;

    .line 148
    .line 149
    iget-object v1, p0, Lc8/y;->u:Lc8/t;

    .line 150
    .line 151
    iget-object v1, v1, Lc8/t;->a:Lt7/o;

    .line 152
    .line 153
    invoke-direct {p2, p1, v1, v2}, Lc8/m;-><init>(ILt7/o;Z)V

    .line 154
    .line 155
    .line 156
    iget-object p1, p0, Lc8/y;->s:Laq/a;

    .line 157
    .line 158
    if-eqz p1, :cond_c

    .line 159
    .line 160
    invoke-virtual {p1, p2}, Laq/a;->B(Ljava/lang/Exception;)V

    .line 161
    .line 162
    .line 163
    :cond_c
    iget-boolean p1, p2, Lc8/m;->e:Z

    .line 164
    .line 165
    if-eqz p1, :cond_e

    .line 166
    .line 167
    iget-object p1, p0, Lc8/y;->a:Landroid/content/Context;

    .line 168
    .line 169
    if-nez p1, :cond_d

    .line 170
    .line 171
    goto :goto_7

    .line 172
    :cond_d
    sget-object p1, Lc8/b;->c:Lc8/b;

    .line 173
    .line 174
    iput-object p1, p0, Lc8/y;->x:Lc8/b;

    .line 175
    .line 176
    iget-object p0, p0, Lc8/y;->y:Lc8/f;

    .line 177
    .line 178
    invoke-virtual {p0, p1}, Lc8/f;->d(Lc8/b;)V

    .line 179
    .line 180
    .line 181
    throw p2

    .line 182
    :cond_e
    :goto_7
    invoke-virtual {v0, p2}, Las/e;->c(Ljava/lang/Exception;)V

    .line 183
    .line 184
    .line 185
    return-void

    .line 186
    :cond_f
    const/4 p2, 0x0

    .line 187
    iput-object p2, v0, Las/e;->c:Ljava/lang/Object;

    .line 188
    .line 189
    iput-wide v10, v0, Las/e;->a:J

    .line 190
    .line 191
    iput-wide v10, v0, Las/e;->b:J

    .line 192
    .line 193
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 194
    .line 195
    invoke-static {v0}, Lc8/y;->p(Landroid/media/AudioTrack;)Z

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    if-eqz v0, :cond_11

    .line 200
    .line 201
    iget-wide v0, p0, Lc8/y;->I:J

    .line 202
    .line 203
    cmp-long v0, v0, v4

    .line 204
    .line 205
    if-lez v0, :cond_10

    .line 206
    .line 207
    iput-boolean v2, p0, Lc8/y;->e0:Z

    .line 208
    .line 209
    :cond_10
    iget-boolean v0, p0, Lc8/y;->U:Z

    .line 210
    .line 211
    if-eqz v0, :cond_11

    .line 212
    .line 213
    iget-object v0, p0, Lc8/y;->s:Laq/a;

    .line 214
    .line 215
    if-eqz v0, :cond_11

    .line 216
    .line 217
    if-ge p1, v6, :cond_11

    .line 218
    .line 219
    iget-boolean v1, p0, Lc8/y;->e0:Z

    .line 220
    .line 221
    if-nez v1, :cond_11

    .line 222
    .line 223
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v0, Lc8/a0;

    .line 226
    .line 227
    iget-object v0, v0, Lf8/s;->J:La8/l0;

    .line 228
    .line 229
    if-eqz v0, :cond_11

    .line 230
    .line 231
    iget-object v0, v0, La8/l0;->a:La8/q0;

    .line 232
    .line 233
    iput-boolean v3, v0, La8/q0;->T:Z

    .line 234
    .line 235
    :cond_11
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 236
    .line 237
    iget v0, v0, Lc8/t;->c:I

    .line 238
    .line 239
    if-nez v0, :cond_12

    .line 240
    .line 241
    iget-wide v4, p0, Lc8/y;->H:J

    .line 242
    .line 243
    int-to-long v7, p1

    .line 244
    add-long/2addr v4, v7

    .line 245
    iput-wide v4, p0, Lc8/y;->H:J

    .line 246
    .line 247
    :cond_12
    if-ne p1, v6, :cond_15

    .line 248
    .line 249
    if-eqz v0, :cond_14

    .line 250
    .line 251
    iget-object p1, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 252
    .line 253
    iget-object v0, p0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 254
    .line 255
    if-ne p1, v0, :cond_13

    .line 256
    .line 257
    move v2, v3

    .line 258
    :cond_13
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 259
    .line 260
    .line 261
    iget-wide v0, p0, Lc8/y;->I:J

    .line 262
    .line 263
    iget p1, p0, Lc8/y;->J:I

    .line 264
    .line 265
    int-to-long v2, p1

    .line 266
    iget p1, p0, Lc8/y;->P:I

    .line 267
    .line 268
    int-to-long v4, p1

    .line 269
    mul-long/2addr v2, v4

    .line 270
    add-long/2addr v2, v0

    .line 271
    iput-wide v2, p0, Lc8/y;->I:J

    .line 272
    .line 273
    :cond_14
    iput-object p2, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 274
    .line 275
    :cond_15
    :goto_8
    return-void

    .line 276
    :catchall_0
    move-exception v0

    .line 277
    move-object p0, v0

    .line 278
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 279
    throw p0
.end method

.method public final f()Z
    .locals 6

    .line 1
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lu7/c;->d()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-wide/high16 v1, -0x8000000000000000L

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0, v1, v2}, Lc8/y;->e(J)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 17
    .line 18
    if-nez p0, :cond_4

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 22
    .line 23
    invoke-virtual {v0}, Lu7/c;->d()Z

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    if-eqz v5, :cond_2

    .line 28
    .line 29
    iget-boolean v5, v0, Lu7/c;->d:Z

    .line 30
    .line 31
    if-eqz v5, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    iput-boolean v4, v0, Lu7/c;->d:Z

    .line 35
    .line 36
    iget-object v0, v0, Lu7/c;->b:Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Lu7/f;

    .line 43
    .line 44
    invoke-interface {v0}, Lu7/f;->e()V

    .line 45
    .line 46
    .line 47
    :cond_2
    :goto_0
    invoke-virtual {p0, v1, v2}, Lc8/y;->t(J)V

    .line 48
    .line 49
    .line 50
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 51
    .line 52
    invoke-virtual {v0}, Lu7/c;->c()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_4

    .line 57
    .line 58
    iget-object p0, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 59
    .line 60
    if-eqz p0, :cond_3

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-nez p0, :cond_4

    .line 67
    .line 68
    :cond_3
    :goto_1
    return v4

    .line 69
    :cond_4
    return v3
.end method

.method public final g()V
    .locals 11

    .line 1
    invoke-virtual {p0}, Lc8/y;->o()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v0, :cond_5

    .line 9
    .line 10
    iput-wide v1, p0, Lc8/y;->F:J

    .line 11
    .line 12
    iput-wide v1, p0, Lc8/y;->G:J

    .line 13
    .line 14
    iput-wide v1, p0, Lc8/y;->H:J

    .line 15
    .line 16
    iput-wide v1, p0, Lc8/y;->I:J

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput-boolean v0, p0, Lc8/y;->e0:Z

    .line 20
    .line 21
    iput v0, p0, Lc8/y;->J:I

    .line 22
    .line 23
    new-instance v4, Lc8/u;

    .line 24
    .line 25
    iget-object v5, p0, Lc8/y;->D:Lt7/g0;

    .line 26
    .line 27
    const-wide/16 v6, 0x0

    .line 28
    .line 29
    const-wide/16 v8, 0x0

    .line 30
    .line 31
    invoke-direct/range {v4 .. v9}, Lc8/u;-><init>(Lt7/g0;JJ)V

    .line 32
    .line 33
    .line 34
    iput-object v4, p0, Lc8/y;->C:Lc8/u;

    .line 35
    .line 36
    iput-wide v1, p0, Lc8/y;->M:J

    .line 37
    .line 38
    iput-object v3, p0, Lc8/y;->B:Lc8/u;

    .line 39
    .line 40
    iget-object v4, p0, Lc8/y;->i:Ljava/util/ArrayDeque;

    .line 41
    .line 42
    invoke-virtual {v4}, Ljava/util/ArrayDeque;->clear()V

    .line 43
    .line 44
    .line 45
    iput-object v3, p0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 46
    .line 47
    iput v0, p0, Lc8/y;->P:I

    .line 48
    .line 49
    iput-object v3, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 50
    .line 51
    iput-boolean v0, p0, Lc8/y;->S:Z

    .line 52
    .line 53
    iput-boolean v0, p0, Lc8/y;->R:Z

    .line 54
    .line 55
    iput-boolean v0, p0, Lc8/y;->T:Z

    .line 56
    .line 57
    iget-object v0, p0, Lc8/y;->d:Lc8/e0;

    .line 58
    .line 59
    iput-wide v1, v0, Lc8/e0;->o:J

    .line 60
    .line 61
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 62
    .line 63
    iget-object v0, v0, Lc8/t;->i:Lu7/c;

    .line 64
    .line 65
    iput-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 66
    .line 67
    invoke-virtual {v0}, Lu7/c;->a()V

    .line 68
    .line 69
    .line 70
    iget-object v0, p0, Lc8/y;->h:Lc8/p;

    .line 71
    .line 72
    iget-object v0, v0, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Landroid/media/AudioTrack;->getPlayState()I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    const/4 v4, 0x3

    .line 82
    if-ne v0, v4, :cond_0

    .line 83
    .line 84
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 85
    .line 86
    invoke-virtual {v0}, Landroid/media/AudioTrack;->pause()V

    .line 87
    .line 88
    .line 89
    :cond_0
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 90
    .line 91
    invoke-static {v0}, Lc8/y;->p(Landroid/media/AudioTrack;)Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_1

    .line 96
    .line 97
    iget-object v0, p0, Lc8/y;->k:Lgw0/c;

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    iget-object v4, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 103
    .line 104
    iget-object v5, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v5, Lc8/x;

    .line 107
    .line 108
    invoke-virtual {v4, v5}, Landroid/media/AudioTrack;->unregisterStreamEventCallback(Landroid/media/AudioTrack$StreamEventCallback;)V

    .line 109
    .line 110
    .line 111
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Landroid/os/Handler;

    .line 114
    .line 115
    invoke-virtual {v0, v3}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_1
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 119
    .line 120
    invoke-virtual {v0}, Lc8/t;->a()Lc8/j;

    .line 121
    .line 122
    .line 123
    move-result-object v8

    .line 124
    iget-object v0, p0, Lc8/y;->t:Lc8/t;

    .line 125
    .line 126
    if-eqz v0, :cond_2

    .line 127
    .line 128
    iput-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 129
    .line 130
    iput-object v3, p0, Lc8/y;->t:Lc8/t;

    .line 131
    .line 132
    :cond_2
    iget-object v0, p0, Lc8/y;->h:Lc8/p;

    .line 133
    .line 134
    invoke-virtual {v0}, Lc8/p;->f()V

    .line 135
    .line 136
    .line 137
    iput-object v3, v0, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 138
    .line 139
    iput-object v3, v0, Lc8/p;->e:Lc8/o;

    .line 140
    .line 141
    iget-object v0, p0, Lc8/y;->z:Lgw0/c;

    .line 142
    .line 143
    if-eqz v0, :cond_3

    .line 144
    .line 145
    iget-object v4, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v4, Landroid/media/AudioTrack;

    .line 148
    .line 149
    iget-object v5, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v5, Lc8/v;

    .line 152
    .line 153
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v4, v5}, Landroid/media/AudioTrack;->removeOnRoutingChangedListener(Landroid/media/AudioRouting$OnRoutingChangedListener;)V

    .line 157
    .line 158
    .line 159
    iput-object v3, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 160
    .line 161
    iput-object v3, p0, Lc8/y;->z:Lgw0/c;

    .line 162
    .line 163
    :cond_3
    iget-object v5, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 164
    .line 165
    iget-object v6, p0, Lc8/y;->s:Laq/a;

    .line 166
    .line 167
    new-instance v7, Landroid/os/Handler;

    .line 168
    .line 169
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    invoke-direct {v7, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 174
    .line 175
    .line 176
    sget-object v10, Lc8/y;->l0:Ljava/lang/Object;

    .line 177
    .line 178
    monitor-enter v10

    .line 179
    :try_start_0
    sget-object v0, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 180
    .line 181
    if-nez v0, :cond_4

    .line 182
    .line 183
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 184
    .line 185
    new-instance v0, Lw7/v;

    .line 186
    .line 187
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 188
    .line 189
    .line 190
    invoke-static {v0}, Ljava/util/concurrent/Executors;->newSingleThreadScheduledExecutor(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ScheduledExecutorService;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    sput-object v0, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 195
    .line 196
    goto :goto_0

    .line 197
    :catchall_0
    move-exception v0

    .line 198
    move-object p0, v0

    .line 199
    goto :goto_1

    .line 200
    :cond_4
    :goto_0
    sget v0, Lc8/y;->n0:I

    .line 201
    .line 202
    add-int/lit8 v0, v0, 0x1

    .line 203
    .line 204
    sput v0, Lc8/y;->n0:I

    .line 205
    .line 206
    sget-object v0, Lc8/y;->m0:Ljava/util/concurrent/ScheduledExecutorService;

    .line 207
    .line 208
    new-instance v4, Lc8/r;

    .line 209
    .line 210
    const/4 v9, 0x0

    .line 211
    invoke-direct/range {v4 .. v9}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 212
    .line 213
    .line 214
    sget-object v5, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 215
    .line 216
    const-wide/16 v6, 0x14

    .line 217
    .line 218
    invoke-interface {v0, v4, v6, v7, v5}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 219
    .line 220
    .line 221
    monitor-exit v10
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 222
    iput-object v3, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 223
    .line 224
    goto :goto_2

    .line 225
    :goto_1
    :try_start_1
    monitor-exit v10
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 226
    throw p0

    .line 227
    :cond_5
    :goto_2
    iget-object v0, p0, Lc8/y;->m:Las/e;

    .line 228
    .line 229
    iput-object v3, v0, Las/e;->c:Ljava/lang/Object;

    .line 230
    .line 231
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 232
    .line 233
    .line 234
    .line 235
    .line 236
    iput-wide v4, v0, Las/e;->a:J

    .line 237
    .line 238
    iput-wide v4, v0, Las/e;->b:J

    .line 239
    .line 240
    iget-object v0, p0, Lc8/y;->l:Las/e;

    .line 241
    .line 242
    iput-object v3, v0, Las/e;->c:Ljava/lang/Object;

    .line 243
    .line 244
    iput-wide v4, v0, Las/e;->a:J

    .line 245
    .line 246
    iput-wide v4, v0, Las/e;->b:J

    .line 247
    .line 248
    iput-wide v1, p0, Lc8/y;->g0:J

    .line 249
    .line 250
    iput-wide v1, p0, Lc8/y;->h0:J

    .line 251
    .line 252
    iget-object p0, p0, Lc8/y;->i0:Landroid/os/Handler;

    .line 253
    .line 254
    if-eqz p0, :cond_6

    .line 255
    .line 256
    invoke-virtual {p0, v3}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    :cond_6
    return-void
.end method

.method public final h(Lt7/o;)Lc8/h;
    .locals 7

    .line 1
    iget-boolean v0, p0, Lc8/y;->d0:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    iget-object v0, p0, Lc8/y;->A:Lt7/c;

    .line 9
    .line 10
    iget-object p0, p0, Lc8/y;->o:Lc2/k;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 22
    .line 23
    iget v2, p1, Lt7/o;->G:I

    .line 24
    .line 25
    const/4 v3, -0x1

    .line 26
    if-ne v2, v3, :cond_1

    .line 27
    .line 28
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    iget-object v3, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v3, Landroid/content/Context;

    .line 34
    .line 35
    iget-object v4, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v4, Ljava/lang/Boolean;

    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v6, 0x1

    .line 41
    if-eqz v4, :cond_2

    .line 42
    .line 43
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    if-eqz v3, :cond_4

    .line 49
    .line 50
    invoke-static {v3}, Lu7/b;->a(Landroid/content/Context;)Landroid/media/AudioManager;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    const-string v4, "offloadVariableRateSupported"

    .line 55
    .line 56
    invoke-virtual {v3, v4}, Landroid/media/AudioManager;->getParameters(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    if-eqz v3, :cond_3

    .line 61
    .line 62
    const-string v4, "offloadVariableRateSupported=1"

    .line 63
    .line 64
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-eqz v3, :cond_3

    .line 69
    .line 70
    move v3, v6

    .line 71
    goto :goto_0

    .line 72
    :cond_3
    move v3, v5

    .line 73
    :goto_0
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    iput-object v3, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_4
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 81
    .line 82
    iput-object v3, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 83
    .line 84
    :goto_1
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p0, Ljava/lang/Boolean;

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    :goto_2
    iget-object v3, p1, Lt7/o;->n:Ljava/lang/String;

    .line 93
    .line 94
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    iget-object v4, p1, Lt7/o;->k:Ljava/lang/String;

    .line 98
    .line 99
    invoke-static {v3, v4}, Lt7/d0;->c(Ljava/lang/String;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-eqz v3, :cond_b

    .line 104
    .line 105
    invoke-static {v3}, Lw7/w;->l(I)I

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-ge v1, v4, :cond_5

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    iget p1, p1, Lt7/o;->F:I

    .line 113
    .line 114
    invoke-static {p1}, Lw7/w;->m(I)I

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-nez p1, :cond_6

    .line 119
    .line 120
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 121
    .line 122
    return-object p0

    .line 123
    :cond_6
    :try_start_0
    new-instance v4, Landroid/media/AudioFormat$Builder;

    .line 124
    .line 125
    invoke-direct {v4}, Landroid/media/AudioFormat$Builder;-><init>()V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v4, v2}, Landroid/media/AudioFormat$Builder;->setSampleRate(I)Landroid/media/AudioFormat$Builder;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    invoke-virtual {v2, p1}, Landroid/media/AudioFormat$Builder;->setChannelMask(I)Landroid/media/AudioFormat$Builder;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    invoke-virtual {p1, v3}, Landroid/media/AudioFormat$Builder;->setEncoding(I)Landroid/media/AudioFormat$Builder;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-virtual {p1}, Landroid/media/AudioFormat$Builder;->build()Landroid/media/AudioFormat;

    .line 141
    .line 142
    .line 143
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 144
    const/16 v2, 0x1f

    .line 145
    .line 146
    if-lt v1, v2, :cond_9

    .line 147
    .line 148
    invoke-virtual {v0}, Lt7/c;->a()Lpv/g;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Landroid/media/AudioAttributes;

    .line 155
    .line 156
    invoke-static {p1, v0}, Lc4/a;->b(Landroid/media/AudioFormat;Landroid/media/AudioAttributes;)I

    .line 157
    .line 158
    .line 159
    move-result p1

    .line 160
    if-nez p1, :cond_7

    .line 161
    .line 162
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 163
    .line 164
    return-object p0

    .line 165
    :cond_7
    new-instance v0, Lc8/g;

    .line 166
    .line 167
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 168
    .line 169
    .line 170
    const/16 v2, 0x20

    .line 171
    .line 172
    if-le v1, v2, :cond_8

    .line 173
    .line 174
    const/4 v1, 0x2

    .line 175
    if-ne p1, v1, :cond_8

    .line 176
    .line 177
    move v5, v6

    .line 178
    :cond_8
    iput-boolean v6, v0, Lc8/g;->a:Z

    .line 179
    .line 180
    iput-boolean v5, v0, Lc8/g;->b:Z

    .line 181
    .line 182
    iput-boolean p0, v0, Lc8/g;->c:Z

    .line 183
    .line 184
    invoke-virtual {v0}, Lc8/g;->a()Lc8/h;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    return-object p0

    .line 189
    :cond_9
    invoke-virtual {v0}, Lt7/c;->a()Lpv/g;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v0, Landroid/media/AudioAttributes;

    .line 196
    .line 197
    invoke-static {p1, v0}, Landroid/media/AudioManager;->isOffloadedPlaybackSupported(Landroid/media/AudioFormat;Landroid/media/AudioAttributes;)Z

    .line 198
    .line 199
    .line 200
    move-result p1

    .line 201
    if-nez p1, :cond_a

    .line 202
    .line 203
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 204
    .line 205
    return-object p0

    .line 206
    :cond_a
    new-instance p1, Lc8/g;

    .line 207
    .line 208
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 209
    .line 210
    .line 211
    iput-boolean v6, p1, Lc8/g;->a:Z

    .line 212
    .line 213
    iput-boolean p0, p1, Lc8/g;->c:Z

    .line 214
    .line 215
    invoke-virtual {p1}, Lc8/g;->a()Lc8/h;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    return-object p0

    .line 220
    :catch_0
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 221
    .line 222
    return-object p0

    .line 223
    :cond_b
    :goto_3
    sget-object p0, Lc8/h;->d:Lc8/h;

    .line 224
    .line 225
    return-object p0
.end method

.method public final i(Lt7/o;)I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lc8/y;->q()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lt7/o;->n:Ljava/lang/String;

    .line 5
    .line 6
    iget v1, p1, Lt7/o;->H:I

    .line 7
    .line 8
    const-string v2, "audio/raw"

    .line 9
    .line 10
    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x2

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-static {v1}, Lw7/w;->A(I)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-nez p0, :cond_0

    .line 23
    .line 24
    const-string p0, "DefaultAudioSink"

    .line 25
    .line 26
    const-string p1, "Invalid PCM encoding: "

    .line 27
    .line 28
    invoke-static {p1, v1, p0}, Lvj/b;->w(Ljava/lang/String;ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return v2

    .line 32
    :cond_0
    if-eq v1, v3, :cond_2

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    return p0

    .line 36
    :cond_1
    iget-object v0, p0, Lc8/y;->x:Lc8/b;

    .line 37
    .line 38
    iget-object p0, p0, Lc8/y;->A:Lt7/c;

    .line 39
    .line 40
    invoke-virtual {v0, p1, p0}, Lc8/b;->d(Lt7/o;Lt7/c;)Landroid/util/Pair;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-eqz p0, :cond_3

    .line 45
    .line 46
    :cond_2
    return v3

    .line 47
    :cond_3
    return v2
.end method

.method public final j()J
    .locals 5

    .line 1
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 2
    .line 3
    iget v1, v0, Lc8/t;->c:I

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-wide v1, p0, Lc8/y;->F:J

    .line 8
    .line 9
    iget p0, v0, Lc8/t;->b:I

    .line 10
    .line 11
    int-to-long v3, p0

    .line 12
    div-long/2addr v1, v3

    .line 13
    return-wide v1

    .line 14
    :cond_0
    iget-wide v0, p0, Lc8/y;->G:J

    .line 15
    .line 16
    return-wide v0
.end method

.method public final k()J
    .locals 7

    .line 1
    iget-object v0, p0, Lc8/y;->u:Lc8/t;

    .line 2
    .line 3
    iget v1, v0, Lc8/t;->c:I

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-wide v1, p0, Lc8/y;->H:J

    .line 8
    .line 9
    iget p0, v0, Lc8/t;->d:I

    .line 10
    .line 11
    int-to-long v3, p0

    .line 12
    sget-object p0, Lw7/w;->a:Ljava/lang/String;

    .line 13
    .line 14
    add-long/2addr v1, v3

    .line 15
    const-wide/16 v5, 0x1

    .line 16
    .line 17
    sub-long/2addr v1, v5

    .line 18
    div-long/2addr v1, v3

    .line 19
    return-wide v1

    .line 20
    :cond_0
    iget-wide v0, p0, Lc8/y;->I:J

    .line 21
    .line 22
    return-wide v0
.end method

.method public final l(JLjava/nio/ByteBuffer;I)Z
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    move/from16 v4, p4

    .line 8
    .line 9
    iget-object v5, v0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 10
    .line 11
    const/4 v6, 0x1

    .line 12
    const/4 v7, 0x0

    .line 13
    if-eqz v5, :cond_1

    .line 14
    .line 15
    if-ne v3, v5, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v5, v7

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    :goto_0
    move v5, v6

    .line 21
    :goto_1
    invoke-static {v5}, Lw7/a;->c(Z)V

    .line 22
    .line 23
    .line 24
    iget-object v5, v0, Lc8/y;->t:Lc8/t;

    .line 25
    .line 26
    const/4 v8, 0x3

    .line 27
    iget-object v9, v0, Lc8/y;->h:Lc8/p;

    .line 28
    .line 29
    const/4 v10, 0x0

    .line 30
    if-eqz v5, :cond_7

    .line 31
    .line 32
    invoke-virtual {v0}, Lc8/y;->f()Z

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    if-nez v5, :cond_2

    .line 37
    .line 38
    :goto_2
    move/from16 v19, v7

    .line 39
    .line 40
    goto/16 :goto_1e

    .line 41
    .line 42
    :cond_2
    iget-object v5, v0, Lc8/y;->t:Lc8/t;

    .line 43
    .line 44
    iget-object v11, v0, Lc8/y;->u:Lc8/t;

    .line 45
    .line 46
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget v12, v11, Lc8/t;->c:I

    .line 50
    .line 51
    iget v13, v5, Lc8/t;->c:I

    .line 52
    .line 53
    if-ne v12, v13, :cond_4

    .line 54
    .line 55
    iget v12, v11, Lc8/t;->g:I

    .line 56
    .line 57
    iget v13, v5, Lc8/t;->g:I

    .line 58
    .line 59
    if-ne v12, v13, :cond_4

    .line 60
    .line 61
    iget v12, v11, Lc8/t;->e:I

    .line 62
    .line 63
    iget v13, v5, Lc8/t;->e:I

    .line 64
    .line 65
    if-ne v12, v13, :cond_4

    .line 66
    .line 67
    iget v12, v11, Lc8/t;->f:I

    .line 68
    .line 69
    iget v13, v5, Lc8/t;->f:I

    .line 70
    .line 71
    if-ne v12, v13, :cond_4

    .line 72
    .line 73
    iget v12, v11, Lc8/t;->d:I

    .line 74
    .line 75
    iget v13, v5, Lc8/t;->d:I

    .line 76
    .line 77
    if-ne v12, v13, :cond_4

    .line 78
    .line 79
    iget-boolean v12, v11, Lc8/t;->j:Z

    .line 80
    .line 81
    iget-boolean v13, v5, Lc8/t;->j:Z

    .line 82
    .line 83
    if-ne v12, v13, :cond_4

    .line 84
    .line 85
    iget-boolean v11, v11, Lc8/t;->k:Z

    .line 86
    .line 87
    iget-boolean v5, v5, Lc8/t;->k:Z

    .line 88
    .line 89
    if-ne v11, v5, :cond_4

    .line 90
    .line 91
    iget-object v5, v0, Lc8/y;->t:Lc8/t;

    .line 92
    .line 93
    iput-object v5, v0, Lc8/y;->u:Lc8/t;

    .line 94
    .line 95
    iput-object v10, v0, Lc8/y;->t:Lc8/t;

    .line 96
    .line 97
    iget-object v5, v0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 98
    .line 99
    if-eqz v5, :cond_6

    .line 100
    .line 101
    invoke-virtual {v5}, Landroid/media/AudioTrack;->isOffloadedPlayback()Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-eqz v5, :cond_6

    .line 106
    .line 107
    iget-object v5, v0, Lc8/y;->u:Lc8/t;

    .line 108
    .line 109
    iget-boolean v5, v5, Lc8/t;->k:Z

    .line 110
    .line 111
    if-eqz v5, :cond_6

    .line 112
    .line 113
    iget-object v5, v0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 114
    .line 115
    invoke-virtual {v5}, Landroid/media/AudioTrack;->getPlayState()I

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    if-ne v5, v8, :cond_3

    .line 120
    .line 121
    iget-object v5, v0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 122
    .line 123
    invoke-virtual {v5}, Landroid/media/AudioTrack;->setOffloadEndOfStream()V

    .line 124
    .line 125
    .line 126
    iput-boolean v6, v9, Lc8/p;->D:Z

    .line 127
    .line 128
    iget-object v5, v9, Lc8/p;->e:Lc8/o;

    .line 129
    .line 130
    if-eqz v5, :cond_3

    .line 131
    .line 132
    iget-object v5, v5, Lc8/o;->a:Lc8/n;

    .line 133
    .line 134
    iput-boolean v6, v5, Lc8/n;->f:Z

    .line 135
    .line 136
    :cond_3
    iget-object v5, v0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 137
    .line 138
    iget-object v11, v0, Lc8/y;->u:Lc8/t;

    .line 139
    .line 140
    iget-object v11, v11, Lc8/t;->a:Lt7/o;

    .line 141
    .line 142
    iget v12, v11, Lt7/o;->I:I

    .line 143
    .line 144
    iget v11, v11, Lt7/o;->J:I

    .line 145
    .line 146
    invoke-virtual {v5, v12, v11}, Landroid/media/AudioTrack;->setOffloadDelayPadding(II)V

    .line 147
    .line 148
    .line 149
    iput-boolean v6, v0, Lc8/y;->e0:Z

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_4
    invoke-virtual {v0}, Lc8/y;->s()V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v0}, Lc8/y;->m()Z

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-eqz v5, :cond_5

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_5
    invoke-virtual {v0}, Lc8/y;->g()V

    .line 163
    .line 164
    .line 165
    :cond_6
    :goto_3
    invoke-virtual/range {p0 .. p2}, Lc8/y;->a(J)V

    .line 166
    .line 167
    .line 168
    :cond_7
    invoke-virtual {v0}, Lc8/y;->o()Z

    .line 169
    .line 170
    .line 171
    move-result v5

    .line 172
    iget-object v11, v0, Lc8/y;->l:Las/e;

    .line 173
    .line 174
    if-nez v5, :cond_9

    .line 175
    .line 176
    :try_start_0
    invoke-virtual {v0}, Lc8/y;->n()Z

    .line 177
    .line 178
    .line 179
    move-result v5
    :try_end_0
    .catch Lc8/l; {:try_start_0 .. :try_end_0} :catch_0

    .line 180
    if-nez v5, :cond_9

    .line 181
    .line 182
    goto/16 :goto_2

    .line 183
    .line 184
    :catch_0
    move-exception v0

    .line 185
    iget-boolean v1, v0, Lc8/l;->e:Z

    .line 186
    .line 187
    if-nez v1, :cond_8

    .line 188
    .line 189
    invoke-virtual {v11, v0}, Las/e;->c(Ljava/lang/Exception;)V

    .line 190
    .line 191
    .line 192
    return v7

    .line 193
    :cond_8
    throw v0

    .line 194
    :cond_9
    iput-object v10, v11, Las/e;->c:Ljava/lang/Object;

    .line 195
    .line 196
    const-wide v12, -0x7fffffffffffffffL    # -4.9E-324

    .line 197
    .line 198
    .line 199
    .line 200
    .line 201
    iput-wide v12, v11, Las/e;->a:J

    .line 202
    .line 203
    iput-wide v12, v11, Las/e;->b:J

    .line 204
    .line 205
    iget-boolean v5, v0, Lc8/y;->L:Z

    .line 206
    .line 207
    const-wide/16 v14, 0x0

    .line 208
    .line 209
    move-wide/from16 v16, v12

    .line 210
    .line 211
    if-eqz v5, :cond_b

    .line 212
    .line 213
    invoke-static {v14, v15, v1, v2}, Ljava/lang/Math;->max(JJ)J

    .line 214
    .line 215
    .line 216
    move-result-wide v12

    .line 217
    iput-wide v12, v0, Lc8/y;->M:J

    .line 218
    .line 219
    iput-boolean v7, v0, Lc8/y;->K:Z

    .line 220
    .line 221
    iput-boolean v7, v0, Lc8/y;->L:Z

    .line 222
    .line 223
    iget-object v5, v0, Lc8/y;->u:Lc8/t;

    .line 224
    .line 225
    if-eqz v5, :cond_a

    .line 226
    .line 227
    iget-boolean v5, v5, Lc8/t;->j:Z

    .line 228
    .line 229
    if-eqz v5, :cond_a

    .line 230
    .line 231
    invoke-virtual {v0}, Lc8/y;->v()V

    .line 232
    .line 233
    .line 234
    :cond_a
    invoke-virtual/range {p0 .. p2}, Lc8/y;->a(J)V

    .line 235
    .line 236
    .line 237
    iget-boolean v5, v0, Lc8/y;->U:Z

    .line 238
    .line 239
    if-eqz v5, :cond_b

    .line 240
    .line 241
    invoke-virtual {v0}, Lc8/y;->r()V

    .line 242
    .line 243
    .line 244
    :cond_b
    invoke-virtual {v0}, Lc8/y;->k()J

    .line 245
    .line 246
    .line 247
    iget-object v5, v9, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 248
    .line 249
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 250
    .line 251
    .line 252
    invoke-virtual {v5}, Landroid/media/AudioTrack;->getPlayState()I

    .line 253
    .line 254
    .line 255
    iget-object v5, v9, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 256
    .line 257
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 258
    .line 259
    .line 260
    invoke-virtual {v5}, Landroid/media/AudioTrack;->getUnderrunCount()I

    .line 261
    .line 262
    .line 263
    move-result v5

    .line 264
    iget v11, v9, Lc8/p;->k:I

    .line 265
    .line 266
    if-le v5, v11, :cond_c

    .line 267
    .line 268
    move v11, v6

    .line 269
    goto :goto_4

    .line 270
    :cond_c
    move v11, v7

    .line 271
    :goto_4
    iput v5, v9, Lc8/p;->k:I

    .line 272
    .line 273
    if-eqz v11, :cond_d

    .line 274
    .line 275
    iget-object v5, v9, Lc8/p;->a:Lbu/c;

    .line 276
    .line 277
    iget v11, v9, Lc8/p;->d:I

    .line 278
    .line 279
    iget-wide v12, v9, Lc8/p;->g:J

    .line 280
    .line 281
    invoke-static {v12, v13}, Lw7/w;->N(J)J

    .line 282
    .line 283
    .line 284
    move-result-wide v21

    .line 285
    iget-object v5, v5, Lbu/c;->e:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v5, Lc8/y;

    .line 288
    .line 289
    iget-object v12, v5, Lc8/y;->s:Laq/a;

    .line 290
    .line 291
    if-eqz v12, :cond_d

    .line 292
    .line 293
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 294
    .line 295
    .line 296
    move-result-wide v12

    .line 297
    move-wide/from16 v25, v14

    .line 298
    .line 299
    iget-wide v14, v5, Lc8/y;->c0:J

    .line 300
    .line 301
    sub-long v23, v12, v14

    .line 302
    .line 303
    iget-object v5, v5, Lc8/y;->s:Laq/a;

    .line 304
    .line 305
    iget-object v5, v5, Laq/a;->e:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v5, Lc8/a0;

    .line 308
    .line 309
    iget-object v5, v5, Lc8/a0;->Q1:Lb81/d;

    .line 310
    .line 311
    iget-object v12, v5, Lb81/d;->e:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v12, Landroid/os/Handler;

    .line 314
    .line 315
    if-eqz v12, :cond_e

    .line 316
    .line 317
    new-instance v18, Lc8/i;

    .line 318
    .line 319
    move-object/from16 v19, v5

    .line 320
    .line 321
    move/from16 v20, v11

    .line 322
    .line 323
    invoke-direct/range {v18 .. v24}, Lc8/i;-><init>(Lb81/d;IJJ)V

    .line 324
    .line 325
    .line 326
    move-object/from16 v5, v18

    .line 327
    .line 328
    invoke-virtual {v12, v5}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 329
    .line 330
    .line 331
    goto :goto_5

    .line 332
    :cond_d
    move-wide/from16 v25, v14

    .line 333
    .line 334
    :cond_e
    :goto_5
    iget-object v5, v0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 335
    .line 336
    if-nez v5, :cond_38

    .line 337
    .line 338
    invoke-virtual {v3}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 339
    .line 340
    .line 341
    move-result-object v5

    .line 342
    sget-object v11, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 343
    .line 344
    if-ne v5, v11, :cond_f

    .line 345
    .line 346
    move v5, v6

    .line 347
    goto :goto_6

    .line 348
    :cond_f
    move v5, v7

    .line 349
    :goto_6
    invoke-static {v5}, Lw7/a;->c(Z)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v3}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 353
    .line 354
    .line 355
    move-result v5

    .line 356
    if-nez v5, :cond_10

    .line 357
    .line 358
    goto/16 :goto_1b

    .line 359
    .line 360
    :cond_10
    iget-object v5, v0, Lc8/y;->u:Lc8/t;

    .line 361
    .line 362
    iget v11, v5, Lc8/t;->c:I

    .line 363
    .line 364
    if-eqz v11, :cond_2f

    .line 365
    .line 366
    iget v11, v0, Lc8/y;->J:I

    .line 367
    .line 368
    if-nez v11, :cond_2f

    .line 369
    .line 370
    iget v5, v5, Lc8/t;->g:I

    .line 371
    .line 372
    const/16 v11, 0x14

    .line 373
    .line 374
    const/4 v12, 0x2

    .line 375
    const/4 v13, 0x5

    .line 376
    if-eq v5, v11, :cond_2a

    .line 377
    .line 378
    const/16 v11, 0x1e

    .line 379
    .line 380
    const/4 v14, -0x2

    .line 381
    const/4 v15, -0x1

    .line 382
    if-eq v5, v11, :cond_22

    .line 383
    .line 384
    const/16 v11, 0xa

    .line 385
    .line 386
    packed-switch v5, :pswitch_data_0

    .line 387
    .line 388
    .line 389
    const/16 v12, 0x10

    .line 390
    .line 391
    packed-switch v5, :pswitch_data_1

    .line 392
    .line 393
    .line 394
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 395
    .line 396
    const-string v1, "Unexpected audio encoding: "

    .line 397
    .line 398
    invoke-static {v5, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    throw v0

    .line 406
    :pswitch_0
    new-array v5, v12, [B

    .line 407
    .line 408
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 409
    .line 410
    .line 411
    move-result v8

    .line 412
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 413
    .line 414
    .line 415
    invoke-virtual {v3, v8}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 416
    .line 417
    .line 418
    new-instance v8, Lm9/f;

    .line 419
    .line 420
    invoke-direct {v8, v12, v5}, Lm9/f;-><init>(I[B)V

    .line 421
    .line 422
    .line 423
    invoke-static {v8}, Lo8/b;->m(Lm9/f;)Lm8/j;

    .line 424
    .line 425
    .line 426
    move-result-object v5

    .line 427
    iget v15, v5, Lm8/j;->c:I

    .line 428
    .line 429
    goto/16 :goto_1a

    .line 430
    .line 431
    :cond_11
    :goto_7
    :pswitch_1
    const/16 v15, 0x400

    .line 432
    .line 433
    goto/16 :goto_1a

    .line 434
    .line 435
    :pswitch_2
    const/16 v15, 0x200

    .line 436
    .line 437
    goto/16 :goto_1a

    .line 438
    .line 439
    :pswitch_3
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 440
    .line 441
    .line 442
    move-result v5

    .line 443
    invoke-virtual {v3}, Ljava/nio/Buffer;->limit()I

    .line 444
    .line 445
    .line 446
    move-result v8

    .line 447
    sub-int/2addr v8, v11

    .line 448
    move v11, v5

    .line 449
    :goto_8
    if-gt v11, v8, :cond_14

    .line 450
    .line 451
    add-int/lit8 v13, v11, 0x4

    .line 452
    .line 453
    sget-object v18, Lw7/w;->a:Ljava/lang/String;

    .line 454
    .line 455
    invoke-virtual {v3, v13}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 456
    .line 457
    .line 458
    move-result v13

    .line 459
    move/from16 v19, v12

    .line 460
    .line 461
    invoke-virtual {v3}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 462
    .line 463
    .line 464
    move-result-object v12

    .line 465
    sget-object v10, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 466
    .line 467
    if-ne v12, v10, :cond_12

    .line 468
    .line 469
    goto :goto_9

    .line 470
    :cond_12
    invoke-static {v13}, Ljava/lang/Integer;->reverseBytes(I)I

    .line 471
    .line 472
    .line 473
    move-result v13

    .line 474
    :goto_9
    and-int/lit8 v10, v13, -0x2

    .line 475
    .line 476
    const v12, -0x78d9046

    .line 477
    .line 478
    .line 479
    if-ne v10, v12, :cond_13

    .line 480
    .line 481
    sub-int/2addr v11, v5

    .line 482
    goto :goto_a

    .line 483
    :cond_13
    add-int/lit8 v11, v11, 0x1

    .line 484
    .line 485
    move/from16 v12, v19

    .line 486
    .line 487
    const/4 v10, 0x0

    .line 488
    goto :goto_8

    .line 489
    :cond_14
    move/from16 v19, v12

    .line 490
    .line 491
    move v11, v15

    .line 492
    :goto_a
    if-ne v11, v15, :cond_15

    .line 493
    .line 494
    move v15, v7

    .line 495
    goto/16 :goto_1a

    .line 496
    .line 497
    :cond_15
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 498
    .line 499
    .line 500
    move-result v5

    .line 501
    add-int/2addr v5, v11

    .line 502
    add-int/lit8 v5, v5, 0x7

    .line 503
    .line 504
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 505
    .line 506
    .line 507
    move-result v5

    .line 508
    and-int/lit16 v5, v5, 0xff

    .line 509
    .line 510
    const/16 v8, 0xbb

    .line 511
    .line 512
    if-ne v5, v8, :cond_16

    .line 513
    .line 514
    move v5, v6

    .line 515
    goto :goto_b

    .line 516
    :cond_16
    move v5, v7

    .line 517
    :goto_b
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 518
    .line 519
    .line 520
    move-result v8

    .line 521
    add-int/2addr v8, v11

    .line 522
    if-eqz v5, :cond_17

    .line 523
    .line 524
    const/16 v5, 0x9

    .line 525
    .line 526
    goto :goto_c

    .line 527
    :cond_17
    const/16 v5, 0x8

    .line 528
    .line 529
    :goto_c
    add-int/2addr v8, v5

    .line 530
    invoke-virtual {v3, v8}, Ljava/nio/ByteBuffer;->get(I)B

    .line 531
    .line 532
    .line 533
    move-result v5

    .line 534
    shr-int/lit8 v5, v5, 0x4

    .line 535
    .line 536
    and-int/lit8 v5, v5, 0x7

    .line 537
    .line 538
    const/16 v8, 0x28

    .line 539
    .line 540
    shl-int v5, v8, v5

    .line 541
    .line 542
    mul-int/lit8 v15, v5, 0x10

    .line 543
    .line 544
    goto/16 :goto_1a

    .line 545
    .line 546
    :pswitch_4
    const/16 v15, 0x800

    .line 547
    .line 548
    goto/16 :goto_1a

    .line 549
    .line 550
    :pswitch_5
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 551
    .line 552
    .line 553
    move-result v5

    .line 554
    sget-object v10, Lw7/w;->a:Ljava/lang/String;

    .line 555
    .line 556
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 557
    .line 558
    .line 559
    move-result v5

    .line 560
    invoke-virtual {v3}, Ljava/nio/ByteBuffer;->order()Ljava/nio/ByteOrder;

    .line 561
    .line 562
    .line 563
    move-result-object v10

    .line 564
    sget-object v13, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 565
    .line 566
    if-ne v10, v13, :cond_18

    .line 567
    .line 568
    goto :goto_d

    .line 569
    :cond_18
    invoke-static {v5}, Ljava/lang/Integer;->reverseBytes(I)I

    .line 570
    .line 571
    .line 572
    move-result v5

    .line 573
    :goto_d
    const/high16 v10, -0x200000

    .line 574
    .line 575
    and-int v13, v5, v10

    .line 576
    .line 577
    if-ne v13, v10, :cond_19

    .line 578
    .line 579
    ushr-int/lit8 v10, v5, 0x13

    .line 580
    .line 581
    and-int/2addr v10, v8

    .line 582
    if-ne v10, v6, :cond_1a

    .line 583
    .line 584
    :cond_19
    :goto_e
    move v5, v15

    .line 585
    goto :goto_f

    .line 586
    :cond_1a
    ushr-int/lit8 v13, v5, 0x11

    .line 587
    .line 588
    and-int/2addr v13, v8

    .line 589
    if-nez v13, :cond_1b

    .line 590
    .line 591
    goto :goto_e

    .line 592
    :cond_1b
    ushr-int/lit8 v14, v5, 0xc

    .line 593
    .line 594
    const/16 v7, 0xf

    .line 595
    .line 596
    and-int/2addr v14, v7

    .line 597
    ushr-int/2addr v5, v11

    .line 598
    and-int/2addr v5, v8

    .line 599
    if-eqz v14, :cond_19

    .line 600
    .line 601
    if-eq v14, v7, :cond_19

    .line 602
    .line 603
    if-ne v5, v8, :cond_1c

    .line 604
    .line 605
    goto :goto_e

    .line 606
    :cond_1c
    const/16 v5, 0x480

    .line 607
    .line 608
    if-eq v13, v6, :cond_1e

    .line 609
    .line 610
    if-eq v13, v12, :cond_20

    .line 611
    .line 612
    if-ne v13, v8, :cond_1d

    .line 613
    .line 614
    const/16 v5, 0x180

    .line 615
    .line 616
    goto :goto_f

    .line 617
    :cond_1d
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 618
    .line 619
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 620
    .line 621
    .line 622
    throw v0

    .line 623
    :cond_1e
    if-ne v10, v8, :cond_1f

    .line 624
    .line 625
    goto :goto_f

    .line 626
    :cond_1f
    const/16 v5, 0x240

    .line 627
    .line 628
    :cond_20
    :goto_f
    if-eq v5, v15, :cond_21

    .line 629
    .line 630
    move v15, v5

    .line 631
    goto/16 :goto_1a

    .line 632
    .line 633
    :cond_21
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 634
    .line 635
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 636
    .line 637
    .line 638
    throw v0

    .line 639
    :cond_22
    :pswitch_6
    move v5, v7

    .line 640
    goto :goto_11

    .line 641
    :pswitch_7
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 642
    .line 643
    .line 644
    move-result v5

    .line 645
    add-int/2addr v5, v13

    .line 646
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 647
    .line 648
    .line 649
    move-result v5

    .line 650
    and-int/lit16 v5, v5, 0xf8

    .line 651
    .line 652
    shr-int/2addr v5, v8

    .line 653
    if-le v5, v11, :cond_24

    .line 654
    .line 655
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 656
    .line 657
    .line 658
    move-result v5

    .line 659
    add-int/lit8 v5, v5, 0x4

    .line 660
    .line 661
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 662
    .line 663
    .line 664
    move-result v5

    .line 665
    and-int/lit16 v5, v5, 0xc0

    .line 666
    .line 667
    shr-int/lit8 v5, v5, 0x6

    .line 668
    .line 669
    if-ne v5, v8, :cond_23

    .line 670
    .line 671
    goto :goto_10

    .line 672
    :cond_23
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 673
    .line 674
    .line 675
    move-result v5

    .line 676
    add-int/lit8 v5, v5, 0x4

    .line 677
    .line 678
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 679
    .line 680
    .line 681
    move-result v5

    .line 682
    and-int/lit8 v5, v5, 0x30

    .line 683
    .line 684
    shr-int/lit8 v8, v5, 0x4

    .line 685
    .line 686
    :goto_10
    sget-object v5, Lo8/b;->c:[I

    .line 687
    .line 688
    aget v5, v5, v8

    .line 689
    .line 690
    mul-int/lit16 v15, v5, 0x100

    .line 691
    .line 692
    goto/16 :goto_1a

    .line 693
    .line 694
    :cond_24
    const/16 v15, 0x600

    .line 695
    .line 696
    goto/16 :goto_1a

    .line 697
    .line 698
    :goto_11
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 699
    .line 700
    .line 701
    move-result v7

    .line 702
    const v8, -0xde4bec0

    .line 703
    .line 704
    .line 705
    if-eq v7, v8, :cond_11

    .line 706
    .line 707
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 708
    .line 709
    .line 710
    move-result v7

    .line 711
    const v8, -0x17bd3b8f

    .line 712
    .line 713
    .line 714
    if-ne v7, v8, :cond_25

    .line 715
    .line 716
    goto/16 :goto_7

    .line 717
    .line 718
    :cond_25
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 719
    .line 720
    .line 721
    move-result v7

    .line 722
    const v5, 0x25205864

    .line 723
    .line 724
    .line 725
    if-ne v7, v5, :cond_26

    .line 726
    .line 727
    const/16 v15, 0x1000

    .line 728
    .line 729
    goto/16 :goto_1a

    .line 730
    .line 731
    :cond_26
    invoke-virtual {v3}, Ljava/nio/Buffer;->position()I

    .line 732
    .line 733
    .line 734
    move-result v5

    .line 735
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 736
    .line 737
    .line 738
    move-result v7

    .line 739
    if-eq v7, v14, :cond_29

    .line 740
    .line 741
    if-eq v7, v15, :cond_28

    .line 742
    .line 743
    const/16 v8, 0x1f

    .line 744
    .line 745
    if-eq v7, v8, :cond_27

    .line 746
    .line 747
    add-int/lit8 v7, v5, 0x4

    .line 748
    .line 749
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 750
    .line 751
    .line 752
    move-result v7

    .line 753
    and-int/2addr v7, v6

    .line 754
    shl-int/lit8 v7, v7, 0x6

    .line 755
    .line 756
    add-int/2addr v5, v13

    .line 757
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 758
    .line 759
    .line 760
    move-result v5

    .line 761
    :goto_12
    and-int/lit16 v5, v5, 0xfc

    .line 762
    .line 763
    :goto_13
    shr-int/2addr v5, v12

    .line 764
    or-int/2addr v5, v7

    .line 765
    goto :goto_15

    .line 766
    :cond_27
    add-int/lit8 v7, v5, 0x5

    .line 767
    .line 768
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 769
    .line 770
    .line 771
    move-result v7

    .line 772
    and-int/lit8 v7, v7, 0x7

    .line 773
    .line 774
    shl-int/lit8 v7, v7, 0x4

    .line 775
    .line 776
    add-int/lit8 v5, v5, 0x6

    .line 777
    .line 778
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 779
    .line 780
    .line 781
    move-result v5

    .line 782
    :goto_14
    and-int/lit8 v5, v5, 0x3c

    .line 783
    .line 784
    goto :goto_13

    .line 785
    :cond_28
    add-int/lit8 v7, v5, 0x4

    .line 786
    .line 787
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 788
    .line 789
    .line 790
    move-result v7

    .line 791
    and-int/lit8 v7, v7, 0x7

    .line 792
    .line 793
    shl-int/lit8 v7, v7, 0x4

    .line 794
    .line 795
    add-int/lit8 v5, v5, 0x7

    .line 796
    .line 797
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 798
    .line 799
    .line 800
    move-result v5

    .line 801
    goto :goto_14

    .line 802
    :cond_29
    add-int/lit8 v7, v5, 0x5

    .line 803
    .line 804
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 805
    .line 806
    .line 807
    move-result v7

    .line 808
    and-int/2addr v7, v6

    .line 809
    shl-int/lit8 v7, v7, 0x6

    .line 810
    .line 811
    add-int/lit8 v5, v5, 0x4

    .line 812
    .line 813
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 814
    .line 815
    .line 816
    move-result v5

    .line 817
    goto :goto_12

    .line 818
    :goto_15
    add-int/2addr v5, v6

    .line 819
    mul-int/lit8 v15, v5, 0x20

    .line 820
    .line 821
    goto :goto_1a

    .line 822
    :cond_2a
    invoke-virtual {v3, v13}, Ljava/nio/ByteBuffer;->get(I)B

    .line 823
    .line 824
    .line 825
    move-result v5

    .line 826
    and-int/2addr v5, v12

    .line 827
    if-nez v5, :cond_2b

    .line 828
    .line 829
    const/4 v5, 0x0

    .line 830
    goto :goto_18

    .line 831
    :cond_2b
    const/16 v5, 0x1a

    .line 832
    .line 833
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 834
    .line 835
    .line 836
    move-result v5

    .line 837
    const/16 v7, 0x1c

    .line 838
    .line 839
    move v10, v7

    .line 840
    const/4 v8, 0x0

    .line 841
    :goto_16
    if-ge v8, v5, :cond_2c

    .line 842
    .line 843
    add-int/lit8 v11, v8, 0x1b

    .line 844
    .line 845
    invoke-virtual {v3, v11}, Ljava/nio/ByteBuffer;->get(I)B

    .line 846
    .line 847
    .line 848
    move-result v11

    .line 849
    add-int/2addr v10, v11

    .line 850
    add-int/lit8 v8, v8, 0x1

    .line 851
    .line 852
    goto :goto_16

    .line 853
    :cond_2c
    add-int/lit8 v5, v10, 0x1a

    .line 854
    .line 855
    invoke-virtual {v3, v5}, Ljava/nio/ByteBuffer;->get(I)B

    .line 856
    .line 857
    .line 858
    move-result v5

    .line 859
    const/4 v8, 0x0

    .line 860
    :goto_17
    if-ge v8, v5, :cond_2d

    .line 861
    .line 862
    add-int/lit8 v11, v10, 0x1b

    .line 863
    .line 864
    add-int/2addr v11, v8

    .line 865
    invoke-virtual {v3, v11}, Ljava/nio/ByteBuffer;->get(I)B

    .line 866
    .line 867
    .line 868
    move-result v11

    .line 869
    add-int/2addr v7, v11

    .line 870
    add-int/lit8 v8, v8, 0x1

    .line 871
    .line 872
    goto :goto_17

    .line 873
    :cond_2d
    add-int v5, v10, v7

    .line 874
    .line 875
    :goto_18
    add-int/lit8 v7, v5, 0x1a

    .line 876
    .line 877
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 878
    .line 879
    .line 880
    move-result v7

    .line 881
    add-int/lit8 v7, v7, 0x1b

    .line 882
    .line 883
    add-int/2addr v7, v5

    .line 884
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 885
    .line 886
    .line 887
    move-result v5

    .line 888
    invoke-virtual {v3}, Ljava/nio/Buffer;->limit()I

    .line 889
    .line 890
    .line 891
    move-result v8

    .line 892
    sub-int/2addr v8, v7

    .line 893
    if-le v8, v6, :cond_2e

    .line 894
    .line 895
    add-int/2addr v7, v6

    .line 896
    invoke-virtual {v3, v7}, Ljava/nio/ByteBuffer;->get(I)B

    .line 897
    .line 898
    .line 899
    move-result v7

    .line 900
    goto :goto_19

    .line 901
    :cond_2e
    const/4 v7, 0x0

    .line 902
    :goto_19
    invoke-static {v5, v7}, Lo8/b;->k(BB)J

    .line 903
    .line 904
    .line 905
    move-result-wide v7

    .line 906
    const-wide/32 v10, 0xbb80

    .line 907
    .line 908
    .line 909
    mul-long/2addr v7, v10

    .line 910
    const-wide/32 v10, 0xf4240

    .line 911
    .line 912
    .line 913
    div-long/2addr v7, v10

    .line 914
    long-to-int v15, v7

    .line 915
    :goto_1a
    iput v15, v0, Lc8/y;->J:I

    .line 916
    .line 917
    if-nez v15, :cond_2f

    .line 918
    .line 919
    :goto_1b
    return v6

    .line 920
    :cond_2f
    iget-object v5, v0, Lc8/y;->B:Lc8/u;

    .line 921
    .line 922
    if-eqz v5, :cond_32

    .line 923
    .line 924
    invoke-virtual {v0}, Lc8/y;->f()Z

    .line 925
    .line 926
    .line 927
    move-result v5

    .line 928
    if-nez v5, :cond_31

    .line 929
    .line 930
    :cond_30
    :goto_1c
    const/16 v19, 0x0

    .line 931
    .line 932
    goto/16 :goto_1e

    .line 933
    .line 934
    :cond_31
    invoke-virtual/range {p0 .. p2}, Lc8/y;->a(J)V

    .line 935
    .line 936
    .line 937
    const/4 v5, 0x0

    .line 938
    iput-object v5, v0, Lc8/y;->B:Lc8/u;

    .line 939
    .line 940
    :cond_32
    iget-wide v7, v0, Lc8/y;->M:J

    .line 941
    .line 942
    iget-object v5, v0, Lc8/y;->u:Lc8/t;

    .line 943
    .line 944
    invoke-virtual {v0}, Lc8/y;->j()J

    .line 945
    .line 946
    .line 947
    move-result-wide v10

    .line 948
    iget-object v12, v0, Lc8/y;->d:Lc8/e0;

    .line 949
    .line 950
    iget-wide v12, v12, Lc8/e0;->o:J

    .line 951
    .line 952
    sub-long/2addr v10, v12

    .line 953
    iget-object v5, v5, Lc8/t;->a:Lt7/o;

    .line 954
    .line 955
    iget v5, v5, Lt7/o;->G:I

    .line 956
    .line 957
    invoke-static {v5, v10, v11}, Lw7/w;->H(IJ)J

    .line 958
    .line 959
    .line 960
    move-result-wide v10

    .line 961
    add-long/2addr v10, v7

    .line 962
    iget-boolean v5, v0, Lc8/y;->K:Z

    .line 963
    .line 964
    if-nez v5, :cond_34

    .line 965
    .line 966
    sub-long v7, v10, v1

    .line 967
    .line 968
    invoke-static {v7, v8}, Ljava/lang/Math;->abs(J)J

    .line 969
    .line 970
    .line 971
    move-result-wide v7

    .line 972
    const-wide/32 v12, 0x30d40

    .line 973
    .line 974
    .line 975
    cmp-long v5, v7, v12

    .line 976
    .line 977
    if-lez v5, :cond_34

    .line 978
    .line 979
    iget-object v5, v0, Lc8/y;->s:Laq/a;

    .line 980
    .line 981
    if-eqz v5, :cond_33

    .line 982
    .line 983
    new-instance v7, Lb0/l;

    .line 984
    .line 985
    const-string v8, "Unexpected audio track timestamp discontinuity: expected "

    .line 986
    .line 987
    const-string v12, ", got "

    .line 988
    .line 989
    invoke-static {v10, v11, v8, v12}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 990
    .line 991
    .line 992
    move-result-object v8

    .line 993
    invoke-virtual {v8, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 994
    .line 995
    .line 996
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 997
    .line 998
    .line 999
    move-result-object v8

    .line 1000
    invoke-direct {v7, v8}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 1001
    .line 1002
    .line 1003
    invoke-virtual {v5, v7}, Laq/a;->B(Ljava/lang/Exception;)V

    .line 1004
    .line 1005
    .line 1006
    :cond_33
    iput-boolean v6, v0, Lc8/y;->K:Z

    .line 1007
    .line 1008
    :cond_34
    iget-boolean v5, v0, Lc8/y;->K:Z

    .line 1009
    .line 1010
    if-eqz v5, :cond_36

    .line 1011
    .line 1012
    invoke-virtual {v0}, Lc8/y;->f()Z

    .line 1013
    .line 1014
    .line 1015
    move-result v5

    .line 1016
    if-nez v5, :cond_35

    .line 1017
    .line 1018
    goto :goto_1c

    .line 1019
    :cond_35
    sub-long v7, v1, v10

    .line 1020
    .line 1021
    iget-wide v10, v0, Lc8/y;->M:J

    .line 1022
    .line 1023
    add-long/2addr v10, v7

    .line 1024
    iput-wide v10, v0, Lc8/y;->M:J

    .line 1025
    .line 1026
    const/4 v5, 0x0

    .line 1027
    iput-boolean v5, v0, Lc8/y;->K:Z

    .line 1028
    .line 1029
    invoke-virtual/range {p0 .. p2}, Lc8/y;->a(J)V

    .line 1030
    .line 1031
    .line 1032
    iget-object v5, v0, Lc8/y;->s:Laq/a;

    .line 1033
    .line 1034
    if-eqz v5, :cond_36

    .line 1035
    .line 1036
    cmp-long v7, v7, v25

    .line 1037
    .line 1038
    if-eqz v7, :cond_36

    .line 1039
    .line 1040
    iget-object v5, v5, Laq/a;->e:Ljava/lang/Object;

    .line 1041
    .line 1042
    check-cast v5, Lc8/a0;

    .line 1043
    .line 1044
    iput-boolean v6, v5, Lc8/a0;->Y1:Z

    .line 1045
    .line 1046
    :cond_36
    iget-object v5, v0, Lc8/y;->u:Lc8/t;

    .line 1047
    .line 1048
    iget v5, v5, Lc8/t;->c:I

    .line 1049
    .line 1050
    if-nez v5, :cond_37

    .line 1051
    .line 1052
    iget-wide v7, v0, Lc8/y;->F:J

    .line 1053
    .line 1054
    invoke-virtual {v3}, Ljava/nio/Buffer;->remaining()I

    .line 1055
    .line 1056
    .line 1057
    move-result v5

    .line 1058
    int-to-long v10, v5

    .line 1059
    add-long/2addr v7, v10

    .line 1060
    iput-wide v7, v0, Lc8/y;->F:J

    .line 1061
    .line 1062
    goto :goto_1d

    .line 1063
    :cond_37
    iget-wide v7, v0, Lc8/y;->G:J

    .line 1064
    .line 1065
    iget v5, v0, Lc8/y;->J:I

    .line 1066
    .line 1067
    int-to-long v10, v5

    .line 1068
    int-to-long v12, v4

    .line 1069
    mul-long/2addr v10, v12

    .line 1070
    add-long/2addr v10, v7

    .line 1071
    iput-wide v10, v0, Lc8/y;->G:J

    .line 1072
    .line 1073
    :goto_1d
    iput-object v3, v0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 1074
    .line 1075
    iput v4, v0, Lc8/y;->P:I

    .line 1076
    .line 1077
    :cond_38
    invoke-virtual/range {p0 .. p2}, Lc8/y;->t(J)V

    .line 1078
    .line 1079
    .line 1080
    iget-object v1, v0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 1081
    .line 1082
    invoke-virtual {v1}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 1083
    .line 1084
    .line 1085
    move-result v1

    .line 1086
    if-nez v1, :cond_39

    .line 1087
    .line 1088
    const/4 v5, 0x0

    .line 1089
    iput-object v5, v0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 1090
    .line 1091
    const/4 v5, 0x0

    .line 1092
    iput v5, v0, Lc8/y;->P:I

    .line 1093
    .line 1094
    return v6

    .line 1095
    :cond_39
    invoke-virtual {v0}, Lc8/y;->k()J

    .line 1096
    .line 1097
    .line 1098
    move-result-wide v1

    .line 1099
    iget-wide v3, v9, Lc8/p;->x:J

    .line 1100
    .line 1101
    cmp-long v3, v3, v16

    .line 1102
    .line 1103
    if-eqz v3, :cond_30

    .line 1104
    .line 1105
    cmp-long v1, v1, v25

    .line 1106
    .line 1107
    if-lez v1, :cond_30

    .line 1108
    .line 1109
    iget-object v1, v9, Lc8/p;->F:Lw7/r;

    .line 1110
    .line 1111
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1112
    .line 1113
    .line 1114
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 1115
    .line 1116
    .line 1117
    move-result-wide v1

    .line 1118
    iget-wide v3, v9, Lc8/p;->x:J

    .line 1119
    .line 1120
    sub-long/2addr v1, v3

    .line 1121
    const-wide/16 v3, 0xc8

    .line 1122
    .line 1123
    cmp-long v1, v1, v3

    .line 1124
    .line 1125
    if-ltz v1, :cond_30

    .line 1126
    .line 1127
    const-string v1, "DefaultAudioSink"

    .line 1128
    .line 1129
    const-string v2, "Resetting stalled audio track"

    .line 1130
    .line 1131
    invoke-static {v1, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 1132
    .line 1133
    .line 1134
    invoke-virtual {v0}, Lc8/y;->g()V

    .line 1135
    .line 1136
    .line 1137
    return v6

    .line 1138
    :goto_1e
    return v19

    .line 1139
    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_7
        :pswitch_7
        :pswitch_6
        :pswitch_6
        :pswitch_5
        :pswitch_1
        :pswitch_4
        :pswitch_4
    .end packed-switch

    .line 1140
    .line 1141
    .line 1142
    .line 1143
    .line 1144
    .line 1145
    .line 1146
    .line 1147
    .line 1148
    .line 1149
    .line 1150
    .line 1151
    .line 1152
    .line 1153
    .line 1154
    .line 1155
    .line 1156
    .line 1157
    .line 1158
    .line 1159
    :pswitch_data_1
    .packed-switch 0xe
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_7
    .end packed-switch
.end method

.method public final m()Z
    .locals 9

    .line 1
    invoke-virtual {p0}, Lc8/y;->o()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/media/AudioTrack;->isOffloadedPlayback()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    iget-boolean v0, p0, Lc8/y;->T:Z

    .line 16
    .line 17
    if-nez v0, :cond_2

    .line 18
    .line 19
    :cond_0
    invoke-virtual {p0}, Lc8/y;->k()J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    iget-object p0, p0, Lc8/y;->h:Lc8/p;

    .line 24
    .line 25
    invoke-virtual {p0}, Lc8/p;->a()J

    .line 26
    .line 27
    .line 28
    move-result-wide v2

    .line 29
    iget p0, p0, Lc8/p;->f:I

    .line 30
    .line 31
    sget-object v4, Lw7/w;->a:Ljava/lang/String;

    .line 32
    .line 33
    int-to-long v4, p0

    .line 34
    const-wide/32 v6, 0xf4240

    .line 35
    .line 36
    .line 37
    sget-object v8, Ljava/math/RoundingMode;->UP:Ljava/math/RoundingMode;

    .line 38
    .line 39
    invoke-static/range {v2 .. v8}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 40
    .line 41
    .line 42
    move-result-wide v2

    .line 43
    cmp-long p0, v0, v2

    .line 44
    .line 45
    if-gtz p0, :cond_1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    const/4 p0, 0x1

    .line 49
    return p0

    .line 50
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 51
    return p0
.end method

.method public final n()Z
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lc8/y;->l:Las/e;

    .line 4
    .line 5
    iget-object v2, v0, Las/e;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/lang/Exception;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x1

    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    goto :goto_2

    .line 14
    :cond_0
    sget-object v2, Lc8/y;->l0:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v2

    .line 17
    :try_start_0
    sget v5, Lc8/y;->n0:I

    .line 18
    .line 19
    if-lez v5, :cond_1

    .line 20
    .line 21
    move v5, v4

    .line 22
    goto :goto_0

    .line 23
    :cond_1
    move v5, v3

    .line 24
    :goto_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    if-eqz v5, :cond_2

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_2
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 29
    .line 30
    .line 31
    move-result-wide v5

    .line 32
    iget-wide v7, v0, Las/e;->b:J

    .line 33
    .line 34
    cmp-long v0, v5, v7

    .line 35
    .line 36
    if-gez v0, :cond_3

    .line 37
    .line 38
    :goto_1
    return v3

    .line 39
    :cond_3
    :goto_2
    :try_start_1
    iget-object v0, v1, Lc8/y;->u:Lc8/t;

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1, v0}, Lc8/y;->c(Lc8/t;)Landroid/media/AudioTrack;

    .line 45
    .line 46
    .line 47
    move-result-object v0
    :try_end_1
    .catch Lc8/l; {:try_start_1 .. :try_end_1} :catch_0

    .line 48
    goto :goto_3

    .line 49
    :catch_0
    move-exception v0

    .line 50
    move-object v2, v0

    .line 51
    iget-object v0, v1, Lc8/y;->u:Lc8/t;

    .line 52
    .line 53
    iget v5, v0, Lc8/t;->h:I

    .line 54
    .line 55
    const v6, 0xf4240

    .line 56
    .line 57
    .line 58
    if-le v5, v6, :cond_f

    .line 59
    .line 60
    new-instance v7, Lc8/t;

    .line 61
    .line 62
    iget-object v8, v0, Lc8/t;->a:Lt7/o;

    .line 63
    .line 64
    iget v9, v0, Lc8/t;->b:I

    .line 65
    .line 66
    iget v10, v0, Lc8/t;->c:I

    .line 67
    .line 68
    iget v11, v0, Lc8/t;->d:I

    .line 69
    .line 70
    iget v12, v0, Lc8/t;->e:I

    .line 71
    .line 72
    iget v13, v0, Lc8/t;->f:I

    .line 73
    .line 74
    iget v14, v0, Lc8/t;->g:I

    .line 75
    .line 76
    iget-object v5, v0, Lc8/t;->i:Lu7/c;

    .line 77
    .line 78
    iget-boolean v6, v0, Lc8/t;->j:Z

    .line 79
    .line 80
    iget-boolean v15, v0, Lc8/t;->k:Z

    .line 81
    .line 82
    iget-boolean v0, v0, Lc8/t;->l:Z

    .line 83
    .line 84
    move/from16 v18, v15

    .line 85
    .line 86
    const v15, 0xf4240

    .line 87
    .line 88
    .line 89
    move/from16 v19, v0

    .line 90
    .line 91
    move-object/from16 v16, v5

    .line 92
    .line 93
    move/from16 v17, v6

    .line 94
    .line 95
    invoke-direct/range {v7 .. v19}, Lc8/t;-><init>(Lt7/o;IIIIIIILu7/c;ZZZ)V

    .line 96
    .line 97
    .line 98
    :try_start_2
    invoke-virtual {v1, v7}, Lc8/y;->c(Lc8/t;)Landroid/media/AudioTrack;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    iput-object v7, v1, Lc8/y;->u:Lc8/t;
    :try_end_2
    .catch Lc8/l; {:try_start_2 .. :try_end_2} :catch_1

    .line 103
    .line 104
    :goto_3
    iput-object v0, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 105
    .line 106
    invoke-virtual {v0}, Landroid/media/AudioTrack;->isOffloadedPlayback()Z

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    if-eqz v0, :cond_5

    .line 111
    .line 112
    iget-object v0, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 113
    .line 114
    iget-object v2, v1, Lc8/y;->k:Lgw0/c;

    .line 115
    .line 116
    if-nez v2, :cond_4

    .line 117
    .line 118
    new-instance v2, Lgw0/c;

    .line 119
    .line 120
    invoke-direct {v2, v1}, Lgw0/c;-><init>(Lc8/y;)V

    .line 121
    .line 122
    .line 123
    iput-object v2, v1, Lc8/y;->k:Lgw0/c;

    .line 124
    .line 125
    :cond_4
    iget-object v2, v1, Lc8/y;->k:Lgw0/c;

    .line 126
    .line 127
    iget-object v5, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v5, Landroid/os/Handler;

    .line 130
    .line 131
    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    new-instance v6, Lc8/w;

    .line 135
    .line 136
    const/4 v7, 0x0

    .line 137
    invoke-direct {v6, v5, v7}, Lc8/w;-><init>(Ljava/lang/Object;I)V

    .line 138
    .line 139
    .line 140
    iget-object v2, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v2, Lc8/x;

    .line 143
    .line 144
    invoke-virtual {v0, v6, v2}, Landroid/media/AudioTrack;->registerStreamEventCallback(Ljava/util/concurrent/Executor;Landroid/media/AudioTrack$StreamEventCallback;)V

    .line 145
    .line 146
    .line 147
    iget-object v0, v1, Lc8/y;->u:Lc8/t;

    .line 148
    .line 149
    iget-boolean v2, v0, Lc8/t;->k:Z

    .line 150
    .line 151
    if-eqz v2, :cond_5

    .line 152
    .line 153
    iget-object v2, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 154
    .line 155
    iget-object v0, v0, Lc8/t;->a:Lt7/o;

    .line 156
    .line 157
    iget v5, v0, Lt7/o;->I:I

    .line 158
    .line 159
    iget v0, v0, Lt7/o;->J:I

    .line 160
    .line 161
    invoke-virtual {v2, v5, v0}, Landroid/media/AudioTrack;->setOffloadDelayPadding(II)V

    .line 162
    .line 163
    .line 164
    :cond_5
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 165
    .line 166
    const/16 v2, 0x1f

    .line 167
    .line 168
    if-lt v0, v2, :cond_6

    .line 169
    .line 170
    iget-object v2, v1, Lc8/y;->r:Lb8/k;

    .line 171
    .line 172
    if-eqz v2, :cond_6

    .line 173
    .line 174
    iget-object v5, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 175
    .line 176
    invoke-virtual {v2}, Lb8/k;->a()Landroid/media/metrics/LogSessionId;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    invoke-static {}, Lb8/h;->a()Landroid/media/metrics/LogSessionId;

    .line 181
    .line 182
    .line 183
    invoke-static {v2}, Lb8/h;->y(Landroid/media/metrics/LogSessionId;)Z

    .line 184
    .line 185
    .line 186
    move-result v6

    .line 187
    if-nez v6, :cond_6

    .line 188
    .line 189
    invoke-static {v5, v2}, Lc4/a;->u(Landroid/media/AudioTrack;Landroid/media/metrics/LogSessionId;)V

    .line 190
    .line 191
    .line 192
    :cond_6
    iget-object v2, v1, Lc8/y;->h:Lc8/p;

    .line 193
    .line 194
    iget-object v5, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 195
    .line 196
    iget-object v6, v1, Lc8/y;->u:Lc8/t;

    .line 197
    .line 198
    iget v7, v6, Lc8/t;->c:I

    .line 199
    .line 200
    iget v7, v6, Lc8/t;->g:I

    .line 201
    .line 202
    iget v8, v6, Lc8/t;->d:I

    .line 203
    .line 204
    iget v6, v6, Lc8/t;->h:I

    .line 205
    .line 206
    iget-boolean v9, v1, Lc8/y;->k0:Z

    .line 207
    .line 208
    iput-object v5, v2, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 209
    .line 210
    iput v6, v2, Lc8/p;->d:I

    .line 211
    .line 212
    new-instance v10, Lc8/o;

    .line 213
    .line 214
    iget-object v11, v2, Lc8/p;->a:Lbu/c;

    .line 215
    .line 216
    invoke-direct {v10, v5, v11}, Lc8/o;-><init>(Landroid/media/AudioTrack;Lbu/c;)V

    .line 217
    .line 218
    .line 219
    iput-object v10, v2, Lc8/p;->e:Lc8/o;

    .line 220
    .line 221
    invoke-virtual {v5}, Landroid/media/AudioTrack;->getSampleRate()I

    .line 222
    .line 223
    .line 224
    move-result v5

    .line 225
    iput v5, v2, Lc8/p;->f:I

    .line 226
    .line 227
    invoke-static {v7}, Lw7/w;->A(I)Z

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    iput-boolean v5, v2, Lc8/p;->p:Z

    .line 232
    .line 233
    const-wide v10, -0x7fffffffffffffffL    # -4.9E-324

    .line 234
    .line 235
    .line 236
    .line 237
    .line 238
    if-eqz v5, :cond_7

    .line 239
    .line 240
    div-int/2addr v6, v8

    .line 241
    int-to-long v5, v6

    .line 242
    iget v7, v2, Lc8/p;->f:I

    .line 243
    .line 244
    invoke-static {v7, v5, v6}, Lw7/w;->H(IJ)J

    .line 245
    .line 246
    .line 247
    move-result-wide v5

    .line 248
    goto :goto_4

    .line 249
    :cond_7
    move-wide v5, v10

    .line 250
    :goto_4
    iput-wide v5, v2, Lc8/p;->g:J

    .line 251
    .line 252
    const-wide/16 v5, 0x0

    .line 253
    .line 254
    iput-wide v5, v2, Lc8/p;->s:J

    .line 255
    .line 256
    iput-wide v5, v2, Lc8/p;->t:J

    .line 257
    .line 258
    iput-boolean v3, v2, Lc8/p;->D:Z

    .line 259
    .line 260
    iput-wide v5, v2, Lc8/p;->E:J

    .line 261
    .line 262
    iput-wide v10, v2, Lc8/p;->w:J

    .line 263
    .line 264
    iput-wide v10, v2, Lc8/p;->x:J

    .line 265
    .line 266
    iput-wide v5, v2, Lc8/p;->q:J

    .line 267
    .line 268
    iput-wide v5, v2, Lc8/p;->o:J

    .line 269
    .line 270
    const/high16 v5, 0x3f800000    # 1.0f

    .line 271
    .line 272
    iput v5, v2, Lc8/p;->h:F

    .line 273
    .line 274
    iput v3, v2, Lc8/p;->k:I

    .line 275
    .line 276
    iput-wide v10, v2, Lc8/p;->j:J

    .line 277
    .line 278
    iput-boolean v9, v2, Lc8/p;->A:Z

    .line 279
    .line 280
    invoke-virtual {v1}, Lc8/y;->o()Z

    .line 281
    .line 282
    .line 283
    move-result v2

    .line 284
    if-eqz v2, :cond_8

    .line 285
    .line 286
    iget-object v2, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 287
    .line 288
    iget v5, v1, Lc8/y;->N:F

    .line 289
    .line 290
    invoke-virtual {v2, v5}, Landroid/media/AudioTrack;->setVolume(F)I

    .line 291
    .line 292
    .line 293
    :cond_8
    iget-object v2, v1, Lc8/y;->Y:Lt7/d;

    .line 294
    .line 295
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 296
    .line 297
    .line 298
    iget-object v2, v1, Lc8/y;->Z:La0/j;

    .line 299
    .line 300
    if-eqz v2, :cond_9

    .line 301
    .line 302
    iget-object v5, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 303
    .line 304
    iget-object v2, v2, La0/j;->e:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v2, Landroid/media/AudioDeviceInfo;

    .line 307
    .line 308
    invoke-virtual {v5, v2}, Landroid/media/AudioTrack;->setPreferredDevice(Landroid/media/AudioDeviceInfo;)Z

    .line 309
    .line 310
    .line 311
    iget-object v2, v1, Lc8/y;->y:Lc8/f;

    .line 312
    .line 313
    if-eqz v2, :cond_9

    .line 314
    .line 315
    iget-object v5, v1, Lc8/y;->Z:La0/j;

    .line 316
    .line 317
    iget-object v5, v5, La0/j;->e:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast v5, Landroid/media/AudioDeviceInfo;

    .line 320
    .line 321
    invoke-virtual {v2, v5}, Lc8/f;->f(Landroid/media/AudioDeviceInfo;)V

    .line 322
    .line 323
    .line 324
    :cond_9
    iget-object v2, v1, Lc8/y;->y:Lc8/f;

    .line 325
    .line 326
    if-eqz v2, :cond_a

    .line 327
    .line 328
    new-instance v5, Lgw0/c;

    .line 329
    .line 330
    iget-object v6, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 331
    .line 332
    invoke-direct {v5, v6, v2}, Lgw0/c;-><init>(Landroid/media/AudioTrack;Lc8/f;)V

    .line 333
    .line 334
    .line 335
    iput-object v5, v1, Lc8/y;->z:Lgw0/c;

    .line 336
    .line 337
    :cond_a
    iput-boolean v4, v1, Lc8/y;->L:Z

    .line 338
    .line 339
    iget-object v2, v1, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 340
    .line 341
    invoke-virtual {v2}, Landroid/media/AudioTrack;->getAudioSessionId()I

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    iget v5, v1, Lc8/y;->W:I

    .line 346
    .line 347
    if-eq v2, v5, :cond_b

    .line 348
    .line 349
    move v3, v4

    .line 350
    :cond_b
    iput v2, v1, Lc8/y;->W:I

    .line 351
    .line 352
    iget-object v2, v1, Lc8/y;->s:Laq/a;

    .line 353
    .line 354
    if-eqz v2, :cond_e

    .line 355
    .line 356
    iget-object v5, v1, Lc8/y;->u:Lc8/t;

    .line 357
    .line 358
    invoke-virtual {v5}, Lc8/t;->a()Lc8/j;

    .line 359
    .line 360
    .line 361
    move-result-object v5

    .line 362
    iget-object v2, v2, Laq/a;->e:Ljava/lang/Object;

    .line 363
    .line 364
    check-cast v2, Lc8/a0;

    .line 365
    .line 366
    iget-object v2, v2, Lc8/a0;->Q1:Lb81/d;

    .line 367
    .line 368
    iget-object v6, v2, Lb81/d;->e:Ljava/lang/Object;

    .line 369
    .line 370
    check-cast v6, Landroid/os/Handler;

    .line 371
    .line 372
    if-eqz v6, :cond_c

    .line 373
    .line 374
    new-instance v7, Lc8/i;

    .line 375
    .line 376
    const/4 v8, 0x7

    .line 377
    invoke-direct {v7, v2, v5, v8}, Lc8/i;-><init>(Lb81/d;Ljava/lang/Object;I)V

    .line 378
    .line 379
    .line 380
    invoke-virtual {v6, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 381
    .line 382
    .line 383
    :cond_c
    if-eqz v3, :cond_e

    .line 384
    .line 385
    iput-boolean v4, v1, Lc8/y;->X:Z

    .line 386
    .line 387
    iget-object v2, v1, Lc8/y;->s:Laq/a;

    .line 388
    .line 389
    iget v1, v1, Lc8/y;->W:I

    .line 390
    .line 391
    iget-object v2, v2, Laq/a;->e:Ljava/lang/Object;

    .line 392
    .line 393
    check-cast v2, Lc8/a0;

    .line 394
    .line 395
    const/16 v3, 0x23

    .line 396
    .line 397
    if-lt v0, v3, :cond_d

    .line 398
    .line 399
    iget-object v0, v2, Lc8/a0;->S1:Lgw0/c;

    .line 400
    .line 401
    if-eqz v0, :cond_d

    .line 402
    .line 403
    invoke-virtual {v0, v1}, Lgw0/c;->w(I)V

    .line 404
    .line 405
    .line 406
    :cond_d
    iget-object v0, v2, Lc8/a0;->Q1:Lb81/d;

    .line 407
    .line 408
    iget-object v2, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 409
    .line 410
    check-cast v2, Landroid/os/Handler;

    .line 411
    .line 412
    if-eqz v2, :cond_e

    .line 413
    .line 414
    new-instance v3, La8/j0;

    .line 415
    .line 416
    const/4 v5, 0x2

    .line 417
    invoke-direct {v3, v0, v1, v5}, La8/j0;-><init>(Ljava/lang/Object;II)V

    .line 418
    .line 419
    .line 420
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 421
    .line 422
    .line 423
    :cond_e
    return v4

    .line 424
    :catch_1
    move-exception v0

    .line 425
    invoke-virtual {v2, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 426
    .line 427
    .line 428
    :cond_f
    iget-object v0, v1, Lc8/y;->u:Lc8/t;

    .line 429
    .line 430
    iget v0, v0, Lc8/t;->c:I

    .line 431
    .line 432
    if-ne v0, v4, :cond_10

    .line 433
    .line 434
    iput-boolean v4, v1, Lc8/y;->d0:Z

    .line 435
    .line 436
    :cond_10
    throw v2

    .line 437
    :catchall_0
    move-exception v0

    .line 438
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 439
    throw v0
.end method

.method public final o()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final q()V
    .locals 7

    .line 1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lc8/y;->y:Lc8/f;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x0

    .line 9
    if-eqz v1, :cond_1

    .line 10
    .line 11
    iget-object v1, p0, Lc8/y;->f0:Landroid/os/Looper;

    .line 12
    .line 13
    if-ne v1, v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v3

    .line 17
    goto :goto_1

    .line 18
    :cond_1
    :goto_0
    move v1, v2

    .line 19
    :goto_1
    new-instance v4, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v5, "DefaultAudioSink accessed on multiple threads: "

    .line 22
    .line 23
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v5, p0, Lc8/y;->f0:Landroid/os/Looper;

    .line 27
    .line 28
    const-string v6, "null"

    .line 29
    .line 30
    if-nez v5, :cond_2

    .line 31
    .line 32
    move-object v5, v6

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    invoke-virtual {v5}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    invoke-virtual {v5}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    :goto_2
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v5, " and "

    .line 46
    .line 47
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    if-nez v0, :cond_3

    .line 51
    .line 52
    goto :goto_3

    .line 53
    :cond_3
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    invoke-virtual {v5}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    :goto_3
    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-static {v4, v1}, Lw7/a;->i(Ljava/lang/String;Z)V

    .line 69
    .line 70
    .line 71
    iget-object v1, p0, Lc8/y;->y:Lc8/f;

    .line 72
    .line 73
    if-nez v1, :cond_7

    .line 74
    .line 75
    iget-object v1, p0, Lc8/y;->a:Landroid/content/Context;

    .line 76
    .line 77
    if-eqz v1, :cond_7

    .line 78
    .line 79
    iput-object v0, p0, Lc8/y;->f0:Landroid/os/Looper;

    .line 80
    .line 81
    new-instance v0, Lc8/f;

    .line 82
    .line 83
    new-instance v4, La8/t;

    .line 84
    .line 85
    const/16 v5, 0xc

    .line 86
    .line 87
    invoke-direct {v4, p0, v5}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 88
    .line 89
    .line 90
    iget-object v5, p0, Lc8/y;->A:Lt7/c;

    .line 91
    .line 92
    iget-object v6, p0, Lc8/y;->Z:La0/j;

    .line 93
    .line 94
    invoke-direct {v0, v1, v4, v5, v6}, Lc8/f;-><init>(Landroid/content/Context;La8/t;Lt7/c;La0/j;)V

    .line 95
    .line 96
    .line 97
    iput-object v0, p0, Lc8/y;->y:Lc8/f;

    .line 98
    .line 99
    iget-object v1, v0, Lc8/f;->d:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v1, Landroid/os/Handler;

    .line 102
    .line 103
    iget-object v4, v0, Lc8/f;->b:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v4, Landroid/content/Context;

    .line 106
    .line 107
    iget-boolean v5, v0, Lc8/f;->a:Z

    .line 108
    .line 109
    if-eqz v5, :cond_4

    .line 110
    .line 111
    iget-object v0, v0, Lc8/f;->h:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Lc8/b;

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_4
    iput-boolean v2, v0, Lc8/f;->a:Z

    .line 120
    .line 121
    iget-object v2, v0, Lc8/f;->g:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v2, Lc8/d;

    .line 124
    .line 125
    if-eqz v2, :cond_5

    .line 126
    .line 127
    iget-object v5, v2, Lc8/d;->a:Landroid/content/ContentResolver;

    .line 128
    .line 129
    iget-object v6, v2, Lc8/d;->b:Landroid/net/Uri;

    .line 130
    .line 131
    invoke-virtual {v5, v6, v3, v2}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    .line 132
    .line 133
    .line 134
    :cond_5
    iget-object v2, v0, Lc8/f;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v2, Lc8/c;

    .line 137
    .line 138
    if-eqz v2, :cond_6

    .line 139
    .line 140
    invoke-static {v4}, Lu7/b;->a(Landroid/content/Context;)Landroid/media/AudioManager;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    invoke-virtual {v3, v2, v1}, Landroid/media/AudioManager;->registerAudioDeviceCallback(Landroid/media/AudioDeviceCallback;Landroid/os/Handler;)V

    .line 145
    .line 146
    .line 147
    :cond_6
    iget-object v2, v0, Lc8/f;->f:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v2, Lc8/e;

    .line 150
    .line 151
    new-instance v3, Landroid/content/IntentFilter;

    .line 152
    .line 153
    const-string v5, "android.media.action.HDMI_AUDIO_PLUG"

    .line 154
    .line 155
    invoke-direct {v3, v5}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    const/4 v5, 0x0

    .line 159
    invoke-virtual {v4, v2, v3, v5, v1}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    iget-object v2, v0, Lc8/f;->j:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v2, Lt7/c;

    .line 166
    .line 167
    iget-object v3, v0, Lc8/f;->i:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v3, La0/j;

    .line 170
    .line 171
    invoke-static {v4, v1, v2, v3}, Lc8/b;->b(Landroid/content/Context;Landroid/content/Intent;Lt7/c;La0/j;)Lc8/b;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    iput-object v1, v0, Lc8/f;->h:Ljava/lang/Object;

    .line 176
    .line 177
    move-object v0, v1

    .line 178
    :goto_4
    iput-object v0, p0, Lc8/y;->x:Lc8/b;

    .line 179
    .line 180
    :cond_7
    iget-object p0, p0, Lc8/y;->x:Lc8/b;

    .line 181
    .line 182
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    return-void
.end method

.method public final r()V
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lc8/y;->U:Z

    .line 3
    .line 4
    invoke-virtual {p0}, Lc8/y;->o()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    iget-object v0, p0, Lc8/y;->h:Lc8/p;

    .line 11
    .line 12
    iget-wide v1, v0, Lc8/p;->w:J

    .line 13
    .line 14
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    cmp-long v1, v1, v3

    .line 20
    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    iget-object v1, v0, Lc8/p;->F:Lw7/r;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 29
    .line 30
    .line 31
    move-result-wide v1

    .line 32
    invoke-static {v1, v2}, Lw7/w;->D(J)J

    .line 33
    .line 34
    .line 35
    move-result-wide v1

    .line 36
    iput-wide v1, v0, Lc8/p;->w:J

    .line 37
    .line 38
    :cond_0
    invoke-virtual {v0}, Lc8/p;->b()J

    .line 39
    .line 40
    .line 41
    move-result-wide v1

    .line 42
    iget v3, v0, Lc8/p;->f:I

    .line 43
    .line 44
    invoke-static {v3, v1, v2}, Lw7/w;->H(IJ)J

    .line 45
    .line 46
    .line 47
    move-result-wide v1

    .line 48
    iput-wide v1, v0, Lc8/p;->j:J

    .line 49
    .line 50
    iget-object v0, v0, Lc8/p;->e:Lc8/o;

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    const/4 v1, 0x0

    .line 56
    invoke-virtual {v0, v1}, Lc8/o;->a(I)V

    .line 57
    .line 58
    .line 59
    iget-boolean v0, p0, Lc8/y;->S:Z

    .line 60
    .line 61
    if-eqz v0, :cond_1

    .line 62
    .line 63
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 64
    .line 65
    invoke-static {v0}, Lc8/y;->p(Landroid/media/AudioTrack;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    if-eqz v0, :cond_2

    .line 70
    .line 71
    :cond_1
    iget-object p0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 72
    .line 73
    invoke-virtual {p0}, Landroid/media/AudioTrack;->play()V

    .line 74
    .line 75
    .line 76
    :cond_2
    return-void
.end method

.method public final s()V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lc8/y;->S:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lc8/y;->S:Z

    .line 7
    .line 8
    invoke-virtual {p0}, Lc8/y;->k()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-object v2, p0, Lc8/y;->h:Lc8/p;

    .line 13
    .line 14
    invoke-virtual {v2}, Lc8/p;->b()J

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    iput-wide v3, v2, Lc8/p;->y:J

    .line 19
    .line 20
    iget-object v3, v2, Lc8/p;->F:Lw7/r;

    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 26
    .line 27
    .line 28
    move-result-wide v3

    .line 29
    invoke-static {v3, v4}, Lw7/w;->D(J)J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    iput-wide v3, v2, Lc8/p;->w:J

    .line 34
    .line 35
    iput-wide v0, v2, Lc8/p;->z:J

    .line 36
    .line 37
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 38
    .line 39
    invoke-static {v0}, Lc8/y;->p(Landroid/media/AudioTrack;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_0

    .line 44
    .line 45
    const/4 v0, 0x0

    .line 46
    iput-boolean v0, p0, Lc8/y;->T:Z

    .line 47
    .line 48
    :cond_0
    iget-object p0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 49
    .line 50
    invoke-virtual {p0}, Landroid/media/AudioTrack;->stop()V

    .line 51
    .line 52
    .line 53
    :cond_1
    return-void
.end method

.method public final t(J)V
    .locals 3

    .line 1
    invoke-virtual {p0, p1, p2}, Lc8/y;->e(J)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    goto/16 :goto_2

    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 11
    .line 12
    invoke-virtual {v0}, Lu7/c;->d()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    iget-object v0, p0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 19
    .line 20
    if-eqz v0, :cond_8

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lc8/y;->w(Ljava/nio/ByteBuffer;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1, p2}, Lc8/y;->e(J)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    :goto_0
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 30
    .line 31
    invoke-virtual {v0}, Lu7/c;->c()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_8

    .line 36
    .line 37
    :cond_2
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 38
    .line 39
    invoke-virtual {v0}, Lu7/c;->d()Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_3

    .line 44
    .line 45
    sget-object v0, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_3
    iget-object v1, v0, Lu7/c;->c:[Ljava/nio/ByteBuffer;

    .line 49
    .line 50
    invoke-virtual {v0}, Lu7/c;->b()I

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    aget-object v1, v1, v2

    .line 55
    .line 56
    invoke-virtual {v1}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_4

    .line 61
    .line 62
    move-object v0, v1

    .line 63
    goto :goto_1

    .line 64
    :cond_4
    sget-object v1, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Lu7/c;->e(Ljava/nio/ByteBuffer;)V

    .line 67
    .line 68
    .line 69
    iget-object v1, v0, Lu7/c;->c:[Ljava/nio/ByteBuffer;

    .line 70
    .line 71
    invoke-virtual {v0}, Lu7/c;->b()I

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    aget-object v0, v1, v0

    .line 76
    .line 77
    :goto_1
    invoke-virtual {v0}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-eqz v1, :cond_5

    .line 82
    .line 83
    invoke-virtual {p0, v0}, Lc8/y;->w(Ljava/nio/ByteBuffer;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, p1, p2}, Lc8/y;->e(J)V

    .line 87
    .line 88
    .line 89
    iget-object v0, p0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 90
    .line 91
    if-eqz v0, :cond_2

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_5
    iget-object v0, p0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 95
    .line 96
    if-eqz v0, :cond_8

    .line 97
    .line 98
    invoke-virtual {v0}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-nez v0, :cond_6

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_6
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 106
    .line 107
    iget-object v1, p0, Lc8/y;->O:Ljava/nio/ByteBuffer;

    .line 108
    .line 109
    invoke-virtual {v0}, Lu7/c;->d()Z

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    if-eqz v2, :cond_1

    .line 114
    .line 115
    iget-boolean v2, v0, Lu7/c;->d:Z

    .line 116
    .line 117
    if-eqz v2, :cond_7

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_7
    invoke-virtual {v0, v1}, Lu7/c;->e(Ljava/nio/ByteBuffer;)V

    .line 121
    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_8
    :goto_2
    return-void
.end method

.method public final u()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lc8/y;->g()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lc8/y;->g:Lhr/x0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {v0, v1}, Lhr/h0;->s(I)Lhr/f0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    :goto_0
    invoke-virtual {v0}, Lhr/f0;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0}, Lhr/f0;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lu7/f;

    .line 22
    .line 23
    invoke-interface {v2}, Lu7/f;->reset()V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-object v0, p0, Lc8/y;->e:Lu7/j;

    .line 28
    .line 29
    invoke-virtual {v0}, Lu7/g;->reset()V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Lc8/y;->f:Lc8/d0;

    .line 33
    .line 34
    invoke-virtual {v0}, Lu7/g;->reset()V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Lc8/y;->v:Lu7/c;

    .line 38
    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    iget-object v2, v0, Lu7/c;->a:Lhr/h0;

    .line 42
    .line 43
    move v3, v1

    .line 44
    :goto_1
    invoke-virtual {v2}, Ljava/util/AbstractCollection;->size()I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-ge v3, v4, :cond_1

    .line 49
    .line 50
    invoke-interface {v2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    check-cast v4, Lu7/f;

    .line 55
    .line 56
    invoke-interface {v4}, Lu7/f;->flush()V

    .line 57
    .line 58
    .line 59
    invoke-interface {v4}, Lu7/f;->reset()V

    .line 60
    .line 61
    .line 62
    add-int/lit8 v3, v3, 0x1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    new-array v2, v1, [Ljava/nio/ByteBuffer;

    .line 66
    .line 67
    iput-object v2, v0, Lu7/c;->c:[Ljava/nio/ByteBuffer;

    .line 68
    .line 69
    sget-object v2, Lu7/d;->e:Lu7/d;

    .line 70
    .line 71
    iput-boolean v1, v0, Lu7/c;->d:Z

    .line 72
    .line 73
    :cond_2
    iput-boolean v1, p0, Lc8/y;->U:Z

    .line 74
    .line 75
    iput-boolean v1, p0, Lc8/y;->d0:Z

    .line 76
    .line 77
    return-void
.end method

.method public final v()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lc8/y;->o()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    new-instance v0, Landroid/media/PlaybackParams;

    .line 8
    .line 9
    invoke-direct {v0}, Landroid/media/PlaybackParams;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/media/PlaybackParams;->allowDefaults()Landroid/media/PlaybackParams;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget-object v1, p0, Lc8/y;->D:Lt7/g0;

    .line 17
    .line 18
    iget v1, v1, Lt7/g0;->a:F

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Landroid/media/PlaybackParams;->setSpeed(F)Landroid/media/PlaybackParams;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v1, p0, Lc8/y;->D:Lt7/g0;

    .line 25
    .line 26
    iget v1, v1, Lt7/g0;->b:F

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Landroid/media/PlaybackParams;->setPitch(F)Landroid/media/PlaybackParams;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const/4 v1, 0x2

    .line 33
    invoke-virtual {v0, v1}, Landroid/media/PlaybackParams;->setAudioFallbackMode(I)Landroid/media/PlaybackParams;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :try_start_0
    iget-object v1, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 38
    .line 39
    invoke-virtual {v1, v0}, Landroid/media/AudioTrack;->setPlaybackParams(Landroid/media/PlaybackParams;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catch_0
    move-exception v0

    .line 44
    const-string v1, "DefaultAudioSink"

    .line 45
    .line 46
    const-string v2, "Failed to set playback params"

    .line 47
    .line 48
    invoke-static {v1, v2, v0}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 49
    .line 50
    .line 51
    :goto_0
    new-instance v0, Lt7/g0;

    .line 52
    .line 53
    iget-object v1, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 54
    .line 55
    invoke-virtual {v1}, Landroid/media/AudioTrack;->getPlaybackParams()Landroid/media/PlaybackParams;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v1}, Landroid/media/PlaybackParams;->getSpeed()F

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    iget-object v2, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 64
    .line 65
    invoke-virtual {v2}, Landroid/media/AudioTrack;->getPlaybackParams()Landroid/media/PlaybackParams;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v2}, Landroid/media/PlaybackParams;->getPitch()F

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    invoke-direct {v0, v1, v2}, Lt7/g0;-><init>(FF)V

    .line 74
    .line 75
    .line 76
    iput-object v0, p0, Lc8/y;->D:Lt7/g0;

    .line 77
    .line 78
    iget v0, v0, Lt7/g0;->a:F

    .line 79
    .line 80
    iget-object p0, p0, Lc8/y;->h:Lc8/p;

    .line 81
    .line 82
    iput v0, p0, Lc8/p;->h:F

    .line 83
    .line 84
    iget-object v0, p0, Lc8/p;->e:Lc8/o;

    .line 85
    .line 86
    if-eqz v0, :cond_0

    .line 87
    .line 88
    const/4 v1, 0x0

    .line 89
    invoke-virtual {v0, v1}, Lc8/o;->a(I)V

    .line 90
    .line 91
    .line 92
    :cond_0
    invoke-virtual {p0}, Lc8/p;->f()V

    .line 93
    .line 94
    .line 95
    :cond_1
    return-void
.end method

.method public final w(Ljava/nio/ByteBuffer;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v1, 0x0

    .line 10
    :goto_0
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 11
    .line 12
    .line 13
    invoke-virtual/range {p1 .. p1}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    return-void

    .line 20
    :cond_1
    iget-object v1, v0, Lc8/y;->u:Lc8/t;

    .line 21
    .line 22
    iget v1, v1, Lc8/t;->c:I

    .line 23
    .line 24
    if-eqz v1, :cond_2

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_2
    const-wide/16 v1, 0x14

    .line 28
    .line 29
    invoke-static {v1, v2}, Lw7/w;->D(J)J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    iget-object v1, v0, Lc8/y;->u:Lc8/t;

    .line 34
    .line 35
    iget v1, v1, Lc8/t;->e:I

    .line 36
    .line 37
    int-to-long v5, v1

    .line 38
    const-wide/32 v7, 0xf4240

    .line 39
    .line 40
    .line 41
    sget-object v9, Ljava/math/RoundingMode;->UP:Ljava/math/RoundingMode;

    .line 42
    .line 43
    invoke-static/range {v3 .. v9}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 44
    .line 45
    .line 46
    move-result-wide v1

    .line 47
    long-to-int v1, v1

    .line 48
    invoke-virtual {v0}, Lc8/y;->k()J

    .line 49
    .line 50
    .line 51
    move-result-wide v2

    .line 52
    int-to-long v4, v1

    .line 53
    cmp-long v6, v2, v4

    .line 54
    .line 55
    if-ltz v6, :cond_3

    .line 56
    .line 57
    :goto_1
    move-object/from16 v3, p1

    .line 58
    .line 59
    goto/16 :goto_8

    .line 60
    .line 61
    :cond_3
    iget-object v6, v0, Lc8/y;->u:Lc8/t;

    .line 62
    .line 63
    iget v7, v6, Lc8/t;->g:I

    .line 64
    .line 65
    iget v6, v6, Lc8/t;->d:I

    .line 66
    .line 67
    long-to-int v2, v2

    .line 68
    invoke-virtual/range {p1 .. p1}, Ljava/nio/Buffer;->remaining()I

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    invoke-static {v3}, Ljava/nio/ByteBuffer;->allocateDirect(I)Ljava/nio/ByteBuffer;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    invoke-static {}, Ljava/nio/ByteOrder;->nativeOrder()Ljava/nio/ByteOrder;

    .line 77
    .line 78
    .line 79
    move-result-object v8

    .line 80
    invoke-virtual {v3, v8}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    invoke-virtual/range {p1 .. p1}, Ljava/nio/Buffer;->position()I

    .line 85
    .line 86
    .line 87
    move-result v8

    .line 88
    :cond_4
    :goto_2
    invoke-virtual/range {p1 .. p1}, Ljava/nio/Buffer;->hasRemaining()Z

    .line 89
    .line 90
    .line 91
    move-result v9

    .line 92
    if-eqz v9, :cond_17

    .line 93
    .line 94
    if-ge v2, v1, :cond_17

    .line 95
    .line 96
    const/high16 v12, 0x50000000

    .line 97
    .line 98
    const/high16 v13, 0x10000000

    .line 99
    .line 100
    const/16 v14, 0x16

    .line 101
    .line 102
    const/16 v15, 0x15

    .line 103
    .line 104
    const/high16 v16, 0x4f000000

    .line 105
    .line 106
    const/4 v9, 0x4

    .line 107
    const/high16 v17, -0x31000000

    .line 108
    .line 109
    const/4 v10, 0x3

    .line 110
    const/4 v11, 0x2

    .line 111
    if-eq v7, v11, :cond_d

    .line 112
    .line 113
    if-eq v7, v10, :cond_c

    .line 114
    .line 115
    if-eq v7, v9, :cond_a

    .line 116
    .line 117
    if-eq v7, v15, :cond_9

    .line 118
    .line 119
    if-eq v7, v14, :cond_8

    .line 120
    .line 121
    if-eq v7, v13, :cond_7

    .line 122
    .line 123
    if-eq v7, v12, :cond_6

    .line 124
    .line 125
    const/high16 v12, 0x60000000

    .line 126
    .line 127
    if-ne v7, v12, :cond_5

    .line 128
    .line 129
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 130
    .line 131
    .line 132
    move-result v12

    .line 133
    and-int/lit16 v12, v12, 0xff

    .line 134
    .line 135
    shl-int/lit8 v12, v12, 0x18

    .line 136
    .line 137
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 138
    .line 139
    .line 140
    move-result v13

    .line 141
    and-int/lit16 v13, v13, 0xff

    .line 142
    .line 143
    shl-int/lit8 v13, v13, 0x10

    .line 144
    .line 145
    or-int/2addr v12, v13

    .line 146
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 147
    .line 148
    .line 149
    move-result v13

    .line 150
    and-int/lit16 v13, v13, 0xff

    .line 151
    .line 152
    shl-int/lit8 v13, v13, 0x8

    .line 153
    .line 154
    or-int/2addr v12, v13

    .line 155
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 156
    .line 157
    .line 158
    move-result v13

    .line 159
    and-int/lit16 v13, v13, 0xff

    .line 160
    .line 161
    :goto_3
    or-int/2addr v12, v13

    .line 162
    goto/16 :goto_6

    .line 163
    .line 164
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 165
    .line 166
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :cond_6
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 171
    .line 172
    .line 173
    move-result v12

    .line 174
    and-int/lit16 v12, v12, 0xff

    .line 175
    .line 176
    shl-int/lit8 v12, v12, 0x18

    .line 177
    .line 178
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 179
    .line 180
    .line 181
    move-result v13

    .line 182
    and-int/lit16 v13, v13, 0xff

    .line 183
    .line 184
    shl-int/lit8 v13, v13, 0x10

    .line 185
    .line 186
    or-int/2addr v12, v13

    .line 187
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 188
    .line 189
    .line 190
    move-result v13

    .line 191
    and-int/lit16 v13, v13, 0xff

    .line 192
    .line 193
    shl-int/lit8 v13, v13, 0x8

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_7
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 197
    .line 198
    .line 199
    move-result v12

    .line 200
    and-int/lit16 v12, v12, 0xff

    .line 201
    .line 202
    shl-int/lit8 v12, v12, 0x18

    .line 203
    .line 204
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 205
    .line 206
    .line 207
    move-result v13

    .line 208
    and-int/lit16 v13, v13, 0xff

    .line 209
    .line 210
    shl-int/lit8 v13, v13, 0x10

    .line 211
    .line 212
    goto :goto_3

    .line 213
    :cond_8
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 214
    .line 215
    .line 216
    move-result v12

    .line 217
    and-int/lit16 v12, v12, 0xff

    .line 218
    .line 219
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 220
    .line 221
    .line 222
    move-result v13

    .line 223
    and-int/lit16 v13, v13, 0xff

    .line 224
    .line 225
    shl-int/lit8 v13, v13, 0x8

    .line 226
    .line 227
    or-int/2addr v12, v13

    .line 228
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 229
    .line 230
    .line 231
    move-result v13

    .line 232
    and-int/lit16 v13, v13, 0xff

    .line 233
    .line 234
    shl-int/lit8 v13, v13, 0x10

    .line 235
    .line 236
    or-int/2addr v12, v13

    .line 237
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 238
    .line 239
    .line 240
    move-result v13

    .line 241
    :goto_4
    and-int/lit16 v13, v13, 0xff

    .line 242
    .line 243
    shl-int/lit8 v13, v13, 0x18

    .line 244
    .line 245
    goto :goto_3

    .line 246
    :cond_9
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 247
    .line 248
    .line 249
    move-result v12

    .line 250
    and-int/lit16 v12, v12, 0xff

    .line 251
    .line 252
    shl-int/lit8 v12, v12, 0x8

    .line 253
    .line 254
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 255
    .line 256
    .line 257
    move-result v13

    .line 258
    and-int/lit16 v13, v13, 0xff

    .line 259
    .line 260
    shl-int/lit8 v13, v13, 0x10

    .line 261
    .line 262
    or-int/2addr v12, v13

    .line 263
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 264
    .line 265
    .line 266
    move-result v13

    .line 267
    goto :goto_4

    .line 268
    :cond_a
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->getFloat()F

    .line 269
    .line 270
    .line 271
    move-result v12

    .line 272
    const/high16 v13, -0x40800000    # -1.0f

    .line 273
    .line 274
    const/high16 v14, 0x3f800000    # 1.0f

    .line 275
    .line 276
    invoke-static {v12, v13, v14}, Lw7/w;->f(FFF)F

    .line 277
    .line 278
    .line 279
    move-result v12

    .line 280
    const/4 v13, 0x0

    .line 281
    cmpg-float v13, v12, v13

    .line 282
    .line 283
    if-gez v13, :cond_b

    .line 284
    .line 285
    neg-float v12, v12

    .line 286
    mul-float v12, v12, v17

    .line 287
    .line 288
    :goto_5
    float-to-int v12, v12

    .line 289
    goto :goto_6

    .line 290
    :cond_b
    mul-float v12, v12, v16

    .line 291
    .line 292
    goto :goto_5

    .line 293
    :cond_c
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 294
    .line 295
    .line 296
    move-result v12

    .line 297
    and-int/lit16 v12, v12, 0xff

    .line 298
    .line 299
    shl-int/lit8 v12, v12, 0x18

    .line 300
    .line 301
    goto :goto_6

    .line 302
    :cond_d
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 303
    .line 304
    .line 305
    move-result v12

    .line 306
    and-int/lit16 v12, v12, 0xff

    .line 307
    .line 308
    shl-int/lit8 v12, v12, 0x10

    .line 309
    .line 310
    invoke-virtual/range {p1 .. p1}, Ljava/nio/ByteBuffer;->get()B

    .line 311
    .line 312
    .line 313
    move-result v13

    .line 314
    goto :goto_4

    .line 315
    :goto_6
    int-to-long v12, v12

    .line 316
    int-to-long v9, v2

    .line 317
    mul-long/2addr v12, v9

    .line 318
    div-long/2addr v12, v4

    .line 319
    long-to-int v9, v12

    .line 320
    if-eq v7, v11, :cond_16

    .line 321
    .line 322
    const/4 v10, 0x3

    .line 323
    if-eq v7, v10, :cond_15

    .line 324
    .line 325
    const/4 v14, 0x4

    .line 326
    if-eq v7, v14, :cond_13

    .line 327
    .line 328
    if-eq v7, v15, :cond_12

    .line 329
    .line 330
    const/16 v10, 0x16

    .line 331
    .line 332
    if-eq v7, v10, :cond_11

    .line 333
    .line 334
    const/high16 v10, 0x10000000

    .line 335
    .line 336
    if-eq v7, v10, :cond_10

    .line 337
    .line 338
    const/high16 v10, 0x50000000

    .line 339
    .line 340
    if-eq v7, v10, :cond_f

    .line 341
    .line 342
    const/high16 v12, 0x60000000

    .line 343
    .line 344
    if-ne v7, v12, :cond_e

    .line 345
    .line 346
    shr-int/lit8 v10, v9, 0x18

    .line 347
    .line 348
    int-to-byte v10, v10

    .line 349
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 350
    .line 351
    .line 352
    shr-int/lit8 v10, v9, 0x10

    .line 353
    .line 354
    int-to-byte v10, v10

    .line 355
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 356
    .line 357
    .line 358
    shr-int/lit8 v10, v9, 0x8

    .line 359
    .line 360
    int-to-byte v10, v10

    .line 361
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 362
    .line 363
    .line 364
    int-to-byte v9, v9

    .line 365
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 366
    .line 367
    .line 368
    goto/16 :goto_7

    .line 369
    .line 370
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 371
    .line 372
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 373
    .line 374
    .line 375
    throw v0

    .line 376
    :cond_f
    shr-int/lit8 v10, v9, 0x18

    .line 377
    .line 378
    int-to-byte v10, v10

    .line 379
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 380
    .line 381
    .line 382
    shr-int/lit8 v10, v9, 0x10

    .line 383
    .line 384
    int-to-byte v10, v10

    .line 385
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 386
    .line 387
    .line 388
    shr-int/lit8 v9, v9, 0x8

    .line 389
    .line 390
    int-to-byte v9, v9

    .line 391
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 392
    .line 393
    .line 394
    goto :goto_7

    .line 395
    :cond_10
    shr-int/lit8 v10, v9, 0x18

    .line 396
    .line 397
    int-to-byte v10, v10

    .line 398
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 399
    .line 400
    .line 401
    shr-int/lit8 v9, v9, 0x10

    .line 402
    .line 403
    int-to-byte v9, v9

    .line 404
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 405
    .line 406
    .line 407
    goto :goto_7

    .line 408
    :cond_11
    int-to-byte v10, v9

    .line 409
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 410
    .line 411
    .line 412
    shr-int/lit8 v10, v9, 0x8

    .line 413
    .line 414
    int-to-byte v10, v10

    .line 415
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 416
    .line 417
    .line 418
    shr-int/lit8 v10, v9, 0x10

    .line 419
    .line 420
    int-to-byte v10, v10

    .line 421
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 422
    .line 423
    .line 424
    shr-int/lit8 v9, v9, 0x18

    .line 425
    .line 426
    int-to-byte v9, v9

    .line 427
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 428
    .line 429
    .line 430
    goto :goto_7

    .line 431
    :cond_12
    shr-int/lit8 v10, v9, 0x8

    .line 432
    .line 433
    int-to-byte v10, v10

    .line 434
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 435
    .line 436
    .line 437
    shr-int/lit8 v10, v9, 0x10

    .line 438
    .line 439
    int-to-byte v10, v10

    .line 440
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 441
    .line 442
    .line 443
    shr-int/lit8 v9, v9, 0x18

    .line 444
    .line 445
    int-to-byte v9, v9

    .line 446
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 447
    .line 448
    .line 449
    goto :goto_7

    .line 450
    :cond_13
    if-gez v9, :cond_14

    .line 451
    .line 452
    int-to-float v9, v9

    .line 453
    neg-float v9, v9

    .line 454
    div-float v9, v9, v17

    .line 455
    .line 456
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 457
    .line 458
    .line 459
    goto :goto_7

    .line 460
    :cond_14
    int-to-float v9, v9

    .line 461
    div-float v9, v9, v16

    .line 462
    .line 463
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 464
    .line 465
    .line 466
    goto :goto_7

    .line 467
    :cond_15
    shr-int/lit8 v9, v9, 0x18

    .line 468
    .line 469
    int-to-byte v9, v9

    .line 470
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 471
    .line 472
    .line 473
    goto :goto_7

    .line 474
    :cond_16
    shr-int/lit8 v10, v9, 0x10

    .line 475
    .line 476
    int-to-byte v10, v10

    .line 477
    invoke-virtual {v3, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 478
    .line 479
    .line 480
    shr-int/lit8 v9, v9, 0x18

    .line 481
    .line 482
    int-to-byte v9, v9

    .line 483
    invoke-virtual {v3, v9}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 484
    .line 485
    .line 486
    :goto_7
    invoke-virtual/range {p1 .. p1}, Ljava/nio/Buffer;->position()I

    .line 487
    .line 488
    .line 489
    move-result v9

    .line 490
    add-int v10, v8, v6

    .line 491
    .line 492
    if-ne v9, v10, :cond_4

    .line 493
    .line 494
    add-int/lit8 v2, v2, 0x1

    .line 495
    .line 496
    invoke-virtual/range {p1 .. p1}, Ljava/nio/Buffer;->position()I

    .line 497
    .line 498
    .line 499
    move-result v8

    .line 500
    goto/16 :goto_2

    .line 501
    .line 502
    :cond_17
    move-object/from16 v1, p1

    .line 503
    .line 504
    invoke-virtual {v3, v1}, Ljava/nio/ByteBuffer;->put(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;

    .line 505
    .line 506
    .line 507
    invoke-virtual {v3}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 508
    .line 509
    .line 510
    :goto_8
    iput-object v3, v0, Lc8/y;->Q:Ljava/nio/ByteBuffer;

    .line 511
    .line 512
    return-void
.end method
