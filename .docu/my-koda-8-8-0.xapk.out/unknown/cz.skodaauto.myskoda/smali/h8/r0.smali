.class public final Lh8/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/z;
.implements Lo8/q;
.implements Lk8/h;
.implements Lk8/j;


# static fields
.field public static final S:Ljava/util/Map;

.field public static final T:Lt7/o;


# instance fields
.field public A:Z

.field public B:Z

.field public C:Lcom/google/firebase/messaging/w;

.field public D:Lo8/c0;

.field public E:J

.field public F:Z

.field public G:I

.field public H:Z

.field public I:Z

.field public J:Z

.field public K:I

.field public L:Z

.field public M:J

.field public N:J

.field public O:Z

.field public P:I

.field public Q:Z

.field public R:Z

.field public final d:Landroid/net/Uri;

.field public final e:Ly7/h;

.field public final f:Ld8/j;

.field public final g:Lmb/e;

.field public final h:Ld8/f;

.field public final i:Ld8/f;

.field public final j:Lh8/u0;

.field public final k:Lk8/e;

.field public final l:J

.field public final m:Lt7/o;

.field public final n:J

.field public final o:Lk8/l;

.field public final p:Lgw0/c;

.field public final q:Lw7/e;

.field public final r:Lh8/m0;

.field public final s:Lh8/m0;

.field public final t:Landroid/os/Handler;

.field public u:Lh8/y;

.field public v:Lb9/b;

.field public w:[Lh8/x0;

.field public x:[Lh8/q0;

.field public y:Z

.field public z:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "Icy-MetaData"

    .line 7
    .line 8
    const-string v2, "1"

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lh8/r0;->S:Ljava/util/Map;

    .line 18
    .line 19
    new-instance v0, Lt7/n;

    .line 20
    .line 21
    invoke-direct {v0}, Lt7/n;-><init>()V

    .line 22
    .line 23
    .line 24
    const-string v1, "icy"

    .line 25
    .line 26
    iput-object v1, v0, Lt7/n;->a:Ljava/lang/String;

    .line 27
    .line 28
    const-string v1, "application/x-icy"

    .line 29
    .line 30
    invoke-static {v1}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iput-object v1, v0, Lt7/n;->m:Ljava/lang/String;

    .line 35
    .line 36
    new-instance v1, Lt7/o;

    .line 37
    .line 38
    invoke-direct {v1, v0}, Lt7/o;-><init>(Lt7/n;)V

    .line 39
    .line 40
    .line 41
    sput-object v1, Lh8/r0;->T:Lt7/o;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>(Landroid/net/Uri;Ly7/h;Lgw0/c;Ld8/j;Ld8/f;Lmb/e;Ld8/f;Lh8/u0;Lk8/e;ILt7/o;JLl8/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/r0;->d:Landroid/net/Uri;

    .line 5
    .line 6
    iput-object p2, p0, Lh8/r0;->e:Ly7/h;

    .line 7
    .line 8
    iput-object p4, p0, Lh8/r0;->f:Ld8/j;

    .line 9
    .line 10
    iput-object p5, p0, Lh8/r0;->i:Ld8/f;

    .line 11
    .line 12
    iput-object p6, p0, Lh8/r0;->g:Lmb/e;

    .line 13
    .line 14
    iput-object p7, p0, Lh8/r0;->h:Ld8/f;

    .line 15
    .line 16
    iput-object p8, p0, Lh8/r0;->j:Lh8/u0;

    .line 17
    .line 18
    iput-object p9, p0, Lh8/r0;->k:Lk8/e;

    .line 19
    .line 20
    int-to-long p1, p10

    .line 21
    iput-wide p1, p0, Lh8/r0;->l:J

    .line 22
    .line 23
    iput-object p11, p0, Lh8/r0;->m:Lt7/o;

    .line 24
    .line 25
    const/4 p1, 0x1

    .line 26
    if-eqz p14, :cond_0

    .line 27
    .line 28
    new-instance p2, Lk8/l;

    .line 29
    .line 30
    invoke-direct {p2, p14}, Lk8/l;-><init>(Ll8/a;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance p2, Lk8/l;

    .line 35
    .line 36
    const-string p4, "ProgressiveMediaPeriod"

    .line 37
    .line 38
    const-string p5, "ExoPlayer:Loader:"

    .line 39
    .line 40
    invoke-virtual {p5, p4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p4

    .line 44
    sget-object p5, Lw7/w;->a:Ljava/lang/String;

    .line 45
    .line 46
    new-instance p5, Ls6/a;

    .line 47
    .line 48
    invoke-direct {p5, p4, p1}, Ls6/a;-><init>(Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    invoke-static {p5}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 52
    .line 53
    .line 54
    move-result-object p4

    .line 55
    new-instance p5, Lj9/d;

    .line 56
    .line 57
    invoke-direct {p5, p1}, Lj9/d;-><init>(I)V

    .line 58
    .line 59
    .line 60
    new-instance p6, Ll8/a;

    .line 61
    .line 62
    invoke-direct {p6, p4, p5}, Ll8/a;-><init>(Ljava/util/concurrent/ExecutorService;Lj9/d;)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p2, p6}, Lk8/l;-><init>(Ll8/a;)V

    .line 66
    .line 67
    .line 68
    :goto_0
    iput-object p2, p0, Lh8/r0;->o:Lk8/l;

    .line 69
    .line 70
    iput-object p3, p0, Lh8/r0;->p:Lgw0/c;

    .line 71
    .line 72
    iput-wide p12, p0, Lh8/r0;->n:J

    .line 73
    .line 74
    new-instance p2, Lw7/e;

    .line 75
    .line 76
    invoke-direct {p2}, Lw7/e;-><init>()V

    .line 77
    .line 78
    .line 79
    iput-object p2, p0, Lh8/r0;->q:Lw7/e;

    .line 80
    .line 81
    new-instance p2, Lh8/m0;

    .line 82
    .line 83
    invoke-direct {p2, p0, p1}, Lh8/m0;-><init>(Lh8/r0;I)V

    .line 84
    .line 85
    .line 86
    iput-object p2, p0, Lh8/r0;->r:Lh8/m0;

    .line 87
    .line 88
    new-instance p2, Lh8/m0;

    .line 89
    .line 90
    const/4 p3, 0x2

    .line 91
    invoke-direct {p2, p0, p3}, Lh8/m0;-><init>(Lh8/r0;I)V

    .line 92
    .line 93
    .line 94
    iput-object p2, p0, Lh8/r0;->s:Lh8/m0;

    .line 95
    .line 96
    const/4 p2, 0x0

    .line 97
    invoke-static {p2}, Lw7/w;->k(Lm8/k;)Landroid/os/Handler;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    iput-object p2, p0, Lh8/r0;->t:Landroid/os/Handler;

    .line 102
    .line 103
    const/4 p2, 0x0

    .line 104
    new-array p3, p2, [Lh8/q0;

    .line 105
    .line 106
    iput-object p3, p0, Lh8/r0;->x:[Lh8/q0;

    .line 107
    .line 108
    new-array p2, p2, [Lh8/x0;

    .line 109
    .line 110
    iput-object p2, p0, Lh8/r0;->w:[Lh8/x0;

    .line 111
    .line 112
    const-wide p2, -0x7fffffffffffffffL    # -4.9E-324

    .line 113
    .line 114
    .line 115
    .line 116
    .line 117
    iput-wide p2, p0, Lh8/r0;->N:J

    .line 118
    .line 119
    iput p1, p0, Lh8/r0;->G:I

    .line 120
    .line 121
    return-void
.end method


# virtual methods
.method public final A(I)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Lh8/r0;->O:Z

    .line 5
    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    iget-boolean v0, p0, Lh8/r0;->A:Z

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 13
    .line 14
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, [Z

    .line 17
    .line 18
    aget-boolean v0, v0, p1

    .line 19
    .line 20
    if-eqz v0, :cond_3

    .line 21
    .line 22
    :cond_0
    iget-object v0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 23
    .line 24
    aget-object p1, v0, p1

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    invoke-virtual {p1, v0}, Lh8/x0;->i(Z)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const-wide/16 v1, 0x0

    .line 35
    .line 36
    iput-wide v1, p0, Lh8/r0;->N:J

    .line 37
    .line 38
    iput-boolean v0, p0, Lh8/r0;->O:Z

    .line 39
    .line 40
    const/4 p1, 0x1

    .line 41
    iput-boolean p1, p0, Lh8/r0;->I:Z

    .line 42
    .line 43
    iput-wide v1, p0, Lh8/r0;->M:J

    .line 44
    .line 45
    iput v0, p0, Lh8/r0;->P:I

    .line 46
    .line 47
    iget-object p1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 48
    .line 49
    array-length v1, p1

    .line 50
    move v2, v0

    .line 51
    :goto_0
    if-ge v2, v1, :cond_2

    .line 52
    .line 53
    aget-object v3, p1, v2

    .line 54
    .line 55
    invoke-virtual {v3, v0}, Lh8/x0;->l(Z)V

    .line 56
    .line 57
    .line 58
    add-int/lit8 v2, v2, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iget-object p1, p0, Lh8/r0;->u:Lh8/y;

    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    invoke-interface {p1, p0}, Lh8/y;->f(Lh8/z0;)V

    .line 67
    .line 68
    .line 69
    :cond_3
    :goto_1
    return-void
.end method

.method public final B(Lh8/q0;)Lo8/i0;
    .locals 5

    .line 1
    iget-object v0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    if-ge v1, v0, :cond_1

    .line 6
    .line 7
    iget-object v2, p0, Lh8/r0;->x:[Lh8/q0;

    .line 8
    .line 9
    aget-object v2, v2, v1

    .line 10
    .line 11
    invoke-virtual {p1, v2}, Lh8/q0;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 18
    .line 19
    aget-object p0, p0, v1

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    iget-boolean v1, p0, Lh8/r0;->y:Z

    .line 26
    .line 27
    if-eqz v1, :cond_2

    .line 28
    .line 29
    new-instance p0, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v0, "Extractor added new track (id="

    .line 32
    .line 33
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget p1, p1, Lh8/q0;->a:I

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string p1, ") after finishing tracks."

    .line 42
    .line 43
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    const-string p1, "ProgressiveMediaPeriod"

    .line 51
    .line 52
    invoke-static {p1, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    new-instance p0, Lo8/n;

    .line 56
    .line 57
    invoke-direct {p0}, Lo8/n;-><init>()V

    .line 58
    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_2
    new-instance v1, Lh8/x0;

    .line 62
    .line 63
    iget-object v2, p0, Lh8/r0;->f:Ld8/j;

    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    iget-object v3, p0, Lh8/r0;->k:Lk8/e;

    .line 69
    .line 70
    iget-object v4, p0, Lh8/r0;->i:Ld8/f;

    .line 71
    .line 72
    invoke-direct {v1, v3, v2, v4}, Lh8/x0;-><init>(Lk8/e;Ld8/j;Ld8/f;)V

    .line 73
    .line 74
    .line 75
    iput-object p0, v1, Lh8/x0;->f:Lh8/r0;

    .line 76
    .line 77
    iget-object v2, p0, Lh8/r0;->x:[Lh8/q0;

    .line 78
    .line 79
    add-int/lit8 v3, v0, 0x1

    .line 80
    .line 81
    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    check-cast v2, [Lh8/q0;

    .line 86
    .line 87
    aput-object p1, v2, v0

    .line 88
    .line 89
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 90
    .line 91
    iput-object v2, p0, Lh8/r0;->x:[Lh8/q0;

    .line 92
    .line 93
    iget-object p1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 94
    .line 95
    invoke-static {p1, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    check-cast p1, [Lh8/x0;

    .line 100
    .line 101
    aput-object v1, p1, v0

    .line 102
    .line 103
    iput-object p1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 104
    .line 105
    return-object v1
.end method

.method public final C(Lo8/c0;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lh8/r0;->v:Lb9/b;

    .line 2
    .line 3
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    move-object v0, p1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-instance v0, Lo8/t;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2}, Lo8/t;-><init>(J)V

    .line 15
    .line 16
    .line 17
    :goto_0
    iput-object v0, p0, Lh8/r0;->D:Lo8/c0;

    .line 18
    .line 19
    invoke-interface {p1}, Lo8/c0;->l()J

    .line 20
    .line 21
    .line 22
    move-result-wide v3

    .line 23
    iput-wide v3, p0, Lh8/r0;->E:J

    .line 24
    .line 25
    iget-boolean v0, p0, Lh8/r0;->L:Z

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    if-nez v0, :cond_1

    .line 29
    .line 30
    invoke-interface {p1}, Lo8/c0;->l()J

    .line 31
    .line 32
    .line 33
    move-result-wide v4

    .line 34
    cmp-long v0, v4, v1

    .line 35
    .line 36
    if-nez v0, :cond_1

    .line 37
    .line 38
    move v0, v3

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/4 v0, 0x0

    .line 41
    :goto_1
    iput-boolean v0, p0, Lh8/r0;->F:Z

    .line 42
    .line 43
    if-eqz v0, :cond_2

    .line 44
    .line 45
    const/4 v3, 0x7

    .line 46
    :cond_2
    iput v3, p0, Lh8/r0;->G:I

    .line 47
    .line 48
    iget-boolean v1, p0, Lh8/r0;->z:Z

    .line 49
    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    iget-object v1, p0, Lh8/r0;->j:Lh8/u0;

    .line 53
    .line 54
    iget-wide v2, p0, Lh8/r0;->E:J

    .line 55
    .line 56
    invoke-virtual {v1, v2, v3, p1, v0}, Lh8/u0;->t(JLo8/c0;Z)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_3
    invoke-virtual {p0}, Lh8/r0;->y()V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final D()V
    .locals 12

    .line 1
    new-instance v0, Lh8/o0;

    .line 2
    .line 3
    iget-object v4, p0, Lh8/r0;->p:Lgw0/c;

    .line 4
    .line 5
    iget-object v6, p0, Lh8/r0;->q:Lw7/e;

    .line 6
    .line 7
    iget-object v2, p0, Lh8/r0;->d:Landroid/net/Uri;

    .line 8
    .line 9
    iget-object v3, p0, Lh8/r0;->e:Ly7/h;

    .line 10
    .line 11
    move-object v5, p0

    .line 12
    move-object v1, p0

    .line 13
    invoke-direct/range {v0 .. v6}, Lh8/o0;-><init>(Lh8/r0;Landroid/net/Uri;Ly7/h;Lgw0/c;Lh8/r0;Lw7/e;)V

    .line 14
    .line 15
    .line 16
    iget-boolean p0, v1, Lh8/r0;->z:Z

    .line 17
    .line 18
    const/4 v8, 0x0

    .line 19
    const/4 v9, 0x1

    .line 20
    if-eqz p0, :cond_2

    .line 21
    .line 22
    invoke-virtual {v1}, Lh8/r0;->x()Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 27
    .line 28
    .line 29
    iget-wide v2, v1, Lh8/r0;->E:J

    .line 30
    .line 31
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    cmp-long p0, v2, v4

    .line 37
    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    iget-wide v6, v1, Lh8/r0;->N:J

    .line 41
    .line 42
    cmp-long p0, v6, v2

    .line 43
    .line 44
    if-lez p0, :cond_0

    .line 45
    .line 46
    iput-boolean v9, v1, Lh8/r0;->Q:Z

    .line 47
    .line 48
    iput-wide v4, v1, Lh8/r0;->N:J

    .line 49
    .line 50
    return-void

    .line 51
    :cond_0
    iget-object p0, v1, Lh8/r0;->D:Lo8/c0;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    iget-wide v2, v1, Lh8/r0;->N:J

    .line 57
    .line 58
    invoke-interface {p0, v2, v3}, Lo8/c0;->e(J)Lo8/b0;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    iget-object p0, p0, Lo8/b0;->a:Lo8/d0;

    .line 63
    .line 64
    iget-wide v2, p0, Lo8/d0;->b:J

    .line 65
    .line 66
    iget-wide v6, v1, Lh8/r0;->N:J

    .line 67
    .line 68
    iget-object p0, v0, Lh8/o0;->f:Lo8/s;

    .line 69
    .line 70
    iput-wide v2, p0, Lo8/s;->a:J

    .line 71
    .line 72
    iput-wide v6, v0, Lh8/o0;->i:J

    .line 73
    .line 74
    iput-boolean v9, v0, Lh8/o0;->h:Z

    .line 75
    .line 76
    iput-boolean v8, v0, Lh8/o0;->l:Z

    .line 77
    .line 78
    iget-object p0, v1, Lh8/r0;->w:[Lh8/x0;

    .line 79
    .line 80
    array-length v2, p0

    .line 81
    move v3, v8

    .line 82
    :goto_0
    if-ge v3, v2, :cond_1

    .line 83
    .line 84
    aget-object v6, p0, v3

    .line 85
    .line 86
    iget-wide v10, v1, Lh8/r0;->N:J

    .line 87
    .line 88
    iput-wide v10, v6, Lh8/x0;->t:J

    .line 89
    .line 90
    add-int/lit8 v3, v3, 0x1

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_1
    iput-wide v4, v1, Lh8/r0;->N:J

    .line 94
    .line 95
    :cond_2
    invoke-virtual {v1}, Lh8/r0;->v()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    iput p0, v1, Lh8/r0;->P:I

    .line 100
    .line 101
    iget-object p0, v1, Lh8/r0;->g:Lmb/e;

    .line 102
    .line 103
    iget v2, v1, Lh8/r0;->G:I

    .line 104
    .line 105
    invoke-virtual {p0, v2}, Lmb/e;->q(I)I

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    move-object v4, v1

    .line 110
    iget-object v1, v4, Lh8/r0;->o:Lk8/l;

    .line 111
    .line 112
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    const/4 p0, 0x0

    .line 123
    iput-object p0, v1, Lk8/l;->c:Ljava/io/IOException;

    .line 124
    .line 125
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 126
    .line 127
    .line 128
    move-result-wide v6

    .line 129
    move-object v3, v0

    .line 130
    new-instance v0, Lk8/i;

    .line 131
    .line 132
    invoke-direct/range {v0 .. v7}, Lk8/i;-><init>(Lk8/l;Landroid/os/Looper;Lh8/o0;Lk8/h;IJ)V

    .line 133
    .line 134
    .line 135
    iget-object p0, v1, Lk8/l;->b:Lk8/i;

    .line 136
    .line 137
    if-nez p0, :cond_3

    .line 138
    .line 139
    move v8, v9

    .line 140
    :cond_3
    invoke-static {v8}, Lw7/a;->j(Z)V

    .line 141
    .line 142
    .line 143
    iput-object v0, v1, Lk8/l;->b:Lk8/i;

    .line 144
    .line 145
    invoke-virtual {v0}, Lk8/i;->b()V

    .line 146
    .line 147
    .line 148
    return-void
.end method

.method public final E()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh8/r0;->I:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lh8/r0;->x()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public final a()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh8/r0;->r()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public final b(JLa8/r1;)J
    .locals 17

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
    invoke-virtual {v0}, Lh8/r0;->u()V

    .line 8
    .line 9
    .line 10
    iget-object v4, v0, Lh8/r0;->D:Lo8/c0;

    .line 11
    .line 12
    invoke-interface {v4}, Lo8/c0;->g()Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    const-wide/16 v5, 0x0

    .line 17
    .line 18
    if-nez v4, :cond_0

    .line 19
    .line 20
    return-wide v5

    .line 21
    :cond_0
    iget-object v0, v0, Lh8/r0;->D:Lo8/c0;

    .line 22
    .line 23
    invoke-interface {v0, v1, v2}, Lo8/c0;->e(J)Lo8/b0;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iget-object v4, v0, Lo8/b0;->a:Lo8/d0;

    .line 28
    .line 29
    iget-wide v7, v4, Lo8/d0;->a:J

    .line 30
    .line 31
    iget-object v0, v0, Lo8/b0;->b:Lo8/d0;

    .line 32
    .line 33
    iget-wide v9, v0, Lo8/d0;->a:J

    .line 34
    .line 35
    iget-wide v11, v3, La8/r1;->b:J

    .line 36
    .line 37
    iget-wide v3, v3, La8/r1;->a:J

    .line 38
    .line 39
    cmp-long v0, v3, v5

    .line 40
    .line 41
    if-nez v0, :cond_1

    .line 42
    .line 43
    cmp-long v0, v11, v5

    .line 44
    .line 45
    if-nez v0, :cond_1

    .line 46
    .line 47
    return-wide v1

    .line 48
    :cond_1
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 49
    .line 50
    sub-long v13, v1, v3

    .line 51
    .line 52
    xor-long/2addr v3, v1

    .line 53
    xor-long v15, v1, v13

    .line 54
    .line 55
    and-long/2addr v3, v15

    .line 56
    cmp-long v0, v3, v5

    .line 57
    .line 58
    if-gez v0, :cond_2

    .line 59
    .line 60
    const-wide/high16 v13, -0x8000000000000000L

    .line 61
    .line 62
    :cond_2
    add-long v3, v1, v11

    .line 63
    .line 64
    xor-long v15, v1, v3

    .line 65
    .line 66
    xor-long/2addr v11, v3

    .line 67
    and-long/2addr v11, v15

    .line 68
    cmp-long v0, v11, v5

    .line 69
    .line 70
    if-gez v0, :cond_3

    .line 71
    .line 72
    const-wide v3, 0x7fffffffffffffffL

    .line 73
    .line 74
    .line 75
    .line 76
    .line 77
    :cond_3
    cmp-long v0, v13, v7

    .line 78
    .line 79
    const/4 v5, 0x0

    .line 80
    const/4 v6, 0x1

    .line 81
    if-gtz v0, :cond_4

    .line 82
    .line 83
    cmp-long v0, v7, v3

    .line 84
    .line 85
    if-gtz v0, :cond_4

    .line 86
    .line 87
    move v0, v6

    .line 88
    goto :goto_0

    .line 89
    :cond_4
    move v0, v5

    .line 90
    :goto_0
    cmp-long v11, v13, v9

    .line 91
    .line 92
    if-gtz v11, :cond_5

    .line 93
    .line 94
    cmp-long v3, v9, v3

    .line 95
    .line 96
    if-gtz v3, :cond_5

    .line 97
    .line 98
    move v5, v6

    .line 99
    :cond_5
    if-eqz v0, :cond_6

    .line 100
    .line 101
    if-eqz v5, :cond_6

    .line 102
    .line 103
    sub-long v3, v7, v1

    .line 104
    .line 105
    invoke-static {v3, v4}, Ljava/lang/Math;->abs(J)J

    .line 106
    .line 107
    .line 108
    move-result-wide v3

    .line 109
    sub-long v0, v9, v1

    .line 110
    .line 111
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(J)J

    .line 112
    .line 113
    .line 114
    move-result-wide v0

    .line 115
    cmp-long v0, v3, v0

    .line 116
    .line 117
    if-gtz v0, :cond_8

    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_6
    if-eqz v0, :cond_7

    .line 121
    .line 122
    :goto_1
    return-wide v7

    .line 123
    :cond_7
    if-eqz v5, :cond_9

    .line 124
    .line 125
    :cond_8
    return-wide v9

    .line 126
    :cond_9
    return-wide v13
.end method

.method public final c(Lo8/c0;)V
    .locals 2

    .line 1
    new-instance v0, Lh0/h0;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1, p0, p1}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lh8/r0;->t:Landroid/os/Handler;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final d(J)J
    .locals 11

    .line 1
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, [Z

    .line 9
    .line 10
    iget-object v1, p0, Lh8/r0;->D:Lo8/c0;

    .line 11
    .line 12
    invoke-interface {v1}, Lo8/c0;->g()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const-wide/16 p1, 0x0

    .line 20
    .line 21
    :goto_0
    const/4 v1, 0x0

    .line 22
    iput-boolean v1, p0, Lh8/r0;->I:Z

    .line 23
    .line 24
    iget-wide v2, p0, Lh8/r0;->M:J

    .line 25
    .line 26
    cmp-long v2, v2, p1

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    if-nez v2, :cond_1

    .line 30
    .line 31
    move v2, v3

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v2, v1

    .line 34
    :goto_1
    iput-wide p1, p0, Lh8/r0;->M:J

    .line 35
    .line 36
    invoke-virtual {p0}, Lh8/r0;->x()Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_2

    .line 41
    .line 42
    iput-wide p1, p0, Lh8/r0;->N:J

    .line 43
    .line 44
    return-wide p1

    .line 45
    :cond_2
    iget v4, p0, Lh8/r0;->G:I

    .line 46
    .line 47
    const/4 v5, 0x7

    .line 48
    if-eq v4, v5, :cond_b

    .line 49
    .line 50
    iget-boolean v4, p0, Lh8/r0;->Q:Z

    .line 51
    .line 52
    if-nez v4, :cond_3

    .line 53
    .line 54
    iget-object v4, p0, Lh8/r0;->o:Lk8/l;

    .line 55
    .line 56
    invoke-virtual {v4}, Lk8/l;->a()Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_b

    .line 61
    .line 62
    :cond_3
    iget-object v4, p0, Lh8/r0;->w:[Lh8/x0;

    .line 63
    .line 64
    array-length v4, v4

    .line 65
    move v5, v1

    .line 66
    :goto_2
    if-ge v5, v4, :cond_a

    .line 67
    .line 68
    iget-object v6, p0, Lh8/r0;->w:[Lh8/x0;

    .line 69
    .line 70
    aget-object v6, v6, v5

    .line 71
    .line 72
    iget v7, v6, Lh8/x0;->q:I

    .line 73
    .line 74
    iget v8, v6, Lh8/x0;->s:I

    .line 75
    .line 76
    add-int/2addr v8, v7

    .line 77
    if-nez v8, :cond_4

    .line 78
    .line 79
    if-eqz v2, :cond_4

    .line 80
    .line 81
    goto :goto_6

    .line 82
    :cond_4
    iget-boolean v8, p0, Lh8/r0;->B:Z

    .line 83
    .line 84
    if-eqz v8, :cond_7

    .line 85
    .line 86
    monitor-enter v6

    .line 87
    :try_start_0
    monitor-enter v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 88
    :try_start_1
    iput v1, v6, Lh8/x0;->s:I

    .line 89
    .line 90
    iget-object v8, v6, Lh8/x0;->a:Lh8/v0;

    .line 91
    .line 92
    iget-object v9, v8, Lh8/v0;->d:Lc1/i2;

    .line 93
    .line 94
    iput-object v9, v8, Lh8/v0;->e:Lc1/i2;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 95
    .line 96
    :try_start_2
    monitor-exit v6

    .line 97
    iget v8, v6, Lh8/x0;->q:I

    .line 98
    .line 99
    if-lt v7, v8, :cond_6

    .line 100
    .line 101
    iget v9, v6, Lh8/x0;->p:I

    .line 102
    .line 103
    add-int/2addr v9, v8

    .line 104
    if-le v7, v9, :cond_5

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_5
    const-wide/high16 v9, -0x8000000000000000L

    .line 108
    .line 109
    iput-wide v9, v6, Lh8/x0;->t:J

    .line 110
    .line 111
    sub-int/2addr v7, v8

    .line 112
    iput v7, v6, Lh8/x0;->s:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 113
    .line 114
    monitor-exit v6

    .line 115
    move v6, v3

    .line 116
    goto :goto_5

    .line 117
    :catchall_0
    move-exception p0

    .line 118
    goto :goto_4

    .line 119
    :cond_6
    :goto_3
    monitor-exit v6

    .line 120
    move v6, v1

    .line 121
    goto :goto_5

    .line 122
    :catchall_1
    move-exception p0

    .line 123
    :try_start_3
    monitor-exit v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 124
    :try_start_4
    throw p0

    .line 125
    :goto_4
    monitor-exit v6
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 126
    throw p0

    .line 127
    :cond_7
    iget-boolean v7, p0, Lh8/r0;->Q:Z

    .line 128
    .line 129
    invoke-virtual {v6, p1, p2, v7}, Lh8/x0;->m(JZ)Z

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    :goto_5
    if-nez v6, :cond_9

    .line 134
    .line 135
    aget-boolean v6, v0, v5

    .line 136
    .line 137
    if-nez v6, :cond_8

    .line 138
    .line 139
    iget-boolean v6, p0, Lh8/r0;->A:Z

    .line 140
    .line 141
    if-nez v6, :cond_9

    .line 142
    .line 143
    :cond_8
    move v3, v1

    .line 144
    goto :goto_7

    .line 145
    :cond_9
    :goto_6
    add-int/lit8 v5, v5, 0x1

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_a
    :goto_7
    if-eqz v3, :cond_b

    .line 149
    .line 150
    goto :goto_a

    .line 151
    :cond_b
    iput-boolean v1, p0, Lh8/r0;->O:Z

    .line 152
    .line 153
    iput-wide p1, p0, Lh8/r0;->N:J

    .line 154
    .line 155
    iput-boolean v1, p0, Lh8/r0;->Q:Z

    .line 156
    .line 157
    iput-boolean v1, p0, Lh8/r0;->J:Z

    .line 158
    .line 159
    iget-object v0, p0, Lh8/r0;->o:Lk8/l;

    .line 160
    .line 161
    invoke-virtual {v0}, Lk8/l;->a()Z

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    if-eqz v0, :cond_d

    .line 166
    .line 167
    iget-object v0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 168
    .line 169
    array-length v2, v0

    .line 170
    move v3, v1

    .line 171
    :goto_8
    if-ge v3, v2, :cond_c

    .line 172
    .line 173
    aget-object v4, v0, v3

    .line 174
    .line 175
    invoke-virtual {v4}, Lh8/x0;->f()V

    .line 176
    .line 177
    .line 178
    add-int/lit8 v3, v3, 0x1

    .line 179
    .line 180
    goto :goto_8

    .line 181
    :cond_c
    iget-object p0, p0, Lh8/r0;->o:Lk8/l;

    .line 182
    .line 183
    iget-object p0, p0, Lk8/l;->b:Lk8/i;

    .line 184
    .line 185
    invoke-static {p0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {p0, v1}, Lk8/i;->a(Z)V

    .line 189
    .line 190
    .line 191
    return-wide p1

    .line 192
    :cond_d
    iget-object v0, p0, Lh8/r0;->o:Lk8/l;

    .line 193
    .line 194
    const/4 v2, 0x0

    .line 195
    iput-object v2, v0, Lk8/l;->c:Ljava/io/IOException;

    .line 196
    .line 197
    iget-object p0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 198
    .line 199
    array-length v0, p0

    .line 200
    move v2, v1

    .line 201
    :goto_9
    if-ge v2, v0, :cond_e

    .line 202
    .line 203
    aget-object v3, p0, v2

    .line 204
    .line 205
    invoke-virtual {v3, v1}, Lh8/x0;->l(Z)V

    .line 206
    .line 207
    .line 208
    add-int/lit8 v2, v2, 0x1

    .line 209
    .line 210
    goto :goto_9

    .line 211
    :cond_e
    :goto_a
    return-wide p1
.end method

.method public final e()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/r0;->o:Lk8/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Lk8/l;->a()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lh8/r0;->q:Lw7/e;

    .line 10
    .line 11
    monitor-enter p0

    .line 12
    :try_start_0
    iget-boolean v0, p0, Lw7/e;->b:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    .line 14
    monitor-exit p0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :catchall_0
    move-exception v0

    .line 20
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    throw v0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final f(Lh8/o0;JI)V
    .locals 11

    .line 1
    iget-object p2, p1, Lh8/o0;->b:Ly7/y;

    .line 2
    .line 3
    if-nez p4, :cond_0

    .line 4
    .line 5
    new-instance p2, Lh8/s;

    .line 6
    .line 7
    iget-object p3, p1, Lh8/o0;->j:Ly7/j;

    .line 8
    .line 9
    iget-object p3, p3, Ly7/j;->a:Landroid/net/Uri;

    .line 10
    .line 11
    sget-object p3, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 12
    .line 13
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p3, Lh8/s;

    .line 18
    .line 19
    iget-object p2, p2, Ly7/y;->f:Landroid/net/Uri;

    .line 20
    .line 21
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    move-object p2, p3

    .line 25
    :goto_0
    iget-wide v0, p1, Lh8/o0;->i:J

    .line 26
    .line 27
    iget-wide v2, p0, Lh8/r0;->E:J

    .line 28
    .line 29
    new-instance v4, Lh8/x;

    .line 30
    .line 31
    invoke-static {v0, v1}, Lw7/w;->N(J)J

    .line 32
    .line 33
    .line 34
    move-result-wide v7

    .line 35
    invoke-static {v2, v3}, Lw7/w;->N(J)J

    .line 36
    .line 37
    .line 38
    move-result-wide v9

    .line 39
    const/4 v5, -0x1

    .line 40
    const/4 v6, 0x0

    .line 41
    invoke-direct/range {v4 .. v10}, Lh8/x;-><init>(ILt7/o;JJ)V

    .line 42
    .line 43
    .line 44
    new-instance p1, Lh8/d0;

    .line 45
    .line 46
    iget-object p0, p0, Lh8/r0;->h:Ld8/f;

    .line 47
    .line 48
    invoke-direct {p1, p0, p2, v4, p4}, Lh8/d0;-><init>(Ld8/f;Lh8/s;Lh8/x;I)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, p1}, Ld8/f;->a(Lw7/f;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final g()J
    .locals 3

    .line 1
    iget-boolean v0, p0, Lh8/r0;->J:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lh8/r0;->J:Z

    .line 7
    .line 8
    iget-wide v0, p0, Lh8/r0;->M:J

    .line 9
    .line 10
    return-wide v0

    .line 11
    :cond_0
    iget-boolean v0, p0, Lh8/r0;->I:Z

    .line 12
    .line 13
    if-eqz v0, :cond_2

    .line 14
    .line 15
    iget-boolean v0, p0, Lh8/r0;->Q:Z

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0}, Lh8/r0;->v()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iget v2, p0, Lh8/r0;->P:I

    .line 24
    .line 25
    if-le v0, v2, :cond_2

    .line 26
    .line 27
    :cond_1
    iput-boolean v1, p0, Lh8/r0;->I:Z

    .line 28
    .line 29
    iget-wide v0, p0, Lh8/r0;->M:J

    .line 30
    .line 31
    return-wide v0

    .line 32
    :cond_2
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    return-wide v0
.end method

.method public final h(Lh8/y;J)V
    .locals 5

    .line 1
    iput-object p1, p0, Lh8/r0;->u:Lh8/y;

    .line 2
    .line 3
    iget-object p1, p0, Lh8/r0;->m:Lt7/o;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x3

    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {p0, v1, v0}, Lh8/r0;->q(II)Lo8/i0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {v0, p1}, Lo8/i0;->c(Lt7/o;)V

    .line 14
    .line 15
    .line 16
    new-instance p1, Lo8/z;

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    new-array v2, v0, [J

    .line 20
    .line 21
    const-wide/16 v3, 0x0

    .line 22
    .line 23
    aput-wide v3, v2, v1

    .line 24
    .line 25
    new-array v0, v0, [J

    .line 26
    .line 27
    aput-wide v3, v0, v1

    .line 28
    .line 29
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    invoke-direct {p1, v3, v4, v2, v0}, Lo8/z;-><init>(J[J[J)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lh8/r0;->C(Lo8/c0;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Lh8/r0;->m()V

    .line 41
    .line 42
    .line 43
    iput-wide p2, p0, Lh8/r0;->N:J

    .line 44
    .line 45
    return-void

    .line 46
    :cond_0
    iget-object p1, p0, Lh8/r0;->q:Lw7/e;

    .line 47
    .line 48
    invoke-virtual {p1}, Lw7/e;->c()Z

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Lh8/r0;->D()V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final i(Lh8/o0;Z)V
    .locals 13

    .line 1
    iget-object v0, p1, Lh8/o0;->b:Ly7/y;

    .line 2
    .line 3
    new-instance v1, Lh8/s;

    .line 4
    .line 5
    iget-object v0, v0, Ly7/y;->f:Landroid/net/Uri;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lh8/r0;->g:Lmb/e;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    iget-wide v2, p1, Lh8/o0;->i:J

    .line 16
    .line 17
    iget-wide v4, p0, Lh8/r0;->E:J

    .line 18
    .line 19
    new-instance v6, Lh8/x;

    .line 20
    .line 21
    invoke-static {v2, v3}, Lw7/w;->N(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide v9

    .line 25
    invoke-static {v4, v5}, Lw7/w;->N(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide v11

    .line 29
    const/4 v7, -0x1

    .line 30
    const/4 v8, 0x0

    .line 31
    invoke-direct/range {v6 .. v12}, Lh8/x;-><init>(ILt7/o;JJ)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lh8/e0;

    .line 35
    .line 36
    const/4 v0, 0x1

    .line 37
    iget-object v2, p0, Lh8/r0;->h:Ld8/f;

    .line 38
    .line 39
    invoke-direct {p1, v2, v1, v6, v0}, Lh8/e0;-><init>(Ld8/f;Lh8/s;Lh8/x;I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2, p1}, Ld8/f;->a(Lw7/f;)V

    .line 43
    .line 44
    .line 45
    if-nez p2, :cond_1

    .line 46
    .line 47
    iget-object p1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 48
    .line 49
    array-length p2, p1

    .line 50
    const/4 v0, 0x0

    .line 51
    move v1, v0

    .line 52
    :goto_0
    if-ge v1, p2, :cond_0

    .line 53
    .line 54
    aget-object v2, p1, v1

    .line 55
    .line 56
    invoke-virtual {v2, v0}, Lh8/x0;->l(Z)V

    .line 57
    .line 58
    .line 59
    add-int/lit8 v1, v1, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    iget p1, p0, Lh8/r0;->K:I

    .line 63
    .line 64
    if-lez p1, :cond_1

    .line 65
    .line 66
    iget-object p1, p0, Lh8/r0;->u:Lh8/y;

    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    invoke-interface {p1, p0}, Lh8/y;->f(Lh8/z0;)V

    .line 72
    .line 73
    .line 74
    :cond_1
    return-void
.end method

.method public final j(Lh8/o0;Ljava/io/IOException;I)Lin/p;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v4, p2

    .line 6
    .line 7
    iget-object v2, v1, Lh8/o0;->b:Ly7/y;

    .line 8
    .line 9
    new-instance v3, Lh8/s;

    .line 10
    .line 11
    iget-object v2, v2, Ly7/y;->f:Landroid/net/Uri;

    .line 12
    .line 13
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, v0, Lh8/r0;->g:Lmb/e;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    instance-of v2, v4, Lt7/e0;

    .line 24
    .line 25
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    const/4 v7, 0x1

    .line 31
    if-nez v2, :cond_2

    .line 32
    .line 33
    instance-of v2, v4, Ljava/io/FileNotFoundException;

    .line 34
    .line 35
    if-nez v2, :cond_2

    .line 36
    .line 37
    instance-of v2, v4, Ly7/r;

    .line 38
    .line 39
    if-nez v2, :cond_2

    .line 40
    .line 41
    instance-of v2, v4, Lk8/k;

    .line 42
    .line 43
    if-nez v2, :cond_2

    .line 44
    .line 45
    sget v2, Ly7/i;->e:I

    .line 46
    .line 47
    move-object v2, v4

    .line 48
    :goto_0
    if-eqz v2, :cond_1

    .line 49
    .line 50
    instance-of v8, v2, Ly7/i;

    .line 51
    .line 52
    if-eqz v8, :cond_0

    .line 53
    .line 54
    move-object v8, v2

    .line 55
    check-cast v8, Ly7/i;

    .line 56
    .line 57
    iget v8, v8, Ly7/i;->d:I

    .line 58
    .line 59
    const/16 v9, 0x7d8

    .line 60
    .line 61
    if-ne v8, v9, :cond_0

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    goto :goto_0

    .line 69
    :cond_1
    add-int/lit8 v2, p3, -0x1

    .line 70
    .line 71
    mul-int/lit16 v2, v2, 0x3e8

    .line 72
    .line 73
    const/16 v8, 0x1388

    .line 74
    .line 75
    invoke-static {v2, v8}, Ljava/lang/Math;->min(II)I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    int-to-long v8, v2

    .line 80
    goto :goto_2

    .line 81
    :cond_2
    :goto_1
    move-wide v8, v5

    .line 82
    :goto_2
    cmp-long v2, v8, v5

    .line 83
    .line 84
    const/4 v10, 0x0

    .line 85
    if-nez v2, :cond_3

    .line 86
    .line 87
    sget-object v2, Lk8/l;->e:Lin/p;

    .line 88
    .line 89
    :goto_3
    move-object v6, v2

    .line 90
    goto :goto_8

    .line 91
    :cond_3
    invoke-virtual {v0}, Lh8/r0;->v()I

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    iget v11, v0, Lh8/r0;->P:I

    .line 96
    .line 97
    if-le v2, v11, :cond_4

    .line 98
    .line 99
    move v11, v7

    .line 100
    goto :goto_4

    .line 101
    :cond_4
    move v11, v10

    .line 102
    :goto_4
    iget-boolean v12, v0, Lh8/r0;->L:Z

    .line 103
    .line 104
    if-nez v12, :cond_8

    .line 105
    .line 106
    iget-object v12, v0, Lh8/r0;->D:Lo8/c0;

    .line 107
    .line 108
    if-eqz v12, :cond_5

    .line 109
    .line 110
    invoke-interface {v12}, Lo8/c0;->l()J

    .line 111
    .line 112
    .line 113
    move-result-wide v12

    .line 114
    cmp-long v5, v12, v5

    .line 115
    .line 116
    if-eqz v5, :cond_5

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_5
    iget-boolean v2, v0, Lh8/r0;->z:Z

    .line 120
    .line 121
    if-eqz v2, :cond_6

    .line 122
    .line 123
    invoke-virtual {v0}, Lh8/r0;->E()Z

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    if-nez v2, :cond_6

    .line 128
    .line 129
    iput-boolean v7, v0, Lh8/r0;->O:Z

    .line 130
    .line 131
    sget-object v2, Lk8/l;->d:Lin/p;

    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_6
    iget-boolean v2, v0, Lh8/r0;->z:Z

    .line 135
    .line 136
    iput-boolean v2, v0, Lh8/r0;->I:Z

    .line 137
    .line 138
    const-wide/16 v5, 0x0

    .line 139
    .line 140
    iput-wide v5, v0, Lh8/r0;->M:J

    .line 141
    .line 142
    iput v10, v0, Lh8/r0;->P:I

    .line 143
    .line 144
    iget-object v2, v0, Lh8/r0;->w:[Lh8/x0;

    .line 145
    .line 146
    array-length v12, v2

    .line 147
    move v13, v10

    .line 148
    :goto_5
    if-ge v13, v12, :cond_7

    .line 149
    .line 150
    aget-object v14, v2, v13

    .line 151
    .line 152
    invoke-virtual {v14, v10}, Lh8/x0;->l(Z)V

    .line 153
    .line 154
    .line 155
    add-int/lit8 v13, v13, 0x1

    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_7
    iget-object v2, v1, Lh8/o0;->f:Lo8/s;

    .line 159
    .line 160
    iput-wide v5, v2, Lo8/s;->a:J

    .line 161
    .line 162
    iput-wide v5, v1, Lh8/o0;->i:J

    .line 163
    .line 164
    iput-boolean v7, v1, Lh8/o0;->h:Z

    .line 165
    .line 166
    iput-boolean v10, v1, Lh8/o0;->l:Z

    .line 167
    .line 168
    goto :goto_7

    .line 169
    :cond_8
    :goto_6
    iput v2, v0, Lh8/r0;->P:I

    .line 170
    .line 171
    :goto_7
    new-instance v2, Lin/p;

    .line 172
    .line 173
    invoke-direct {v2, v11, v8, v9}, Lin/p;-><init>(IJ)V

    .line 174
    .line 175
    .line 176
    goto :goto_3

    .line 177
    :goto_8
    iget v2, v6, Lin/p;->d:I

    .line 178
    .line 179
    if-eqz v2, :cond_9

    .line 180
    .line 181
    if-ne v2, v7, :cond_a

    .line 182
    .line 183
    :cond_9
    move v10, v7

    .line 184
    :cond_a
    xor-int/lit8 v5, v10, 0x1

    .line 185
    .line 186
    iget-wide v1, v1, Lh8/o0;->i:J

    .line 187
    .line 188
    iget-wide v7, v0, Lh8/r0;->E:J

    .line 189
    .line 190
    new-instance v9, Lh8/x;

    .line 191
    .line 192
    invoke-static {v1, v2}, Lw7/w;->N(J)J

    .line 193
    .line 194
    .line 195
    move-result-wide v12

    .line 196
    invoke-static {v7, v8}, Lw7/w;->N(J)J

    .line 197
    .line 198
    .line 199
    move-result-wide v14

    .line 200
    const/4 v10, -0x1

    .line 201
    const/4 v11, 0x0

    .line 202
    invoke-direct/range {v9 .. v15}, Lh8/x;-><init>(ILt7/o;JJ)V

    .line 203
    .line 204
    .line 205
    new-instance v1, Lh8/f0;

    .line 206
    .line 207
    iget-object v0, v0, Lh8/r0;->h:Ld8/f;

    .line 208
    .line 209
    move-object v2, v1

    .line 210
    move-object v1, v0

    .line 211
    move-object v0, v2

    .line 212
    move-object v2, v3

    .line 213
    move-object v3, v9

    .line 214
    invoke-direct/range {v0 .. v5}, Lh8/f0;-><init>(Ld8/f;Lh8/s;Lh8/x;Ljava/io/IOException;Z)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v1, v0}, Ld8/f;->a(Lw7/f;)V

    .line 218
    .line 219
    .line 220
    return-object v6
.end method

.method public final k()V
    .locals 3

    .line 1
    iget-object v0, p0, Lh8/r0;->g:Lmb/e;

    .line 2
    .line 3
    iget v1, p0, Lh8/r0;->G:I

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lmb/e;->q(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lh8/r0;->o:Lk8/l;

    .line 10
    .line 11
    iget-object v2, v1, Lk8/l;->c:Ljava/io/IOException;

    .line 12
    .line 13
    if-nez v2, :cond_5

    .line 14
    .line 15
    iget-object v1, v1, Lk8/l;->b:Lk8/i;

    .line 16
    .line 17
    if-eqz v1, :cond_2

    .line 18
    .line 19
    const/high16 v2, -0x80000000

    .line 20
    .line 21
    if-ne v0, v2, :cond_0

    .line 22
    .line 23
    iget v0, v1, Lk8/i;->d:I

    .line 24
    .line 25
    :cond_0
    iget-object v2, v1, Lk8/i;->g:Ljava/io/IOException;

    .line 26
    .line 27
    if-eqz v2, :cond_2

    .line 28
    .line 29
    iget v1, v1, Lk8/i;->h:I

    .line 30
    .line 31
    if-gt v1, v0, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    throw v2

    .line 35
    :cond_2
    :goto_0
    iget-boolean v0, p0, Lh8/r0;->Q:Z

    .line 36
    .line 37
    if-eqz v0, :cond_4

    .line 38
    .line 39
    iget-boolean p0, p0, Lh8/r0;->z:Z

    .line 40
    .line 41
    if-eqz p0, :cond_3

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_3
    const-string p0, "Loading finished before preparation is complete."

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-static {v0, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_4
    :goto_1
    return-void

    .line 53
    :cond_5
    throw v2
.end method

.method public final l(J)V
    .locals 13

    .line 1
    iget-boolean v0, p0, Lh8/r0;->B:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_5

    .line 6
    :cond_0
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lh8/r0;->x()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    goto :goto_5

    .line 16
    :cond_1
    iget-object v0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 17
    .line 18
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, [Z

    .line 21
    .line 22
    iget-object v1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 23
    .line 24
    array-length v1, v1

    .line 25
    const/4 v2, 0x0

    .line 26
    :goto_0
    if-ge v2, v1, :cond_6

    .line 27
    .line 28
    iget-object v3, p0, Lh8/r0;->w:[Lh8/x0;

    .line 29
    .line 30
    aget-object v4, v3, v2

    .line 31
    .line 32
    aget-boolean v3, v0, v2

    .line 33
    .line 34
    iget-object v10, v4, Lh8/x0;->a:Lh8/v0;

    .line 35
    .line 36
    monitor-enter v4

    .line 37
    :try_start_0
    iget v5, v4, Lh8/x0;->p:I

    .line 38
    .line 39
    const-wide/16 v11, -0x1

    .line 40
    .line 41
    if-eqz v5, :cond_2

    .line 42
    .line 43
    iget-object v6, v4, Lh8/x0;->n:[J

    .line 44
    .line 45
    iget v7, v4, Lh8/x0;->r:I

    .line 46
    .line 47
    aget-wide v8, v6, v7

    .line 48
    .line 49
    cmp-long v6, p1, v8

    .line 50
    .line 51
    if-gez v6, :cond_3

    .line 52
    .line 53
    :cond_2
    move-wide v5, p1

    .line 54
    goto :goto_2

    .line 55
    :cond_3
    if-eqz v3, :cond_4

    .line 56
    .line 57
    iget v3, v4, Lh8/x0;->s:I

    .line 58
    .line 59
    if-eq v3, v5, :cond_4

    .line 60
    .line 61
    add-int/lit8 v5, v3, 0x1

    .line 62
    .line 63
    :cond_4
    move v8, v5

    .line 64
    goto :goto_1

    .line 65
    :catchall_0
    move-exception v0

    .line 66
    move-object p0, v0

    .line 67
    goto :goto_4

    .line 68
    :goto_1
    const/4 v9, 0x0

    .line 69
    move-wide v5, p1

    .line 70
    invoke-virtual/range {v4 .. v9}, Lh8/x0;->g(JIIZ)I

    .line 71
    .line 72
    .line 73
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 74
    const/4 p2, -0x1

    .line 75
    if-ne p1, p2, :cond_5

    .line 76
    .line 77
    monitor-exit v4

    .line 78
    goto :goto_3

    .line 79
    :cond_5
    :try_start_1
    invoke-virtual {v4, p1}, Lh8/x0;->e(I)J

    .line 80
    .line 81
    .line 82
    move-result-wide v11
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 83
    monitor-exit v4

    .line 84
    goto :goto_3

    .line 85
    :goto_2
    monitor-exit v4

    .line 86
    :goto_3
    invoke-virtual {v10, v11, v12}, Lh8/v0;->a(J)V

    .line 87
    .line 88
    .line 89
    add-int/lit8 v2, v2, 0x1

    .line 90
    .line 91
    move-wide p1, v5

    .line 92
    goto :goto_0

    .line 93
    :goto_4
    :try_start_2
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 94
    throw p0

    .line 95
    :cond_6
    :goto_5
    return-void
.end method

.method public final m()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lh8/r0;->y:Z

    .line 3
    .line 4
    iget-object v0, p0, Lh8/r0;->t:Landroid/os/Handler;

    .line 5
    .line 6
    iget-object p0, p0, Lh8/r0;->r:Lh8/m0;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final n()Lh8/e1;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh8/e1;

    .line 9
    .line 10
    return-object p0
.end method

.method public final o([Lj8/q;[Z[Lh8/y0;[ZJ)J
    .locals 8

    .line 1
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lh8/e1;

    .line 9
    .line 10
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, [Z

    .line 13
    .line 14
    iget v2, p0, Lh8/r0;->K:I

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    move v4, v3

    .line 18
    :goto_0
    array-length v5, p1

    .line 19
    const/4 v6, 0x1

    .line 20
    if-ge v4, v5, :cond_2

    .line 21
    .line 22
    aget-object v5, p3, v4

    .line 23
    .line 24
    if-eqz v5, :cond_1

    .line 25
    .line 26
    aget-object v7, p1, v4

    .line 27
    .line 28
    if-eqz v7, :cond_0

    .line 29
    .line 30
    aget-boolean v7, p2, v4

    .line 31
    .line 32
    if-nez v7, :cond_1

    .line 33
    .line 34
    :cond_0
    check-cast v5, Lh8/p0;

    .line 35
    .line 36
    iget v5, v5, Lh8/p0;->d:I

    .line 37
    .line 38
    aget-boolean v7, v0, v5

    .line 39
    .line 40
    invoke-static {v7}, Lw7/a;->j(Z)V

    .line 41
    .line 42
    .line 43
    iget v7, p0, Lh8/r0;->K:I

    .line 44
    .line 45
    sub-int/2addr v7, v6

    .line 46
    iput v7, p0, Lh8/r0;->K:I

    .line 47
    .line 48
    aput-boolean v3, v0, v5

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    aput-object v5, p3, v4

    .line 52
    .line 53
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    iget-boolean p2, p0, Lh8/r0;->H:Z

    .line 57
    .line 58
    if-eqz p2, :cond_4

    .line 59
    .line 60
    if-nez v2, :cond_3

    .line 61
    .line 62
    :goto_1
    move p2, v6

    .line 63
    goto :goto_2

    .line 64
    :cond_3
    move p2, v3

    .line 65
    goto :goto_2

    .line 66
    :cond_4
    const-wide/16 v4, 0x0

    .line 67
    .line 68
    cmp-long p2, p5, v4

    .line 69
    .line 70
    if-eqz p2, :cond_3

    .line 71
    .line 72
    iget-boolean p2, p0, Lh8/r0;->B:Z

    .line 73
    .line 74
    if-nez p2, :cond_3

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :goto_2
    move v2, v3

    .line 78
    :goto_3
    array-length v4, p1

    .line 79
    if-ge v2, v4, :cond_a

    .line 80
    .line 81
    aget-object v4, p3, v2

    .line 82
    .line 83
    if-nez v4, :cond_9

    .line 84
    .line 85
    aget-object v4, p1, v2

    .line 86
    .line 87
    if-eqz v4, :cond_9

    .line 88
    .line 89
    invoke-interface {v4}, Lj8/q;->length()I

    .line 90
    .line 91
    .line 92
    move-result v5

    .line 93
    if-ne v5, v6, :cond_5

    .line 94
    .line 95
    move v5, v6

    .line 96
    goto :goto_4

    .line 97
    :cond_5
    move v5, v3

    .line 98
    :goto_4
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 99
    .line 100
    .line 101
    invoke-interface {v4, v3}, Lj8/q;->b(I)I

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-nez v5, :cond_6

    .line 106
    .line 107
    move v5, v6

    .line 108
    goto :goto_5

    .line 109
    :cond_6
    move v5, v3

    .line 110
    :goto_5
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 111
    .line 112
    .line 113
    invoke-interface {v4}, Lj8/q;->g()Lt7/q0;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    iget-object v7, v1, Lh8/e1;->b:Lhr/x0;

    .line 118
    .line 119
    invoke-virtual {v7, v5}, Lhr/h0;->indexOf(Ljava/lang/Object;)I

    .line 120
    .line 121
    .line 122
    move-result v5

    .line 123
    if-ltz v5, :cond_7

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_7
    const/4 v5, -0x1

    .line 127
    :goto_6
    aget-boolean v7, v0, v5

    .line 128
    .line 129
    xor-int/2addr v7, v6

    .line 130
    invoke-static {v7}, Lw7/a;->j(Z)V

    .line 131
    .line 132
    .line 133
    iget v7, p0, Lh8/r0;->K:I

    .line 134
    .line 135
    add-int/2addr v7, v6

    .line 136
    iput v7, p0, Lh8/r0;->K:I

    .line 137
    .line 138
    aput-boolean v6, v0, v5

    .line 139
    .line 140
    iget-boolean v7, p0, Lh8/r0;->J:Z

    .line 141
    .line 142
    invoke-interface {v4}, Lj8/q;->k()Lt7/o;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    iget-boolean v4, v4, Lt7/o;->t:Z

    .line 147
    .line 148
    or-int/2addr v4, v7

    .line 149
    iput-boolean v4, p0, Lh8/r0;->J:Z

    .line 150
    .line 151
    new-instance v4, Lh8/p0;

    .line 152
    .line 153
    invoke-direct {v4, p0, v5}, Lh8/p0;-><init>(Lh8/r0;I)V

    .line 154
    .line 155
    .line 156
    aput-object v4, p3, v2

    .line 157
    .line 158
    aput-boolean v6, p4, v2

    .line 159
    .line 160
    if-nez p2, :cond_9

    .line 161
    .line 162
    iget-object p2, p0, Lh8/r0;->w:[Lh8/x0;

    .line 163
    .line 164
    aget-object p2, p2, v5

    .line 165
    .line 166
    iget v4, p2, Lh8/x0;->q:I

    .line 167
    .line 168
    iget v5, p2, Lh8/x0;->s:I

    .line 169
    .line 170
    add-int/2addr v4, v5

    .line 171
    if-eqz v4, :cond_8

    .line 172
    .line 173
    invoke-virtual {p2, p5, p6, v6}, Lh8/x0;->m(JZ)Z

    .line 174
    .line 175
    .line 176
    move-result p2

    .line 177
    if-nez p2, :cond_8

    .line 178
    .line 179
    move p2, v6

    .line 180
    goto :goto_7

    .line 181
    :cond_8
    move p2, v3

    .line 182
    :cond_9
    :goto_7
    add-int/lit8 v2, v2, 0x1

    .line 183
    .line 184
    goto :goto_3

    .line 185
    :cond_a
    iget p1, p0, Lh8/r0;->K:I

    .line 186
    .line 187
    if-nez p1, :cond_d

    .line 188
    .line 189
    iput-boolean v3, p0, Lh8/r0;->O:Z

    .line 190
    .line 191
    iput-boolean v3, p0, Lh8/r0;->I:Z

    .line 192
    .line 193
    iput-boolean v3, p0, Lh8/r0;->J:Z

    .line 194
    .line 195
    iget-object p1, p0, Lh8/r0;->o:Lk8/l;

    .line 196
    .line 197
    invoke-virtual {p1}, Lk8/l;->a()Z

    .line 198
    .line 199
    .line 200
    move-result p2

    .line 201
    if-eqz p2, :cond_c

    .line 202
    .line 203
    iget-object p2, p0, Lh8/r0;->w:[Lh8/x0;

    .line 204
    .line 205
    array-length p3, p2

    .line 206
    move p4, v3

    .line 207
    :goto_8
    if-ge p4, p3, :cond_b

    .line 208
    .line 209
    aget-object v0, p2, p4

    .line 210
    .line 211
    invoke-virtual {v0}, Lh8/x0;->f()V

    .line 212
    .line 213
    .line 214
    add-int/lit8 p4, p4, 0x1

    .line 215
    .line 216
    goto :goto_8

    .line 217
    :cond_b
    iget-object p1, p1, Lk8/l;->b:Lk8/i;

    .line 218
    .line 219
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {p1, v3}, Lk8/i;->a(Z)V

    .line 223
    .line 224
    .line 225
    goto :goto_b

    .line 226
    :cond_c
    iput-boolean v3, p0, Lh8/r0;->Q:Z

    .line 227
    .line 228
    iget-object p1, p0, Lh8/r0;->w:[Lh8/x0;

    .line 229
    .line 230
    array-length p2, p1

    .line 231
    move p3, v3

    .line 232
    :goto_9
    if-ge p3, p2, :cond_f

    .line 233
    .line 234
    aget-object p4, p1, p3

    .line 235
    .line 236
    invoke-virtual {p4, v3}, Lh8/x0;->l(Z)V

    .line 237
    .line 238
    .line 239
    add-int/lit8 p3, p3, 0x1

    .line 240
    .line 241
    goto :goto_9

    .line 242
    :cond_d
    if-eqz p2, :cond_f

    .line 243
    .line 244
    invoke-virtual {p0, p5, p6}, Lh8/r0;->d(J)J

    .line 245
    .line 246
    .line 247
    move-result-wide p5

    .line 248
    :goto_a
    array-length p1, p3

    .line 249
    if-ge v3, p1, :cond_f

    .line 250
    .line 251
    aget-object p1, p3, v3

    .line 252
    .line 253
    if-eqz p1, :cond_e

    .line 254
    .line 255
    aput-boolean v6, p4, v3

    .line 256
    .line 257
    :cond_e
    add-int/lit8 v3, v3, 0x1

    .line 258
    .line 259
    goto :goto_a

    .line 260
    :cond_f
    :goto_b
    iput-boolean v6, p0, Lh8/r0;->H:Z

    .line 261
    .line 262
    return-wide p5
.end method

.method public final p(La8/u0;)Z
    .locals 1

    .line 1
    iget-boolean p1, p0, Lh8/r0;->Q:Z

    .line 2
    .line 3
    if-nez p1, :cond_4

    .line 4
    .line 5
    iget-object p1, p0, Lh8/r0;->o:Lk8/l;

    .line 6
    .line 7
    iget-object v0, p1, Lk8/l;->c:Ljava/io/IOException;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-boolean v0, p0, Lh8/r0;->O:Z

    .line 13
    .line 14
    if-nez v0, :cond_4

    .line 15
    .line 16
    iget-boolean v0, p0, Lh8/r0;->z:Z

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    iget-object v0, p0, Lh8/r0;->m:Lt7/o;

    .line 21
    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    :cond_1
    iget v0, p0, Lh8/r0;->K:I

    .line 25
    .line 26
    if-nez v0, :cond_2

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_2
    iget-object v0, p0, Lh8/r0;->q:Lw7/e;

    .line 30
    .line 31
    invoke-virtual {v0}, Lw7/e;->c()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-virtual {p1}, Lk8/l;->a()Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_3

    .line 40
    .line 41
    invoke-virtual {p0}, Lh8/r0;->D()V

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    return p0

    .line 46
    :cond_3
    return v0

    .line 47
    :cond_4
    :goto_0
    const/4 p0, 0x0

    .line 48
    return p0
.end method

.method public final q(II)Lo8/i0;
    .locals 1

    .line 1
    new-instance p2, Lh8/q0;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p2, p1, v0}, Lh8/q0;-><init>(IZ)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p2}, Lh8/r0;->B(Lh8/q0;)Lo8/i0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final r()J
    .locals 12

    .line 1
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Lh8/r0;->Q:Z

    .line 5
    .line 6
    const-wide/high16 v1, -0x8000000000000000L

    .line 7
    .line 8
    if-nez v0, :cond_7

    .line 9
    .line 10
    iget v0, p0, Lh8/r0;->K:I

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    goto :goto_2

    .line 15
    :cond_0
    invoke-virtual {p0}, Lh8/r0;->x()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iget-wide v0, p0, Lh8/r0;->N:J

    .line 22
    .line 23
    return-wide v0

    .line 24
    :cond_1
    iget-boolean v0, p0, Lh8/r0;->A:Z

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const-wide v4, 0x7fffffffffffffffL

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    iget-object v0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 35
    .line 36
    array-length v0, v0

    .line 37
    move v6, v3

    .line 38
    move-wide v7, v4

    .line 39
    :goto_0
    if-ge v6, v0, :cond_4

    .line 40
    .line 41
    iget-object v9, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 42
    .line 43
    iget-object v10, v9, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v10, [Z

    .line 46
    .line 47
    aget-boolean v10, v10, v6

    .line 48
    .line 49
    if-eqz v10, :cond_2

    .line 50
    .line 51
    iget-object v9, v9, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v9, [Z

    .line 54
    .line 55
    aget-boolean v9, v9, v6

    .line 56
    .line 57
    if-eqz v9, :cond_2

    .line 58
    .line 59
    iget-object v9, p0, Lh8/r0;->w:[Lh8/x0;

    .line 60
    .line 61
    aget-object v9, v9, v6

    .line 62
    .line 63
    monitor-enter v9

    .line 64
    :try_start_0
    iget-boolean v10, v9, Lh8/x0;->w:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 65
    .line 66
    monitor-exit v9

    .line 67
    if-nez v10, :cond_2

    .line 68
    .line 69
    iget-object v9, p0, Lh8/r0;->w:[Lh8/x0;

    .line 70
    .line 71
    aget-object v9, v9, v6

    .line 72
    .line 73
    monitor-enter v9

    .line 74
    :try_start_1
    iget-wide v10, v9, Lh8/x0;->v:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 75
    .line 76
    monitor-exit v9

    .line 77
    invoke-static {v7, v8, v10, v11}, Ljava/lang/Math;->min(JJ)J

    .line 78
    .line 79
    .line 80
    move-result-wide v7

    .line 81
    goto :goto_1

    .line 82
    :catchall_0
    move-exception p0

    .line 83
    :try_start_2
    monitor-exit v9
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 84
    throw p0

    .line 85
    :catchall_1
    move-exception p0

    .line 86
    :try_start_3
    monitor-exit v9
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 87
    throw p0

    .line 88
    :cond_2
    :goto_1
    add-int/lit8 v6, v6, 0x1

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_3
    move-wide v7, v4

    .line 92
    :cond_4
    cmp-long v0, v7, v4

    .line 93
    .line 94
    if-nez v0, :cond_5

    .line 95
    .line 96
    invoke-virtual {p0, v3}, Lh8/r0;->w(Z)J

    .line 97
    .line 98
    .line 99
    move-result-wide v7

    .line 100
    :cond_5
    cmp-long v0, v7, v1

    .line 101
    .line 102
    if-nez v0, :cond_6

    .line 103
    .line 104
    iget-wide v0, p0, Lh8/r0;->M:J

    .line 105
    .line 106
    return-wide v0

    .line 107
    :cond_6
    return-wide v7

    .line 108
    :cond_7
    :goto_2
    return-wide v1
.end method

.method public final s(J)V
    .locals 0

    .line 1
    return-void
.end method

.method public final t(Lh8/o0;)V
    .locals 14

    .line 1
    iget-wide v0, p0, Lh8/r0;->E:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long v0, v0, v2

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Lh8/r0;->D:Lo8/c0;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, v1}, Lh8/r0;->w(Z)J

    .line 18
    .line 19
    .line 20
    move-result-wide v2

    .line 21
    const-wide/high16 v4, -0x8000000000000000L

    .line 22
    .line 23
    cmp-long v0, v2, v4

    .line 24
    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    const-wide/16 v2, 0x0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const-wide/16 v4, 0x2710

    .line 31
    .line 32
    add-long/2addr v2, v4

    .line 33
    :goto_0
    iput-wide v2, p0, Lh8/r0;->E:J

    .line 34
    .line 35
    iget-object v0, p0, Lh8/r0;->D:Lo8/c0;

    .line 36
    .line 37
    iget-boolean v4, p0, Lh8/r0;->F:Z

    .line 38
    .line 39
    iget-object v5, p0, Lh8/r0;->j:Lh8/u0;

    .line 40
    .line 41
    invoke-virtual {v5, v2, v3, v0, v4}, Lh8/u0;->t(JLo8/c0;Z)V

    .line 42
    .line 43
    .line 44
    :cond_1
    iget-object v0, p1, Lh8/o0;->b:Ly7/y;

    .line 45
    .line 46
    new-instance v2, Lh8/s;

    .line 47
    .line 48
    iget-object v0, v0, Ly7/y;->f:Landroid/net/Uri;

    .line 49
    .line 50
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 51
    .line 52
    .line 53
    iget-object v0, p0, Lh8/r0;->g:Lmb/e;

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    iget-wide v3, p1, Lh8/o0;->i:J

    .line 59
    .line 60
    iget-wide v5, p0, Lh8/r0;->E:J

    .line 61
    .line 62
    new-instance v7, Lh8/x;

    .line 63
    .line 64
    invoke-static {v3, v4}, Lw7/w;->N(J)J

    .line 65
    .line 66
    .line 67
    move-result-wide v10

    .line 68
    invoke-static {v5, v6}, Lw7/w;->N(J)J

    .line 69
    .line 70
    .line 71
    move-result-wide v12

    .line 72
    const/4 v8, -0x1

    .line 73
    const/4 v9, 0x0

    .line 74
    invoke-direct/range {v7 .. v13}, Lh8/x;-><init>(ILt7/o;JJ)V

    .line 75
    .line 76
    .line 77
    new-instance p1, Lh8/e0;

    .line 78
    .line 79
    const/4 v0, 0x0

    .line 80
    iget-object v3, p0, Lh8/r0;->h:Ld8/f;

    .line 81
    .line 82
    invoke-direct {p1, v3, v2, v7, v0}, Lh8/e0;-><init>(Ld8/f;Lh8/s;Lh8/x;I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v3, p1}, Ld8/f;->a(Lw7/f;)V

    .line 86
    .line 87
    .line 88
    iput-boolean v1, p0, Lh8/r0;->Q:Z

    .line 89
    .line 90
    iget-object p1, p0, Lh8/r0;->u:Lh8/y;

    .line 91
    .line 92
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    invoke-interface {p1, p0}, Lh8/y;->f(Lh8/z0;)V

    .line 96
    .line 97
    .line 98
    return-void
.end method

.method public final u()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh8/r0;->z:Z

    .line 2
    .line 3
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lh8/r0;->D:Lo8/c0;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final v()I
    .locals 5

    .line 1
    iget-object p0, p0, Lh8/r0;->w:[Lh8/x0;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/4 v1, 0x0

    .line 5
    move v2, v1

    .line 6
    :goto_0
    if-ge v1, v0, :cond_0

    .line 7
    .line 8
    aget-object v3, p0, v1

    .line 9
    .line 10
    iget v4, v3, Lh8/x0;->q:I

    .line 11
    .line 12
    iget v3, v3, Lh8/x0;->p:I

    .line 13
    .line 14
    add-int/2addr v4, v3

    .line 15
    add-int/2addr v2, v4

    .line 16
    add-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    return v2
.end method

.method public final w(Z)J
    .locals 6

    .line 1
    const-wide/high16 v0, -0x8000000000000000L

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    :goto_0
    iget-object v3, p0, Lh8/r0;->w:[Lh8/x0;

    .line 5
    .line 6
    array-length v3, v3

    .line 7
    if-ge v2, v3, :cond_2

    .line 8
    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    iget-object v3, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 12
    .line 13
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    iget-object v3, v3, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v3, [Z

    .line 19
    .line 20
    aget-boolean v3, v3, v2

    .line 21
    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    :cond_0
    iget-object v3, p0, Lh8/r0;->w:[Lh8/x0;

    .line 25
    .line 26
    aget-object v3, v3, v2

    .line 27
    .line 28
    monitor-enter v3

    .line 29
    :try_start_0
    iget-wide v4, v3, Lh8/x0;->v:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    monitor-exit v3

    .line 32
    invoke-static {v0, v1, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    :try_start_1
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    throw p0

    .line 42
    :cond_2
    return-wide v0
.end method

.method public final x()Z
    .locals 4

    .line 1
    iget-wide v0, p0, Lh8/r0;->N:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long p0, v0, v2

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public final y()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-wide v1, v0, Lh8/r0;->n:J

    .line 4
    .line 5
    iget-boolean v3, v0, Lh8/r0;->R:Z

    .line 6
    .line 7
    if-nez v3, :cond_e

    .line 8
    .line 9
    iget-boolean v3, v0, Lh8/r0;->z:Z

    .line 10
    .line 11
    if-nez v3, :cond_e

    .line 12
    .line 13
    iget-boolean v3, v0, Lh8/r0;->y:Z

    .line 14
    .line 15
    if-eqz v3, :cond_e

    .line 16
    .line 17
    iget-object v3, v0, Lh8/r0;->D:Lo8/c0;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    goto/16 :goto_8

    .line 22
    .line 23
    :cond_0
    iget-object v3, v0, Lh8/r0;->w:[Lh8/x0;

    .line 24
    .line 25
    array-length v4, v3

    .line 26
    const/4 v5, 0x0

    .line 27
    move v6, v5

    .line 28
    :goto_0
    const/4 v7, 0x0

    .line 29
    if-ge v6, v4, :cond_3

    .line 30
    .line 31
    aget-object v8, v3, v6

    .line 32
    .line 33
    monitor-enter v8

    .line 34
    :try_start_0
    iget-boolean v9, v8, Lh8/x0;->y:Z

    .line 35
    .line 36
    if-eqz v9, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    iget-object v7, v8, Lh8/x0;->z:Lt7/o;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    :goto_1
    monitor-exit v8

    .line 42
    if-nez v7, :cond_2

    .line 43
    .line 44
    goto/16 :goto_8

    .line 45
    .line 46
    :cond_2
    add-int/lit8 v6, v6, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception v0

    .line 50
    :try_start_1
    monitor-exit v8
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    throw v0

    .line 52
    :cond_3
    iget-object v3, v0, Lh8/r0;->q:Lw7/e;

    .line 53
    .line 54
    monitor-enter v3

    .line 55
    :try_start_2
    iput-boolean v5, v3, Lw7/e;->b:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 56
    .line 57
    monitor-exit v3

    .line 58
    iget-object v3, v0, Lh8/r0;->w:[Lh8/x0;

    .line 59
    .line 60
    array-length v3, v3

    .line 61
    new-array v4, v3, [Lt7/q0;

    .line 62
    .line 63
    new-array v6, v3, [Z

    .line 64
    .line 65
    move v8, v5

    .line 66
    :goto_2
    const-wide v9, -0x7fffffffffffffffL    # -4.9E-324

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    const/4 v11, 0x1

    .line 72
    if-ge v8, v3, :cond_c

    .line 73
    .line 74
    iget-object v12, v0, Lh8/r0;->w:[Lh8/x0;

    .line 75
    .line 76
    aget-object v12, v12, v8

    .line 77
    .line 78
    monitor-enter v12

    .line 79
    :try_start_3
    iget-boolean v13, v12, Lh8/x0;->y:Z

    .line 80
    .line 81
    if-eqz v13, :cond_4

    .line 82
    .line 83
    move-object v13, v7

    .line 84
    goto :goto_3

    .line 85
    :cond_4
    iget-object v13, v12, Lh8/x0;->z:Lt7/o;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 86
    .line 87
    :goto_3
    monitor-exit v12

    .line 88
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    iget-object v12, v13, Lt7/o;->n:Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {v12}, Lt7/d0;->i(Ljava/lang/String;)Z

    .line 94
    .line 95
    .line 96
    move-result v14

    .line 97
    if-nez v14, :cond_6

    .line 98
    .line 99
    invoke-static {v12}, Lt7/d0;->l(Ljava/lang/String;)Z

    .line 100
    .line 101
    .line 102
    move-result v15

    .line 103
    if-eqz v15, :cond_5

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_5
    move v15, v5

    .line 107
    goto :goto_5

    .line 108
    :cond_6
    :goto_4
    move v15, v11

    .line 109
    :goto_5
    aput-boolean v15, v6, v8

    .line 110
    .line 111
    move/from16 v16, v5

    .line 112
    .line 113
    iget-boolean v5, v0, Lh8/r0;->A:Z

    .line 114
    .line 115
    or-int/2addr v5, v15

    .line 116
    iput-boolean v5, v0, Lh8/r0;->A:Z

    .line 117
    .line 118
    invoke-static {v12}, Lt7/d0;->j(Ljava/lang/String;)Z

    .line 119
    .line 120
    .line 121
    move-result v5

    .line 122
    cmp-long v9, v1, v9

    .line 123
    .line 124
    if-eqz v9, :cond_7

    .line 125
    .line 126
    if-ne v3, v11, :cond_7

    .line 127
    .line 128
    if-eqz v5, :cond_7

    .line 129
    .line 130
    move v5, v11

    .line 131
    goto :goto_6

    .line 132
    :cond_7
    move/from16 v5, v16

    .line 133
    .line 134
    :goto_6
    iput-boolean v5, v0, Lh8/r0;->B:Z

    .line 135
    .line 136
    iget-object v5, v0, Lh8/r0;->v:Lb9/b;

    .line 137
    .line 138
    if-eqz v5, :cond_b

    .line 139
    .line 140
    iget v9, v5, Lb9/b;->a:I

    .line 141
    .line 142
    if-nez v14, :cond_8

    .line 143
    .line 144
    iget-object v10, v0, Lh8/r0;->x:[Lh8/q0;

    .line 145
    .line 146
    aget-object v10, v10, v8

    .line 147
    .line 148
    iget-boolean v10, v10, Lh8/q0;->b:Z

    .line 149
    .line 150
    if-eqz v10, :cond_a

    .line 151
    .line 152
    :cond_8
    iget-object v10, v13, Lt7/o;->l:Lt7/c0;

    .line 153
    .line 154
    if-nez v10, :cond_9

    .line 155
    .line 156
    new-instance v10, Lt7/c0;

    .line 157
    .line 158
    new-array v11, v11, [Lt7/b0;

    .line 159
    .line 160
    aput-object v5, v11, v16

    .line 161
    .line 162
    invoke-direct {v10, v11}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 163
    .line 164
    .line 165
    goto :goto_7

    .line 166
    :cond_9
    new-array v11, v11, [Lt7/b0;

    .line 167
    .line 168
    aput-object v5, v11, v16

    .line 169
    .line 170
    invoke-virtual {v10, v11}, Lt7/c0;->a([Lt7/b0;)Lt7/c0;

    .line 171
    .line 172
    .line 173
    move-result-object v10

    .line 174
    :goto_7
    invoke-virtual {v13}, Lt7/o;->a()Lt7/n;

    .line 175
    .line 176
    .line 177
    move-result-object v5

    .line 178
    iput-object v10, v5, Lt7/n;->k:Lt7/c0;

    .line 179
    .line 180
    new-instance v13, Lt7/o;

    .line 181
    .line 182
    invoke-direct {v13, v5}, Lt7/o;-><init>(Lt7/n;)V

    .line 183
    .line 184
    .line 185
    :cond_a
    if-eqz v14, :cond_b

    .line 186
    .line 187
    iget v5, v13, Lt7/o;->h:I

    .line 188
    .line 189
    const/4 v10, -0x1

    .line 190
    if-ne v5, v10, :cond_b

    .line 191
    .line 192
    iget v5, v13, Lt7/o;->i:I

    .line 193
    .line 194
    if-ne v5, v10, :cond_b

    .line 195
    .line 196
    if-eq v9, v10, :cond_b

    .line 197
    .line 198
    invoke-virtual {v13}, Lt7/o;->a()Lt7/n;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    iput v9, v5, Lt7/n;->h:I

    .line 203
    .line 204
    new-instance v13, Lt7/o;

    .line 205
    .line 206
    invoke-direct {v13, v5}, Lt7/o;-><init>(Lt7/n;)V

    .line 207
    .line 208
    .line 209
    :cond_b
    iget-object v5, v0, Lh8/r0;->f:Ld8/j;

    .line 210
    .line 211
    invoke-interface {v5, v13}, Ld8/j;->c(Lt7/o;)I

    .line 212
    .line 213
    .line 214
    move-result v5

    .line 215
    invoke-virtual {v13}, Lt7/o;->a()Lt7/n;

    .line 216
    .line 217
    .line 218
    move-result-object v9

    .line 219
    iput v5, v9, Lt7/n;->N:I

    .line 220
    .line 221
    new-instance v5, Lt7/o;

    .line 222
    .line 223
    invoke-direct {v5, v9}, Lt7/o;-><init>(Lt7/n;)V

    .line 224
    .line 225
    .line 226
    new-instance v9, Lt7/q0;

    .line 227
    .line 228
    invoke-static {v8}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v10

    .line 232
    filled-new-array {v5}, [Lt7/o;

    .line 233
    .line 234
    .line 235
    move-result-object v11

    .line 236
    invoke-direct {v9, v10, v11}, Lt7/q0;-><init>(Ljava/lang/String;[Lt7/o;)V

    .line 237
    .line 238
    .line 239
    aput-object v9, v4, v8

    .line 240
    .line 241
    iget-boolean v9, v0, Lh8/r0;->J:Z

    .line 242
    .line 243
    iget-boolean v5, v5, Lt7/o;->t:Z

    .line 244
    .line 245
    or-int/2addr v5, v9

    .line 246
    iput-boolean v5, v0, Lh8/r0;->J:Z

    .line 247
    .line 248
    add-int/lit8 v8, v8, 0x1

    .line 249
    .line 250
    move/from16 v5, v16

    .line 251
    .line 252
    goto/16 :goto_2

    .line 253
    .line 254
    :catchall_1
    move-exception v0

    .line 255
    :try_start_4
    monitor-exit v12
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 256
    throw v0

    .line 257
    :cond_c
    new-instance v3, Lcom/google/firebase/messaging/w;

    .line 258
    .line 259
    new-instance v5, Lh8/e1;

    .line 260
    .line 261
    invoke-direct {v5, v4}, Lh8/e1;-><init>([Lt7/q0;)V

    .line 262
    .line 263
    .line 264
    invoke-direct {v3, v5, v6}, Lcom/google/firebase/messaging/w;-><init>(Lh8/e1;[Z)V

    .line 265
    .line 266
    .line 267
    iput-object v3, v0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 268
    .line 269
    iget-boolean v3, v0, Lh8/r0;->B:Z

    .line 270
    .line 271
    if-eqz v3, :cond_d

    .line 272
    .line 273
    iget-wide v3, v0, Lh8/r0;->E:J

    .line 274
    .line 275
    cmp-long v3, v3, v9

    .line 276
    .line 277
    if-nez v3, :cond_d

    .line 278
    .line 279
    iput-wide v1, v0, Lh8/r0;->E:J

    .line 280
    .line 281
    new-instance v1, Lh8/n0;

    .line 282
    .line 283
    iget-object v2, v0, Lh8/r0;->D:Lo8/c0;

    .line 284
    .line 285
    invoke-direct {v1, v0, v2}, Lh8/n0;-><init>(Lh8/r0;Lo8/c0;)V

    .line 286
    .line 287
    .line 288
    iput-object v1, v0, Lh8/r0;->D:Lo8/c0;

    .line 289
    .line 290
    :cond_d
    iget-object v1, v0, Lh8/r0;->j:Lh8/u0;

    .line 291
    .line 292
    iget-wide v2, v0, Lh8/r0;->E:J

    .line 293
    .line 294
    iget-object v4, v0, Lh8/r0;->D:Lo8/c0;

    .line 295
    .line 296
    iget-boolean v5, v0, Lh8/r0;->F:Z

    .line 297
    .line 298
    invoke-virtual {v1, v2, v3, v4, v5}, Lh8/u0;->t(JLo8/c0;Z)V

    .line 299
    .line 300
    .line 301
    iput-boolean v11, v0, Lh8/r0;->z:Z

    .line 302
    .line 303
    iget-object v1, v0, Lh8/r0;->u:Lh8/y;

    .line 304
    .line 305
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 306
    .line 307
    .line 308
    invoke-interface {v1, v0}, Lh8/y;->c(Lh8/z;)V

    .line 309
    .line 310
    .line 311
    return-void

    .line 312
    :catchall_2
    move-exception v0

    .line 313
    :try_start_5
    monitor-exit v3
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 314
    throw v0

    .line 315
    :cond_e
    :goto_8
    return-void
.end method

.method public final z(I)V
    .locals 10

    .line 1
    invoke-virtual {p0}, Lh8/r0;->u()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lh8/r0;->C:Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, [Z

    .line 9
    .line 10
    aget-boolean v2, v1, p1

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lh8/e1;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lh8/e1;->a(I)Lt7/q0;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const/4 v2, 0x0

    .line 23
    iget-object v0, v0, Lt7/q0;->d:[Lt7/o;

    .line 24
    .line 25
    aget-object v5, v0, v2

    .line 26
    .line 27
    iget-object v0, v5, Lt7/o;->n:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v0}, Lt7/d0;->h(Ljava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    iget-wide v2, p0, Lh8/r0;->M:J

    .line 34
    .line 35
    move-wide v6, v2

    .line 36
    new-instance v3, Lh8/x;

    .line 37
    .line 38
    invoke-static {v6, v7}, Lw7/w;->N(J)J

    .line 39
    .line 40
    .line 41
    move-result-wide v6

    .line 42
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    invoke-direct/range {v3 .. v9}, Lh8/x;-><init>(ILt7/o;JJ)V

    .line 48
    .line 49
    .line 50
    new-instance v0, La0/h;

    .line 51
    .line 52
    const/16 v2, 0x11

    .line 53
    .line 54
    iget-object p0, p0, Lh8/r0;->h:Ld8/f;

    .line 55
    .line 56
    invoke-direct {v0, v2, p0, v3}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0, v0}, Ld8/f;->a(Lw7/f;)V

    .line 60
    .line 61
    .line 62
    const/4 p0, 0x1

    .line 63
    aput-boolean p0, v1, p1

    .line 64
    .line 65
    :cond_0
    return-void
.end method
