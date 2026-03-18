.class public Lq/s;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ljava/util/concurrent/Executor;

.field public e:Ljp/he;

.field public f:Lil/g;

.field public g:Lcom/google/firebase/messaging/w;

.field public h:Lb81/b;

.field public i:Lb81/c;

.field public j:Lq/r;

.field public k:Z

.field public l:Z

.field public m:Z

.field public n:Z

.field public o:Z

.field public p:Landroidx/lifecycle/i0;

.field public q:Landroidx/lifecycle/i0;

.field public r:Landroidx/lifecycle/i0;

.field public s:Landroidx/lifecycle/i0;

.field public t:Landroidx/lifecycle/i0;

.field public u:Landroidx/lifecycle/i0;

.field public v:I

.field public w:Landroidx/lifecycle/i0;

.field public x:Landroidx/lifecycle/i0;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lq/s;->v:I

    .line 6
    .line 7
    return-void
.end method

.method public static g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v1}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Landroidx/lifecycle/i0;->j(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    invoke-virtual {p0, p1}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a(Lq/e;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lq/s;->q:Landroidx/lifecycle/i0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/i0;

    .line 6
    .line 7
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lq/s;->q:Landroidx/lifecycle/i0;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lq/s;->q:Landroidx/lifecycle/i0;

    .line 13
    .line 14
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final b(Ljava/lang/CharSequence;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lq/s;->x:Landroidx/lifecycle/i0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/i0;

    .line 6
    .line 7
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lq/s;->x:Landroidx/lifecycle/i0;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lq/s;->x:Landroidx/lifecycle/i0;

    .line 13
    .line 14
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final d(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lq/s;->w:Landroidx/lifecycle/i0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/i0;

    .line 6
    .line 7
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lq/s;->w:Landroidx/lifecycle/i0;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lq/s;->w:Landroidx/lifecycle/i0;

    .line 13
    .line 14
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final f(Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Lq/s;->t:Landroidx/lifecycle/i0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/i0;

    .line 6
    .line 7
    invoke-direct {v0}, Landroidx/lifecycle/g0;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lq/s;->t:Landroidx/lifecycle/i0;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lq/s;->t:Landroidx/lifecycle/i0;

    .line 13
    .line 14
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-static {p0, p1}, Lq/s;->g(Landroidx/lifecycle/i0;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method
