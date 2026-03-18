.class public final Ly4/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/common/util/concurrent/ListenableFuture;


# instance fields
.field public final d:Ljava/lang/ref/WeakReference;

.field public final e:Ly4/j;


# direct methods
.method public constructor <init>(Ly4/h;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ly4/j;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Ly4/j;-><init>(Ly4/k;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ly4/k;->e:Ly4/j;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 12
    .line 13
    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Ly4/k;->d:Ljava/lang/ref/WeakReference;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ly4/g;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final cancel(Z)Z
    .locals 1

    .line 1
    iget-object v0, p0, Ly4/k;->d:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ly4/h;

    .line 8
    .line 9
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ly4/g;->cancel(Z)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    iput-object p1, v0, Ly4/h;->a:Ljava/lang/Object;

    .line 21
    .line 22
    iput-object p1, v0, Ly4/h;->b:Ly4/k;

    .line 23
    .line 24
    iget-object v0, v0, Ly4/h;->c:Ly4/m;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ly4/g;->j(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    :cond_0
    return p0
.end method

.method public final get()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    invoke-virtual {p0}, Ly4/g;->get()Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;
    .locals 0

    .line 2
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    invoke-virtual {p0, p1, p2, p3}, Ly4/g;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final isCancelled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 2
    .line 3
    iget-object p0, p0, Ly4/g;->d:Ljava/lang/Object;

    .line 4
    .line 5
    instance-of p0, p0, Ly4/a;

    .line 6
    .line 7
    return p0
.end method

.method public final isDone()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Ly4/g;->isDone()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ly4/k;->e:Ly4/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Ly4/g;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
