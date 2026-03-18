.class public final Llo/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/content/DialogInterface$OnCancelListener;


# instance fields
.field public final d:Ljava/lang/Object;

.field public volatile e:Z

.field public final f:Ljava/util/concurrent/atomic/AtomicReference;

.field public final g:Lbp/c;

.field public final h:Ljo/e;

.field public final i:Landroidx/collection/g;

.field public final j:Llo/g;


# direct methods
.method public constructor <init>(Llo/j;Llo/g;)V
    .locals 5

    .line 1
    sget-object v0, Ljo/e;->d:Ljo/e;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Llo/p;->d:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iput-object v1, p0, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 15
    .line 16
    new-instance v1, Lbp/c;

    .line 17
    .line 18
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    const/4 v4, 0x2

    .line 23
    invoke-direct {v1, v3, v4}, Lbp/c;-><init>(Landroid/os/Looper;I)V

    .line 24
    .line 25
    .line 26
    iput-object v1, p0, Llo/p;->g:Lbp/c;

    .line 27
    .line 28
    iput-object v0, p0, Llo/p;->h:Ljo/e;

    .line 29
    .line 30
    new-instance v0, Landroidx/collection/g;

    .line 31
    .line 32
    invoke-direct {v0, v2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Llo/p;->i:Landroidx/collection/g;

    .line 36
    .line 37
    iput-object p2, p0, Llo/p;->j:Llo/g;

    .line 38
    .line 39
    invoke-interface {p1, p0}, Llo/j;->c(Llo/p;)V

    .line 40
    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final a()Landroid/app/Activity;
    .locals 0

    .line 1
    iget-object p0, p0, Llo/p;->d:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llo/j;->b()Landroid/app/Activity;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public final b(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    const-string v0, "resolving_error"

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Ljo/b;

    .line 13
    .line 14
    const-string v1, "failed_status"

    .line 15
    .line 16
    invoke-virtual {p1, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    const-string v2, "failed_resolution"

    .line 21
    .line 22
    invoke-virtual {p1, v2}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Landroid/app/PendingIntent;

    .line 27
    .line 28
    invoke-direct {v0, v1, v2}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 29
    .line 30
    .line 31
    const-string v1, "failed_client_id"

    .line 32
    .line 33
    const/4 v2, -0x1

    .line 34
    invoke-virtual {p1, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    new-instance v1, Llo/g0;

    .line 39
    .line 40
    invoke-direct {v1, v0, p1}, Llo/g0;-><init>(Ljo/b;I)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v1, 0x0

    .line 45
    :goto_0
    iget-object p0, p0, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 46
    .line 47
    invoke-virtual {p0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    return-void
.end method

.method public final c()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Llo/p;->e:Z

    .line 3
    .line 4
    iget-object v0, p0, Llo/p;->j:Llo/g;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    sget-object v1, Llo/g;->u:Ljava/lang/Object;

    .line 10
    .line 11
    monitor-enter v1

    .line 12
    :try_start_0
    iget-object v2, v0, Llo/g;->n:Llo/p;

    .line 13
    .line 14
    if-ne v2, p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    iput-object p0, v0, Llo/g;->n:Llo/p;

    .line 18
    .line 19
    iget-object p0, v0, Llo/g;->o:Landroidx/collection/g;

    .line 20
    .line 21
    invoke-virtual {p0}, Landroidx/collection/g;->clear()V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    :goto_0
    monitor-exit v1

    .line 28
    return-void

    .line 29
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    throw p0
.end method

.method public final d()V
    .locals 1

    .line 1
    iget-object v0, p0, Llo/p;->i:Landroidx/collection/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroidx/collection/g;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Llo/p;->j:Llo/g;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Llo/g;->a(Llo/p;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final onCancel(Landroid/content/DialogInterface;)V
    .locals 3

    .line 1
    new-instance p1, Ljo/b;

    .line 2
    .line 3
    const/16 v0, 0xd

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {p1, v0, v1}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Llo/p;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Llo/g0;

    .line 16
    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    const/4 v2, -0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget v2, v2, Llo/g0;->a:I

    .line 22
    .line 23
    :goto_0
    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Llo/p;->j:Llo/g;

    .line 27
    .line 28
    invoke-virtual {p0, p1, v2}, Llo/g;->h(Ljo/b;I)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
