.class public final Lb0/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/c1;


# instance fields
.field public d:I

.field public e:Z

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 31
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    move-result-object v0

    iput-object v0, p0, Lb0/n1;->g:Ljava/lang/Object;

    const/4 v0, -0x1

    .line 32
    iput v0, p0, Lb0/n1;->d:I

    .line 33
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lb0/n1;->h:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 34
    iput-boolean v0, p0, Lb0/n1;->e:Z

    .line 35
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    move-result-object v0

    iput-object v0, p0, Lb0/n1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ld01/a;Lbu/c;Lh01/o;Z)V
    .locals 0

    const-string p3, "routeDatabase"

    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 4
    iput-object p2, p0, Lb0/n1;->h:Ljava/lang/Object;

    .line 5
    iput-boolean p4, p0, Lb0/n1;->e:Z

    .line 6
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    iput-object p2, p0, Lb0/n1;->i:Ljava/lang/Object;

    .line 7
    iput-object p2, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 8
    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 9
    iget-object p2, p1, Ld01/a;->h:Ld01/a0;

    .line 10
    const-string p3, "url"

    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    invoke-virtual {p2}, Ld01/a0;->j()Ljava/net/URI;

    move-result-object p2

    .line 12
    invoke-virtual {p2}, Ljava/net/URI;->getHost()Ljava/lang/String;

    move-result-object p3

    if-nez p3, :cond_0

    sget-object p1, Ljava/net/Proxy;->NO_PROXY:Ljava/net/Proxy;

    filled-new-array {p1}, [Ljava/net/Proxy;

    move-result-object p1

    .line 13
    invoke-static {p1}, Le01/g;->k([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    goto :goto_1

    .line 14
    :cond_0
    iget-object p1, p1, Ld01/a;->g:Ljava/net/ProxySelector;

    .line 15
    invoke-virtual {p1, p2}, Ljava/net/ProxySelector;->select(Ljava/net/URI;)Ljava/util/List;

    move-result-object p1

    .line 16
    move-object p2, p1

    check-cast p2, Ljava/util/Collection;

    if-eqz p2, :cond_2

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_1

    goto :goto_0

    .line 17
    :cond_1
    invoke-static {p1}, Le01/g;->j(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    goto :goto_1

    .line 18
    :cond_2
    :goto_0
    sget-object p1, Ljava/net/Proxy;->NO_PROXY:Ljava/net/Proxy;

    filled-new-array {p1}, [Ljava/net/Proxy;

    move-result-object p1

    .line 19
    invoke-static {p1}, Le01/g;->k([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    .line 20
    :goto_1
    iput-object p1, p0, Lb0/n1;->i:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 21
    iput p1, p0, Lb0/n1;->d:I

    return-void
.end method

.method public constructor <init>(Lh0/c1;)V
    .locals 2

    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 24
    iput v0, p0, Lb0/n1;->d:I

    .line 25
    iput-boolean v0, p0, Lb0/n1;->e:Z

    .line 26
    new-instance v0, Lb0/n0;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Lb0/n0;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 27
    iput-object p1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 28
    invoke-interface {p1}, Lh0/c1;->getSurface()Landroid/view/Surface;

    move-result-object p1

    iput-object p1, p0, Lb0/n1;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/o0;)V
    .locals 4

    .line 36
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 37
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 38
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    move-result-object v1

    iput-object v1, p0, Lb0/n1;->g:Ljava/lang/Object;

    const/4 v1, -0x1

    .line 39
    iput v1, p0, Lb0/n1;->d:I

    .line 40
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Lb0/n1;->h:Ljava/lang/Object;

    const/4 v2, 0x0

    .line 41
    iput-boolean v2, p0, Lb0/n1;->e:Z

    .line 42
    invoke-static {}, Lh0/k1;->a()Lh0/k1;

    move-result-object v2

    iput-object v2, p0, Lb0/n1;->i:Ljava/lang/Object;

    .line 43
    iget-object v2, p1, Lh0/o0;->a:Ljava/util/ArrayList;

    invoke-interface {v0, v2}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 44
    iget-object v0, p1, Lh0/o0;->b:Lh0/n1;

    invoke-static {v0}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    move-result-object v0

    iput-object v0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 45
    iget v0, p1, Lh0/o0;->c:I

    iput v0, p0, Lb0/n1;->d:I

    .line 46
    iget-object v0, p1, Lh0/o0;->d:Ljava/util/List;

    .line 47
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 48
    iget-boolean v0, p1, Lh0/o0;->e:Z

    .line 49
    iput-boolean v0, p0, Lb0/n1;->e:Z

    .line 50
    iget-object p1, p1, Lh0/o0;->f:Lh0/j2;

    .line 51
    new-instance v0, Landroid/util/ArrayMap;

    invoke-direct {v0}, Landroid/util/ArrayMap;-><init>()V

    .line 52
    iget-object v1, p1, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 53
    invoke-virtual {v1}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    move-result-object v1

    .line 54
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    .line 55
    iget-object v3, p1, Lh0/j2;->a:Landroid/util/ArrayMap;

    invoke-virtual {v3, v2}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    .line 56
    invoke-virtual {v0, v2, v3}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    .line 57
    :cond_0
    new-instance p1, Lh0/k1;

    .line 58
    invoke-direct {p1, v0}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 59
    iput-object p1, p0, Lb0/n1;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/util/List;ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lb0/n1;->f:Ljava/lang/Object;

    iput-object p2, p0, Lb0/n1;->g:Ljava/lang/Object;

    iput p3, p0, Lb0/n1;->d:I

    iput-object p4, p0, Lb0/n1;->h:Ljava/lang/Object;

    iput-object p5, p0, Lb0/n1;->i:Ljava/lang/Object;

    iput-object p6, p0, Lb0/n1;->j:Ljava/lang/Object;

    iput-boolean p7, p0, Lb0/n1;->e:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/util/Collection;)V
    .locals 1

    .line 1
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lh0/m;

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lb0/n1;->c(Lh0/m;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    return-void
.end method

.method public b()Lb0/a1;
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {v1}, Lh0/c1;->b()Lb0/a1;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    iget v2, p0, Lb0/n1;->d:I

    .line 15
    .line 16
    add-int/lit8 v2, v2, 0x1

    .line 17
    .line 18
    iput v2, p0, Lb0/n1;->d:I

    .line 19
    .line 20
    new-instance v2, Lb0/o0;

    .line 21
    .line 22
    invoke-direct {v2, v1}, Lb0/o0;-><init>(Lb0/a1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lb0/n0;

    .line 28
    .line 29
    invoke-virtual {v2, p0}, Lb0/b0;->a(Lb0/a0;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v2, 0x0

    .line 34
    :goto_0
    monitor-exit v0

    .line 35
    return-object v2

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0
.end method

.method public c(Lh0/m;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lb0/n1;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public close()V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lb0/n1;->h:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Landroid/view/Surface;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    invoke-virtual {v1}, Landroid/view/Surface;->release()V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    :goto_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lh0/c1;

    .line 19
    .line 20
    invoke-interface {p0}, Lh0/c1;->close()V

    .line 21
    .line 22
    .line 23
    monitor-exit v0

    .line 24
    return-void

    .line 25
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    throw p0
.end method

.method public d()I
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {p0}, Lh0/c1;->d()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public e()V
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {p0}, Lh0/c1;->e()V

    .line 9
    .line 10
    .line 11
    monitor-exit v0

    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method

.method public f()I
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {p0}, Lh0/c1;->f()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public g(Lh0/b1;Ljava/util/concurrent/Executor;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Lh0/c1;

    .line 7
    .line 8
    new-instance v2, La0/h;

    .line 9
    .line 10
    const/4 v3, 0x2

    .line 11
    invoke-direct {v2, v3, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    invoke-interface {v1, v2, p2}, Lh0/c1;->g(Lh0/b1;Ljava/util/concurrent/Executor;)V

    .line 15
    .line 16
    .line 17
    monitor-exit v0

    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0
.end method

.method public getSurface()Landroid/view/Surface;
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {p0}, Lh0/c1;->getSurface()Landroid/view/Surface;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    monitor-exit v0

    .line 13
    return-object p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public h()Lb0/a1;
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {v1}, Lh0/c1;->h()Lb0/a1;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    iget v2, p0, Lb0/n1;->d:I

    .line 15
    .line 16
    add-int/lit8 v2, v2, 0x1

    .line 17
    .line 18
    iput v2, p0, Lb0/n1;->d:I

    .line 19
    .line 20
    new-instance v2, Lb0/o0;

    .line 21
    .line 22
    invoke-direct {v2, v1}, Lb0/o0;-><init>(Lb0/a1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lb0/n0;

    .line 28
    .line 29
    invoke-virtual {v2, p0}, Lb0/b0;->a(Lb0/a0;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v2, 0x0

    .line 34
    :goto_0
    monitor-exit v0

    .line 35
    return-object v2

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0
.end method

.method public i(Lh0/q0;)V
    .locals 5

    .line 1
    invoke-interface {p1}, Lh0/q0;->d()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lh0/g;

    .line 20
    .line 21
    iget-object v2, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Lh0/j1;

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-virtual {v2, v1, v3}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    invoke-interface {p1, v1}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    iget-object v3, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v3, Lh0/j1;

    .line 36
    .line 37
    invoke-interface {p1, v1}, Lh0/q0;->e(Lh0/g;)Lh0/p0;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    invoke-virtual {v3, v1, v4, v2}, Lh0/j1;->m(Lh0/g;Lh0/p0;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    return-void
.end method

.method public j()Lh0/o0;
    .locals 11

    .line 1
    new-instance v0, Lh0/o0;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    iget-object v2, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/util/HashSet;

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lh0/j1;

    .line 15
    .line 16
    invoke-static {v2}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    iget v3, p0, Lb0/n1;->d:I

    .line 21
    .line 22
    new-instance v4, Ljava/util/ArrayList;

    .line 23
    .line 24
    iget-object v5, p0, Lb0/n1;->h:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v5, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 29
    .line 30
    .line 31
    iget-boolean v5, p0, Lb0/n1;->e:Z

    .line 32
    .line 33
    iget-object v6, p0, Lb0/n1;->i:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v6, Lh0/k1;

    .line 36
    .line 37
    sget-object v7, Lh0/j2;->b:Lh0/j2;

    .line 38
    .line 39
    new-instance v7, Landroid/util/ArrayMap;

    .line 40
    .line 41
    invoke-direct {v7}, Landroid/util/ArrayMap;-><init>()V

    .line 42
    .line 43
    .line 44
    iget-object v8, v6, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 45
    .line 46
    invoke-virtual {v8}, Landroid/util/ArrayMap;->keySet()Ljava/util/Set;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object v8

    .line 54
    :goto_0
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v9

    .line 58
    if-eqz v9, :cond_0

    .line 59
    .line 60
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v9

    .line 64
    check-cast v9, Ljava/lang/String;

    .line 65
    .line 66
    iget-object v10, v6, Lh0/j2;->a:Landroid/util/ArrayMap;

    .line 67
    .line 68
    invoke-virtual {v10, v9}, Landroid/util/ArrayMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v10

    .line 72
    invoke-virtual {v7, v9, v10}, Landroid/util/ArrayMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    new-instance v6, Lh0/j2;

    .line 77
    .line 78
    invoke-direct {v6, v7}, Lh0/j2;-><init>(Landroid/util/ArrayMap;)V

    .line 79
    .line 80
    .line 81
    iget-object p0, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v7, p0

    .line 84
    check-cast v7, Lh0/s;

    .line 85
    .line 86
    invoke-direct/range {v0 .. v7}, Lh0/o0;-><init>(Ljava/util/ArrayList;Lh0/n1;ILjava/util/ArrayList;ZLh0/j2;Lh0/s;)V

    .line 87
    .line 88
    .line 89
    return-object v0
.end method

.method public k(Ltl/h;Lol/f;)V
    .locals 3

    .line 1
    iget-object v0, p1, Ltl/h;->a:Landroid/content/Context;

    .line 2
    .line 3
    iget-object p0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ltl/h;

    .line 6
    .line 7
    iget-object v1, p0, Ltl/h;->a:Landroid/content/Context;

    .line 8
    .line 9
    const-string v2, "Interceptor \'"

    .line 10
    .line 11
    if-ne v0, v1, :cond_4

    .line 12
    .line 13
    iget-object v0, p1, Ltl/h;->b:Ljava/lang/Object;

    .line 14
    .line 15
    sget-object v1, Ltl/j;->a:Ltl/j;

    .line 16
    .line 17
    if-eq v0, v1, :cond_3

    .line 18
    .line 19
    iget-object v0, p1, Ltl/h;->c:Lvl/a;

    .line 20
    .line 21
    iget-object v1, p0, Ltl/h;->c:Lvl/a;

    .line 22
    .line 23
    if-ne v0, v1, :cond_2

    .line 24
    .line 25
    iget-object v0, p1, Ltl/h;->u:Landroidx/lifecycle/r;

    .line 26
    .line 27
    iget-object v1, p0, Ltl/h;->u:Landroidx/lifecycle/r;

    .line 28
    .line 29
    if-ne v0, v1, :cond_1

    .line 30
    .line 31
    iget-object p1, p1, Ltl/h;->v:Lul/h;

    .line 32
    .line 33
    iget-object p0, p0, Ltl/h;->v:Lul/h;

    .line 34
    .line 35
    if-ne p1, p0, :cond_0

    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string p1, "\' cannot modify the request\'s size resolver. Use `Interceptor.Chain.withSize` instead."

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1

    .line 65
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string p1, "\' cannot modify the request\'s lifecycle."

    .line 74
    .line 75
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p1

    .line 92
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 93
    .line 94
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string p1, "\' cannot modify the request\'s target."

    .line 101
    .line 102
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p1

    .line 119
    :cond_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string p1, "\' cannot set the request\'s data to null."

    .line 128
    .line 129
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 137
    .line 138
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw p1

    .line 146
    :cond_4
    new-instance p0, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    const-string p1, "\' cannot modify the request\'s context."

    .line 155
    .line 156
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 164
    .line 165
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw p1
.end method

.method public l()Landroid/util/Range;
    .locals 2

    .line 1
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/j1;

    .line 4
    .line 5
    sget-object v0, Lh0/o0;->j:Lh0/g;

    .line 6
    .line 7
    sget-object v1, Lh0/k;->h:Landroid/util/Range;

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Landroid/util/Range;

    .line 14
    .line 15
    return-object p0
.end method

.method public m()I
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {p0}, Lh0/c1;->m()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public n()Z
    .locals 2

    .line 1
    iget v0, p0, Lb0/n1;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lb0/n1;->i:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-ge v0, v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object p0, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-nez p0, :cond_1

    .line 23
    .line 24
    :goto_0
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    :cond_1
    const/4 p0, 0x0

    .line 27
    return p0
.end method

.method public o()I
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lh0/c1;

    .line 7
    .line 8
    invoke-interface {p0}, Lh0/c1;->o()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    monitor-exit v0

    .line 13
    return p0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public p(Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v2, v0

    .line 4
    check-cast v2, Lmm/g;

    .line 5
    .line 6
    iget v0, p0, Lb0/n1;->d:I

    .line 7
    .line 8
    instance-of v1, p1, Lem/h;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    move-object v1, p1

    .line 13
    check-cast v1, Lem/h;

    .line 14
    .line 15
    iget v3, v1, Lem/h;->g:I

    .line 16
    .line 17
    const/high16 v4, -0x80000000

    .line 18
    .line 19
    and-int v5, v3, v4

    .line 20
    .line 21
    if-eqz v5, :cond_0

    .line 22
    .line 23
    sub-int/2addr v3, v4

    .line 24
    iput v3, v1, Lem/h;->g:I

    .line 25
    .line 26
    :goto_0
    move-object p1, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    new-instance v1, Lem/h;

    .line 29
    .line 30
    invoke-direct {v1, p0, p1}, Lem/h;-><init>(Lb0/n1;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :goto_1
    iget-object v1, p1, Lem/h;->e:Ljava/lang/Object;

    .line 35
    .line 36
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    iget v3, p1, Lem/h;->g:I

    .line 39
    .line 40
    const/4 v10, 0x1

    .line 41
    if-eqz v3, :cond_2

    .line 42
    .line 43
    if-ne v3, v10, :cond_1

    .line 44
    .line 45
    iget-object p0, p1, Lem/h;->d:Lem/f;

    .line 46
    .line 47
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iget-object v1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v1, Ljava/util/List;

    .line 65
    .line 66
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    move-object v11, v1

    .line 71
    check-cast v11, Lem/f;

    .line 72
    .line 73
    add-int/lit8 v4, v0, 0x1

    .line 74
    .line 75
    iget-object v0, p0, Lb0/n1;->h:Ljava/lang/Object;

    .line 76
    .line 77
    move-object v5, v0

    .line 78
    check-cast v5, Lmm/g;

    .line 79
    .line 80
    iget-object v0, p0, Lb0/n1;->i:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v6, v0

    .line 83
    check-cast v6, Lnm/h;

    .line 84
    .line 85
    new-instance v1, Lb0/n1;

    .line 86
    .line 87
    iget-object v0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 88
    .line 89
    move-object v3, v0

    .line 90
    check-cast v3, Ljava/util/List;

    .line 91
    .line 92
    iget-object v0, p0, Lb0/n1;->j:Ljava/lang/Object;

    .line 93
    .line 94
    move-object v7, v0

    .line 95
    check-cast v7, Lyl/f;

    .line 96
    .line 97
    iget-boolean v8, p0, Lb0/n1;->e:Z

    .line 98
    .line 99
    invoke-direct/range {v1 .. v8}, Lb0/n1;-><init>(Ljava/lang/Object;Ljava/util/List;ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 100
    .line 101
    .line 102
    iput-object v11, p1, Lem/h;->d:Lem/f;

    .line 103
    .line 104
    iput v10, p1, Lem/h;->g:I

    .line 105
    .line 106
    invoke-virtual {v11, v1, p1}, Lem/f;->d(Lb0/n1;Lrx0/c;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    if-ne v1, v9, :cond_3

    .line 111
    .line 112
    return-object v9

    .line 113
    :cond_3
    move-object p0, v11

    .line 114
    :goto_2
    check-cast v1, Lmm/j;

    .line 115
    .line 116
    invoke-interface {v1}, Lmm/j;->a()Lmm/g;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    iget-object v0, p1, Lmm/g;->a:Landroid/content/Context;

    .line 121
    .line 122
    iget-object v3, v2, Lmm/g;->a:Landroid/content/Context;

    .line 123
    .line 124
    const-string v4, "Interceptor \'"

    .line 125
    .line 126
    if-ne v0, v3, :cond_7

    .line 127
    .line 128
    iget-object v0, p1, Lmm/g;->b:Ljava/lang/Object;

    .line 129
    .line 130
    sget-object v3, Lmm/l;->a:Lmm/l;

    .line 131
    .line 132
    if-eq v0, v3, :cond_6

    .line 133
    .line 134
    iget-object v0, p1, Lmm/g;->c:Lqm/a;

    .line 135
    .line 136
    iget-object v3, v2, Lmm/g;->c:Lqm/a;

    .line 137
    .line 138
    if-ne v0, v3, :cond_5

    .line 139
    .line 140
    iget-object p1, p1, Lmm/g;->o:Lnm/i;

    .line 141
    .line 142
    iget-object v0, v2, Lmm/g;->o:Lnm/i;

    .line 143
    .line 144
    if-ne p1, v0, :cond_4

    .line 145
    .line 146
    return-object v1

    .line 147
    :cond_4
    new-instance p1, Ljava/lang/StringBuilder;

    .line 148
    .line 149
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    const-string p0, "\' cannot modify the request\'s size resolver. Use `Interceptor.Chain.withSize` instead."

    .line 156
    .line 157
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 165
    .line 166
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    throw p1

    .line 174
    :cond_5
    new-instance p1, Ljava/lang/StringBuilder;

    .line 175
    .line 176
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    const-string p0, "\' cannot modify the request\'s target."

    .line 183
    .line 184
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 192
    .line 193
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    throw p1

    .line 201
    :cond_6
    new-instance p1, Ljava/lang/StringBuilder;

    .line 202
    .line 203
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    const-string p0, "\' cannot set the request\'s data to null."

    .line 210
    .line 211
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 219
    .line 220
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    throw p1

    .line 228
    :cond_7
    new-instance p1, Ljava/lang/StringBuilder;

    .line 229
    .line 230
    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    const-string p0, "\' cannot modify the request\'s context."

    .line 237
    .line 238
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 246
    .line 247
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object p0

    .line 251
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    throw p1
.end method

.method public q(Ltl/h;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v0, Lb0/n1;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Ljava/util/List;

    .line 8
    .line 9
    iget v3, v0, Lb0/n1;->d:I

    .line 10
    .line 11
    instance-of v4, v1, Lol/g;

    .line 12
    .line 13
    if-eqz v4, :cond_0

    .line 14
    .line 15
    move-object v4, v1

    .line 16
    check-cast v4, Lol/g;

    .line 17
    .line 18
    iget v5, v4, Lol/g;->h:I

    .line 19
    .line 20
    const/high16 v6, -0x80000000

    .line 21
    .line 22
    and-int v7, v5, v6

    .line 23
    .line 24
    if-eqz v7, :cond_0

    .line 25
    .line 26
    sub-int/2addr v5, v6

    .line 27
    iput v5, v4, Lol/g;->h:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v4, Lol/g;

    .line 31
    .line 32
    invoke-direct {v4, v0, v1}, Lol/g;-><init>(Lb0/n1;Lrx0/c;)V

    .line 33
    .line 34
    .line 35
    :goto_0
    iget-object v1, v4, Lol/g;->f:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v6, v4, Lol/g;->h:I

    .line 40
    .line 41
    const/4 v7, 0x1

    .line 42
    if-eqz v6, :cond_2

    .line 43
    .line 44
    if-ne v6, v7, :cond_1

    .line 45
    .line 46
    iget-object v0, v4, Lol/g;->e:Lol/f;

    .line 47
    .line 48
    iget-object v2, v4, Lol/g;->d:Lb0/n1;

    .line 49
    .line 50
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    move-object/from16 v16, v1

    .line 54
    .line 55
    move-object v1, v0

    .line 56
    move-object v0, v2

    .line 57
    move-object/from16 v2, v16

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 63
    .line 64
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0

    .line 68
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    if-lez v3, :cond_3

    .line 72
    .line 73
    add-int/lit8 v1, v3, -0x1

    .line 74
    .line 75
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Lol/f;

    .line 80
    .line 81
    move-object/from16 v12, p1

    .line 82
    .line 83
    invoke-virtual {v0, v12, v1}, Lb0/n1;->k(Ltl/h;Lol/f;)V

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_3
    move-object/from16 v12, p1

    .line 88
    .line 89
    :goto_1
    invoke-interface {v2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Lol/f;

    .line 94
    .line 95
    add-int/lit8 v11, v3, 0x1

    .line 96
    .line 97
    iget-object v2, v0, Lb0/n1;->i:Ljava/lang/Object;

    .line 98
    .line 99
    move-object v13, v2

    .line 100
    check-cast v13, Lul/g;

    .line 101
    .line 102
    new-instance v8, Lb0/n1;

    .line 103
    .line 104
    iget-object v2, v0, Lb0/n1;->f:Ljava/lang/Object;

    .line 105
    .line 106
    move-object v9, v2

    .line 107
    check-cast v9, Ltl/h;

    .line 108
    .line 109
    iget-object v2, v0, Lb0/n1;->g:Ljava/lang/Object;

    .line 110
    .line 111
    move-object v10, v2

    .line 112
    check-cast v10, Ljava/util/List;

    .line 113
    .line 114
    iget-object v2, v0, Lb0/n1;->j:Ljava/lang/Object;

    .line 115
    .line 116
    move-object v14, v2

    .line 117
    check-cast v14, Lil/d;

    .line 118
    .line 119
    iget-boolean v15, v0, Lb0/n1;->e:Z

    .line 120
    .line 121
    invoke-direct/range {v8 .. v15}, Lb0/n1;-><init>(Ljava/lang/Object;Ljava/util/List;ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 122
    .line 123
    .line 124
    iput-object v0, v4, Lol/g;->d:Lb0/n1;

    .line 125
    .line 126
    iput-object v1, v4, Lol/g;->e:Lol/f;

    .line 127
    .line 128
    iput v7, v4, Lol/g;->h:I

    .line 129
    .line 130
    invoke-virtual {v1, v8, v4}, Lol/f;->d(Lb0/n1;Lrx0/c;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    if-ne v2, v5, :cond_4

    .line 135
    .line 136
    return-object v5

    .line 137
    :cond_4
    :goto_2
    check-cast v2, Ltl/i;

    .line 138
    .line 139
    invoke-virtual {v2}, Ltl/i;->b()Ltl/h;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    invoke-virtual {v0, v3, v1}, Lb0/n1;->k(Ltl/h;Lol/f;)V

    .line 144
    .line 145
    .line 146
    return-object v2
.end method

.method public r()V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/n1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    const/4 v1, 0x1

    .line 5
    :try_start_0
    iput-boolean v1, p0, Lb0/n1;->e:Z

    .line 6
    .line 7
    iget-object v1, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Lh0/c1;

    .line 10
    .line 11
    invoke-interface {v1}, Lh0/c1;->e()V

    .line 12
    .line 13
    .line 14
    iget v1, p0, Lb0/n1;->d:I

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lb0/n1;->close()V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    :goto_0
    monitor-exit v0

    .line 25
    return-void

    .line 26
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    throw p0
.end method
