.class public abstract Lb0/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/a1;


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Lb0/a1;

.field public final f:Ljava/util/HashSet;


# direct methods
.method public constructor <init>(Lb0/a1;)V
    .locals 1

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
    iput-object v0, p0, Lb0/b0;->d:Ljava/lang/Object;

    .line 10
    .line 11
    new-instance v0, Ljava/util/HashSet;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lb0/b0;->f:Ljava/util/HashSet;

    .line 17
    .line 18
    iput-object p1, p0, Lb0/b0;->e:Lb0/a1;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public R()[Lb0/z0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {p0}, Lb0/a1;->R()[Lb0/z0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final a(Lb0/a0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/b0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/b0;->f:Ljava/util/HashSet;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

.method public close()V
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/lang/AutoCloseable;->close()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb0/b0;->d:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v0

    .line 9
    :try_start_0
    new-instance v1, Ljava/util/HashSet;

    .line 10
    .line 11
    iget-object v2, p0, Lb0/b0;->f:Ljava/util/HashSet;

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 14
    .line 15
    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Lb0/a0;

    .line 32
    .line 33
    invoke-interface {v1, p0}, Lb0/a0;->a(Lb0/b0;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    throw p0
.end method

.method public final getFormat()I
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {p0}, Lb0/a1;->getFormat()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public i0()Lb0/v0;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {p0}, Lb0/a1;->i0()Lb0/v0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public m()I
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {p0}, Lb0/a1;->m()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {p0}, Lb0/a1;->o()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final r()Landroid/media/Image;
    .locals 0

    .line 1
    iget-object p0, p0, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {p0}, Lb0/a1;->r()Landroid/media/Image;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
