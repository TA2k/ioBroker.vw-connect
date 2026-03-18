.class public final Lj01/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/f0;


# instance fields
.field public final d:Lu01/o;

.field public e:Z

.field public final synthetic f:Lj01/f;


# direct methods
.method public constructor <init>(Lj01/f;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj01/b;->f:Lj01/f;

    .line 5
    .line 6
    new-instance v0, Lu01/o;

    .line 7
    .line 8
    iget-object p1, p1, Lj01/f;->c:Lgw0/c;

    .line 9
    .line 10
    iget-object p1, p1, Lgw0/c;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p1, Lu01/a0;

    .line 13
    .line 14
    iget-object p1, p1, Lu01/a0;->d:Lu01/f0;

    .line 15
    .line 16
    invoke-interface {p1}, Lu01/f0;->timeout()Lu01/j0;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-direct {v0, p1}, Lu01/o;-><init>(Lu01/j0;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lj01/b;->d:Lu01/o;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final F(Lu01/f;J)V
    .locals 4

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lj01/b;->e:Z

    .line 7
    .line 8
    const-string v1, "closed"

    .line 9
    .line 10
    if-nez v0, :cond_2

    .line 11
    .line 12
    const-wide/16 v2, 0x0

    .line 13
    .line 14
    cmp-long v0, p2, v2

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object p0, p0, Lj01/b;->f:Lj01/f;

    .line 20
    .line 21
    iget-object p0, p0, Lj01/f;->c:Lgw0/c;

    .line 22
    .line 23
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lu01/a0;

    .line 26
    .line 27
    iget-boolean v0, p0, Lu01/a0;->f:Z

    .line 28
    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    iget-object v0, p0, Lu01/a0;->e:Lu01/f;

    .line 32
    .line 33
    invoke-virtual {v0, p2, p3}, Lu01/f;->l0(J)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Lu01/a0;->a()Lu01/g;

    .line 37
    .line 38
    .line 39
    const-string v0, "\r\n"

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, p1, p2, p3}, Lu01/a0;->F(Lu01/f;J)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, v0}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public final declared-synchronized close()V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lj01/b;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x1

    .line 9
    :try_start_1
    iput-boolean v0, p0, Lj01/b;->e:Z

    .line 10
    .line 11
    iget-object v0, p0, Lj01/b;->f:Lj01/f;

    .line 12
    .line 13
    iget-object v0, v0, Lj01/f;->c:Lgw0/c;

    .line 14
    .line 15
    iget-object v0, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lu01/a0;

    .line 18
    .line 19
    const-string v1, "0\r\n\r\n"

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lj01/b;->d:Lu01/o;

    .line 25
    .line 26
    iget-object v1, v0, Lu01/o;->e:Lu01/j0;

    .line 27
    .line 28
    sget-object v2, Lu01/j0;->d:Lu01/i0;

    .line 29
    .line 30
    iput-object v2, v0, Lu01/o;->e:Lu01/j0;

    .line 31
    .line 32
    invoke-virtual {v1}, Lu01/j0;->a()Lu01/j0;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1}, Lu01/j0;->b()Lu01/j0;

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Lj01/b;->f:Lj01/f;

    .line 39
    .line 40
    const/4 v1, 0x3

    .line 41
    iput v1, v0, Lj01/f;->d:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    .line 43
    monitor-exit p0

    .line 44
    return-void

    .line 45
    :catchall_0
    move-exception v0

    .line 46
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 47
    throw v0
.end method

.method public final declared-synchronized flush()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lj01/b;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    :try_start_1
    iget-object v0, p0, Lj01/b;->f:Lj01/f;

    .line 9
    .line 10
    iget-object v0, v0, Lj01/f;->c:Lgw0/c;

    .line 11
    .line 12
    iget-object v0, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lu01/a0;

    .line 15
    .line 16
    invoke-virtual {v0}, Lu01/a0;->flush()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 17
    .line 18
    .line 19
    monitor-exit p0

    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception v0

    .line 22
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 23
    throw v0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lj01/b;->d:Lu01/o;

    .line 2
    .line 3
    return-object p0
.end method
