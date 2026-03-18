.class public abstract Li0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static volatile a:Landroid/os/Handler;


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x4af006c4    # 7865186.0f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    if-nez p1, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0}, Ll2/t;->A()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 19
    .line 20
    .line 21
    goto :goto_2

    .line 22
    :cond_1
    :goto_0
    sget v0, La7/c1;->d:I

    .line 23
    .line 24
    const v0, -0x428332f6

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ll2/t;->Z(I)V

    .line 28
    .line 29
    .line 30
    const v0, 0x7076b8d0

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ll2/t;->Z(I)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Ll2/t;->a:Leb/j0;

    .line 37
    .line 38
    instance-of v0, v0, Ly6/b;

    .line 39
    .line 40
    if-eqz v0, :cond_4

    .line 41
    .line 42
    invoke-virtual {p0}, Ll2/t;->W()V

    .line 43
    .line 44
    .line 45
    iget-boolean v0, p0, Ll2/t;->S:Z

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    const/4 v2, 0x0

    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    new-instance v0, La7/w;

    .line 52
    .line 53
    invoke-direct {v0, v2, v1}, La7/w;-><init>(II)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ll2/t;->l(Lay0/a;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    invoke-virtual {p0}, Ll2/t;->m0()V

    .line 61
    .line 62
    .line 63
    :goto_1
    invoke-static {p0, v1, v2, v2}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 64
    .line 65
    .line 66
    :goto_2
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-eqz p0, :cond_3

    .line 71
    .line 72
    new-instance v0, La7/i1;

    .line 73
    .line 74
    invoke-direct {v0, p1}, La7/i1;-><init>(I)V

    .line 75
    .line 76
    .line 77
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 78
    .line 79
    :cond_3
    return-void

    .line 80
    :cond_4
    invoke-static {}, Ll2/b;->l()V

    .line 81
    .line 82
    .line 83
    const/4 p0, 0x0

    .line 84
    throw p0
.end method

.method public static final b(Lz4/q;Ljava/util/List;)V
    .locals 4

    .line 1
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_2

    .line 7
    .line 8
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Lt3/p0;

    .line 13
    .line 14
    invoke-static {v2}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    if-nez v3, :cond_0

    .line 19
    .line 20
    invoke-interface {v2}, Lt3/p0;->l()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    new-instance v3, Lz4/b;

    .line 24
    .line 25
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {p0, v3}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    iput-object v2, v3, Le5/b;->f0:Lt3/p0;

    .line 39
    .line 40
    iget-object v3, v3, Le5/b;->g0:Lh5/d;

    .line 41
    .line 42
    if-eqz v3, :cond_1

    .line 43
    .line 44
    iput-object v2, v3, Lh5/d;->g0:Ljava/lang/Object;

    .line 45
    .line 46
    :cond_1
    invoke-interface {v2}, Lt3/p0;->l()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    add-int/lit8 v1, v1, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    return-void
.end method

.method public static c()Landroid/os/Handler;
    .locals 2

    .line 1
    sget-object v0, Li0/d;->a:Landroid/os/Handler;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Li0/d;->a:Landroid/os/Handler;

    .line 6
    .line 7
    return-object v0

    .line 8
    :cond_0
    const-class v0, Li0/d;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    sget-object v1, Li0/d;->a:Landroid/os/Handler;

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-static {v1}, Landroid/os/Handler;->createAsync(Landroid/os/Looper;)Landroid/os/Handler;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    sput-object v1, Li0/d;->a:Landroid/os/Handler;

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception v1

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    sget-object v0, Li0/d;->a:Landroid/os/Handler;

    .line 30
    .line 31
    return-object v0

    .line 32
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    throw v1
.end method

.method public static final d(Ll70/h;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    const p0, 0x7f120242

    .line 19
    .line 20
    .line 21
    return p0

    .line 22
    :cond_0
    new-instance p0, La8/r0;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    const p0, 0x7f120241

    .line 29
    .line 30
    .line 31
    return p0

    .line 32
    :cond_2
    const p0, 0x7f120243

    .line 33
    .line 34
    .line 35
    return p0
.end method

.method public static final e(Ly6/l;)Z
    .locals 2

    .line 1
    instance-of v0, p0, La7/c0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    instance-of v0, p0, Ly6/n;

    .line 8
    .line 9
    if-eqz v0, :cond_3

    .line 10
    .line 11
    check-cast p0, Ly6/n;

    .line 12
    .line 13
    iget-object p0, p0, Ly6/n;->b:Ljava/util/ArrayList;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Ly6/l;

    .line 39
    .line 40
    invoke-static {v0}, Li0/d;->e(Ly6/l;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    return v1

    .line 47
    :cond_3
    :goto_0
    const/4 p0, 0x0

    .line 48
    return p0
.end method
