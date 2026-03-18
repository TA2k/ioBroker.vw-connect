.class public abstract Lb0/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/HashSet;

.field public final b:Ljava/lang/Object;

.field public c:I

.field public d:Lh0/o2;

.field public final e:Ljava/lang/Object;

.field public f:Ljava/util/HashSet;

.field public g:Lh0/o2;

.field public h:Lh0/k;

.field public i:Lh0/o2;

.field public j:Landroid/graphics/Rect;

.field public k:Landroid/graphics/Matrix;

.field public l:Lh0/b0;

.field public m:Lh0/b0;

.field public n:Lh0/z1;

.field public o:Lh0/z1;


# direct methods
.method public constructor <init>(Lh0/o2;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashSet;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    iput v0, p0, Lb0/z1;->c:I

    .line 20
    .line 21
    new-instance v0, Landroid/graphics/Matrix;

    .line 22
    .line 23
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lb0/z1;->k:Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-static {}, Lh0/z1;->a()Lh0/z1;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lb0/z1;->n:Lh0/z1;

    .line 33
    .line 34
    invoke-static {}, Lh0/z1;->a()Lh0/z1;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    iput-object v0, p0, Lb0/z1;->o:Lh0/z1;

    .line 39
    .line 40
    iput-object p1, p0, Lb0/z1;->e:Ljava/lang/Object;

    .line 41
    .line 42
    iput-object p1, p0, Lb0/z1;->g:Lh0/o2;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public A(Landroid/graphics/Rect;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 2
    .line 3
    return-void
.end method

.method public final B(Lh0/b0;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lb0/z1;->y()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object v1, p0, Lb0/z1;->l:Lh0/b0;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-ne p1, v1, :cond_0

    .line 11
    .line 12
    iget-object v3, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 13
    .line 14
    invoke-virtual {v3, v1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    iput-object v2, p0, Lb0/z1;->l:Lh0/b0;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    :goto_0
    iget-object v1, p0, Lb0/z1;->m:Lh0/b0;

    .line 23
    .line 24
    if-ne p1, v1, :cond_1

    .line 25
    .line 26
    iget-object p1, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 27
    .line 28
    invoke-virtual {p1, v1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    iput-object v2, p0, Lb0/z1;->m:Lh0/b0;

    .line 32
    .line 33
    :cond_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    iput-object v2, p0, Lb0/z1;->h:Lh0/k;

    .line 35
    .line 36
    iput-object v2, p0, Lb0/z1;->j:Landroid/graphics/Rect;

    .line 37
    .line 38
    iget-object p1, p0, Lb0/z1;->e:Ljava/lang/Object;

    .line 39
    .line 40
    iput-object p1, p0, Lb0/z1;->g:Lh0/o2;

    .line 41
    .line 42
    iput-object v2, p0, Lb0/z1;->d:Lh0/o2;

    .line 43
    .line 44
    iput-object v2, p0, Lb0/z1;->i:Lh0/o2;

    .line 45
    .line 46
    return-void

    .line 47
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    throw p0
.end method

.method public final C(Ljava/util/List;)V
    .locals 3

    .line 1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lh0/z1;

    .line 14
    .line 15
    iput-object v0, p0, Lb0/z1;->n:Lh0/z1;

    .line 16
    .line 17
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v1, 0x1

    .line 22
    if-le v0, v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Lh0/z1;

    .line 29
    .line 30
    iput-object v0, p0, Lb0/z1;->o:Lh0/z1;

    .line 31
    .line 32
    :cond_1
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_4

    .line 41
    .line 42
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Lh0/z1;

    .line 47
    .line 48
    invoke-virtual {v0}, Lh0/z1;->b()Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    :cond_3
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_2

    .line 61
    .line 62
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    check-cast v1, Lh0/t0;

    .line 67
    .line 68
    iget-object v2, v1, Lh0/t0;->j:Ljava/lang/Class;

    .line 69
    .line 70
    if-nez v2, :cond_3

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    iput-object v2, v1, Lh0/t0;->j:Ljava/lang/Class;

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_4
    :goto_1
    return-void
.end method

.method public final a(Lh0/v1;Lh0/k;)V
    .locals 4

    .line 1
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 2
    .line 3
    iget-object v1, p2, Lh0/k;->e:Landroid/util/Range;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    iget-object p0, p2, Lh0/k;->e:Landroid/util/Range;

    .line 12
    .line 13
    iget-object p1, p1, Lh0/u1;->b:Lb0/n1;

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    sget-object p2, Lh0/o0;->j:Lh0/g;

    .line 19
    .line 20
    iget-object p1, p1, Lb0/n1;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Lh0/j1;

    .line 23
    .line 24
    invoke-virtual {p1, p2, p0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    iget-object p2, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 29
    .line 30
    monitor-enter p2

    .line 31
    :try_start_0
    iget-object p0, p0, Lb0/z1;->l:Lh0/b0;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    invoke-interface {p0}, Lh0/b0;->l()Lh0/z;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-interface {p0}, Lh0/z;->j()Ld01/x;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-class v1, Landroidx/camera/core/internal/compat/quirk/AeFpsRangeQuirk;

    .line 45
    .line 46
    invoke-virtual {p0, v1}, Ld01/x;->n(Ljava/lang/Class;)Ljava/util/ArrayList;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    const/4 v2, 0x0

    .line 55
    const/4 v3, 0x1

    .line 56
    if-gt v1, v3, :cond_1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    move v3, v2

    .line 60
    :goto_0
    const-string v1, "There should not have more than one AeFpsRangeQuirk."

    .line 61
    .line 62
    invoke-static {v3, v1}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-nez v1, :cond_3

    .line 70
    .line 71
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    check-cast p0, Landroidx/camera/core/internal/compat/quirk/AeFpsRangeQuirk;

    .line 76
    .line 77
    check-cast p0, Landroidx/camera/camera2/internal/compat/quirk/AeFpsRangeLegacyQuirk;

    .line 78
    .line 79
    iget-object p0, p0, Landroidx/camera/camera2/internal/compat/quirk/AeFpsRangeLegacyQuirk;->a:Landroid/util/Range;

    .line 80
    .line 81
    if-eqz p0, :cond_2

    .line 82
    .line 83
    move-object v0, p0

    .line 84
    :cond_2
    iget-object p0, p1, Lh0/u1;->b:Lb0/n1;

    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    sget-object p1, Lh0/o0;->j:Lh0/g;

    .line 90
    .line 91
    iget-object p0, p0, Lb0/n1;->g:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Lh0/j1;

    .line 94
    .line 95
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    goto :goto_1

    .line 99
    :catchall_0
    move-exception p0

    .line 100
    goto :goto_2

    .line 101
    :cond_3
    :goto_1
    monitor-exit p2

    .line 102
    return-void

    .line 103
    :goto_2
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 104
    throw p0
.end method

.method public final b(Lh0/b0;Lh0/b0;Lh0/o2;Lh0/o2;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p1, p0, Lb0/z1;->l:Lh0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lb0/z1;->m:Lh0/b0;

    .line 7
    .line 8
    iget-object v1, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    iget-object v1, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 16
    .line 17
    invoke-virtual {v1, p2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    :cond_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    iput-object p3, p0, Lb0/z1;->d:Lh0/o2;

    .line 22
    .line 23
    iput-object p4, p0, Lb0/z1;->i:Lh0/o2;

    .line 24
    .line 25
    invoke-interface {p1}, Lh0/b0;->l()Lh0/z;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iget-object p2, p0, Lb0/z1;->d:Lh0/o2;

    .line 30
    .line 31
    iget-object p3, p0, Lb0/z1;->i:Lh0/o2;

    .line 32
    .line 33
    invoke-virtual {p0, p1, p2, p3}, Lb0/z1;->n(Lh0/z;Lh0/o2;Lh0/o2;)Lh0/o2;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iput-object p1, p0, Lb0/z1;->g:Lh0/o2;

    .line 38
    .line 39
    invoke-virtual {p0}, Lb0/z1;->r()V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    throw p0
.end method

.method public final c()Lh0/b0;
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/z1;->l:Lh0/b0;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public final d()Lh0/y;
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/z1;->l:Lh0/b0;

    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    sget-object p0, Lh0/y;->a:Lh0/x;

    .line 9
    .line 10
    monitor-exit v0

    .line 11
    return-object p0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-interface {p0}, Lh0/b0;->g()Lh0/y;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    monitor-exit v0

    .line 19
    return-object p0

    .line 20
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    throw p0
.end method

.method public final e()Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lb0/z1;->c()Lh0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "No camera attached to use case: "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {v0, p0}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {p0}, Lh0/z;->f()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public abstract f(ZLh0/r2;)Lh0/o2;
.end method

.method public final g()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lb0/z1;->g:Lh0/o2;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "<UnknownUseCase-"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, ">"

    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    sget-object v1, Ll0/k;->g1:Lh0/g;

    .line 27
    .line 28
    invoke-interface {v0, v1, p0}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final h(Lh0/b0;Z)I
    .locals 1

    .line 1
    invoke-interface {p1}, Lh0/b0;->l()Lh0/z;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 6
    .line 7
    check-cast p0, Lh0/a1;

    .line 8
    .line 9
    invoke-interface {p0}, Lh0/a1;->o()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-interface {v0, p0}, Lh0/z;->r(I)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    invoke-interface {p1}, Lh0/b0;->p()Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-nez p1, :cond_0

    .line 22
    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    neg-int p0, p0

    .line 26
    invoke-static {p0}, Li0/f;->i(I)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    :cond_0
    return p0
.end method

.method public final i()Lh0/b0;
    .locals 1

    .line 1
    iget-object v0, p0, Lb0/z1;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lb0/z1;->m:Lh0/b0;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public j(Lh0/z;)Ljava/util/Set;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public k()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract l(Lh0/q0;)Lh0/n2;
.end method

.method public final m(Lh0/b0;)Z
    .locals 3

    .line 1
    iget-object p0, p0, Lb0/z1;->g:Lh0/o2;

    .line 2
    .line 3
    check-cast p0, Lh0/a1;

    .line 4
    .line 5
    sget-object v0, Lh0/a1;->I0:Lh0/g;

    .line 6
    .line 7
    const/4 v1, -0x1

    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-interface {p0, v0, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eq p0, v1, :cond_2

    .line 23
    .line 24
    if-eqz p0, :cond_2

    .line 25
    .line 26
    const/4 v0, 0x1

    .line 27
    if-eq p0, v0, :cond_1

    .line 28
    .line 29
    const/4 v0, 0x2

    .line 30
    if-ne p0, v0, :cond_0

    .line 31
    .line 32
    invoke-interface {p1}, Lh0/b0;->n()Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_0
    new-instance p1, Ljava/lang/AssertionError;

    .line 38
    .line 39
    const-string v0, "Unknown mirrorMode: "

    .line 40
    .line 41
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {p1, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    throw p1

    .line 49
    :cond_1
    return v0

    .line 50
    :cond_2
    const/4 p0, 0x0

    .line 51
    return p0
.end method

.method public final n(Lh0/z;Lh0/o2;Lh0/o2;)Lh0/o2;
    .locals 10

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    invoke-static {p3}, Lh0/j1;->h(Lh0/q0;)Lh0/j1;

    .line 4
    .line 5
    .line 6
    move-result-object p3

    .line 7
    sget-object v0, Ll0/k;->g1:Lh0/g;

    .line 8
    .line 9
    iget-object v1, p3, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 16
    .line 17
    .line 18
    move-result-object p3

    .line 19
    :goto_0
    iget-object v0, p3, Lh0/n1;->d:Ljava/util/TreeMap;

    .line 20
    .line 21
    sget-object v1, Lh0/a1;->F0:Lh0/g;

    .line 22
    .line 23
    iget-object v2, p0, Lb0/z1;->e:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-interface {v2, v1}, Lh0/t1;->j(Lh0/g;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_1

    .line 30
    .line 31
    sget-object v1, Lh0/a1;->J0:Lh0/g;

    .line 32
    .line 33
    invoke-interface {v2, v1}, Lh0/t1;->j(Lh0/g;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    :cond_1
    sget-object v1, Lh0/a1;->N0:Lh0/g;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_2

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    :cond_2
    sget-object v1, Lh0/a1;->N0:Lh0/g;

    .line 51
    .line 52
    invoke-interface {v2, v1}, Lh0/t1;->j(Lh0/g;)Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-eqz v3, :cond_3

    .line 57
    .line 58
    sget-object v3, Lh0/a1;->L0:Lh0/g;

    .line 59
    .line 60
    invoke-virtual {v0, v3}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_3

    .line 65
    .line 66
    invoke-interface {v2, v1}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Ls0/b;

    .line 71
    .line 72
    iget-object v1, v1, Ls0/b;->b:Ls0/c;

    .line 73
    .line 74
    if-eqz v1, :cond_3

    .line 75
    .line 76
    invoke-virtual {v0, v3}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    :cond_3
    invoke-interface {v2}, Lh0/t1;->d()Ljava/util/Set;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    if-eqz v3, :cond_4

    .line 92
    .line 93
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    check-cast v3, Lh0/g;

    .line 98
    .line 99
    invoke-static {p3, p3, v2, v3}, Lh0/q0;->G(Lh0/j1;Lh0/q0;Lh0/q0;Lh0/g;)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    if-eqz p2, :cond_6

    .line 104
    .line 105
    invoke-interface {p2}, Lh0/t1;->d()Ljava/util/Set;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_6

    .line 118
    .line 119
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    check-cast v2, Lh0/g;

    .line 124
    .line 125
    iget-object v3, v2, Lh0/g;->a:Ljava/lang/String;

    .line 126
    .line 127
    sget-object v4, Ll0/k;->g1:Lh0/g;

    .line 128
    .line 129
    iget-object v4, v4, Lh0/g;->a:Ljava/lang/String;

    .line 130
    .line 131
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    if-eqz v3, :cond_5

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_5
    invoke-static {p3, p3, p2, v2}, Lh0/q0;->G(Lh0/j1;Lh0/q0;Lh0/q0;Lh0/g;)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_6
    sget-object p2, Lh0/a1;->J0:Lh0/g;

    .line 143
    .line 144
    invoke-virtual {v0, p2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    if-eqz p2, :cond_7

    .line 149
    .line 150
    sget-object p2, Lh0/a1;->F0:Lh0/g;

    .line 151
    .line 152
    invoke-virtual {v0, p2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    if-eqz v1, :cond_7

    .line 157
    .line 158
    invoke-virtual {v0, p2}, Ljava/util/TreeMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    :cond_7
    sget-object p2, Lh0/a1;->N0:Lh0/g;

    .line 162
    .line 163
    invoke-virtual {v0, p2}, Ljava/util/TreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-eqz v0, :cond_8

    .line 168
    .line 169
    invoke-virtual {p3, p2}, Lh0/n1;->f(Lh0/g;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p2

    .line 173
    check-cast p2, Ls0/b;

    .line 174
    .line 175
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    :cond_8
    const/4 p2, 0x0

    .line 179
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 180
    .line 181
    .line 182
    move-result-object p2

    .line 183
    const/4 v0, 0x2

    .line 184
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    const/4 v2, 0x1

    .line 189
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object v3

    .line 193
    new-instance v4, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    const-string v5, "applyFeaturesToConfig: mFeatureGroup = "

    .line 196
    .line 197
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    iget-object v5, p0, Lb0/z1;->f:Ljava/util/HashSet;

    .line 201
    .line 202
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    const-string v5, ", this = "

    .line 206
    .line 207
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    const-string v5, "UseCase"

    .line 218
    .line 219
    invoke-static {v5, v4}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    iget-object v4, p0, Lb0/z1;->f:Ljava/util/HashSet;

    .line 223
    .line 224
    if-nez v4, :cond_9

    .line 225
    .line 226
    goto/16 :goto_4

    .line 227
    .line 228
    :cond_9
    sget v5, Le0/a;->c:I

    .line 229
    .line 230
    sget-object v5, Lh0/k;->h:Landroid/util/Range;

    .line 231
    .line 232
    sget-object v6, Le0/f;->c:Le0/e;

    .line 233
    .line 234
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 235
    .line 236
    .line 237
    move-result-object v4

    .line 238
    sget-object v7, Lb0/y;->d:Lb0/y;

    .line 239
    .line 240
    :cond_a
    :goto_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 241
    .line 242
    .line 243
    move-result v8

    .line 244
    if-eqz v8, :cond_d

    .line 245
    .line 246
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v8

    .line 250
    check-cast v8, Lc0/a;

    .line 251
    .line 252
    instance-of v9, v8, Le0/a;

    .line 253
    .line 254
    if-eqz v9, :cond_b

    .line 255
    .line 256
    check-cast v8, Le0/a;

    .line 257
    .line 258
    iget-object v7, v8, Le0/a;->a:Lb0/y;

    .line 259
    .line 260
    goto :goto_3

    .line 261
    :cond_b
    instance-of v9, v8, Le0/c;

    .line 262
    .line 263
    if-eqz v9, :cond_c

    .line 264
    .line 265
    check-cast v8, Le0/c;

    .line 266
    .line 267
    new-instance v5, Landroid/util/Range;

    .line 268
    .line 269
    iget v9, v8, Le0/c;->a:I

    .line 270
    .line 271
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 272
    .line 273
    .line 274
    move-result-object v9

    .line 275
    iget v8, v8, Le0/c;->b:I

    .line 276
    .line 277
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 278
    .line 279
    .line 280
    move-result-object v8

    .line 281
    invoke-direct {v5, v9, v8}, Landroid/util/Range;-><init>(Ljava/lang/Comparable;Ljava/lang/Comparable;)V

    .line 282
    .line 283
    .line 284
    goto :goto_3

    .line 285
    :cond_c
    instance-of v9, v8, Le0/f;

    .line 286
    .line 287
    if-eqz v9, :cond_a

    .line 288
    .line 289
    check-cast v8, Le0/f;

    .line 290
    .line 291
    iget-object v6, v8, Le0/f;->a:Le0/e;

    .line 292
    .line 293
    goto :goto_3

    .line 294
    :cond_d
    instance-of v4, p0, Lb0/k1;

    .line 295
    .line 296
    if-nez v4, :cond_e

    .line 297
    .line 298
    invoke-static {p0}, Ll0/g;->B(Lb0/z1;)Z

    .line 299
    .line 300
    .line 301
    move-result v4

    .line 302
    if-eqz v4, :cond_f

    .line 303
    .line 304
    :cond_e
    sget-object v4, Lh0/z0;->E0:Lh0/g;

    .line 305
    .line 306
    invoke-virtual {p3, v4, v7}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    :cond_f
    sget-object v4, Lh0/o2;->V0:Lh0/g;

    .line 310
    .line 311
    invoke-virtual {p3, v4, v5}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    if-eqz v4, :cond_12

    .line 319
    .line 320
    if-eq v4, v2, :cond_11

    .line 321
    .line 322
    if-eq v4, v0, :cond_10

    .line 323
    .line 324
    goto :goto_4

    .line 325
    :cond_10
    sget-object v0, Lh0/o2;->a1:Lh0/g;

    .line 326
    .line 327
    invoke-virtual {p3, v0, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 328
    .line 329
    .line 330
    sget-object v0, Lh0/o2;->b1:Lh0/g;

    .line 331
    .line 332
    invoke-virtual {p3, v0, p2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    goto :goto_4

    .line 336
    :cond_11
    sget-object v0, Lh0/o2;->a1:Lh0/g;

    .line 337
    .line 338
    invoke-virtual {p3, v0, p2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 339
    .line 340
    .line 341
    sget-object p2, Lh0/o2;->b1:Lh0/g;

    .line 342
    .line 343
    invoke-virtual {p3, p2, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 344
    .line 345
    .line 346
    goto :goto_4

    .line 347
    :cond_12
    sget-object p2, Lh0/o2;->a1:Lh0/g;

    .line 348
    .line 349
    invoke-virtual {p3, p2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 350
    .line 351
    .line 352
    sget-object p2, Lh0/o2;->b1:Lh0/g;

    .line 353
    .line 354
    invoke-virtual {p3, p2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 355
    .line 356
    .line 357
    :goto_4
    invoke-virtual {p0, p3}, Lb0/z1;->l(Lh0/q0;)Lh0/n2;

    .line 358
    .line 359
    .line 360
    move-result-object p2

    .line 361
    invoke-virtual {p0, p1, p2}, Lb0/z1;->t(Lh0/z;Lh0/n2;)Lh0/o2;

    .line 362
    .line 363
    .line 364
    move-result-object p0

    .line 365
    return-object p0
.end method

.method public final o()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput v0, p0, Lb0/z1;->c:I

    .line 3
    .line 4
    invoke-virtual {p0}, Lb0/z1;->q()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final p()V
    .locals 2

    .line 1
    iget-object v0, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lb0/y1;

    .line 18
    .line 19
    invoke-interface {v1, p0}, Lb0/y1;->f(Lb0/z1;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    return-void
.end method

.method public final q()V
    .locals 3

    .line 1
    iget v0, p0, Lb0/z1;->c:I

    .line 2
    .line 3
    invoke-static {v0}, Lu/w;->o(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lb0/z1;->a:Ljava/util/HashSet;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-eq v0, v2, :cond_0

    .line 13
    .line 14
    goto :goto_2

    .line 15
    :cond_0
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Lb0/y1;

    .line 30
    .line 31
    invoke-interface {v1, p0}, Lb0/y1;->e(Lb0/z1;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    check-cast v1, Lb0/y1;

    .line 50
    .line 51
    invoke-interface {v1, p0}, Lb0/y1;->m(Lb0/z1;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    :goto_2
    return-void
.end method

.method public r()V
    .locals 0

    .line 1
    return-void
.end method

.method public s()V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract t(Lh0/z;Lh0/n2;)Lh0/o2;
.end method

.method public u()V
    .locals 0

    .line 1
    return-void
.end method

.method public v()V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract w(Lh0/q0;)Lh0/k;
.end method

.method public abstract x(Lh0/k;Lh0/k;)Lh0/k;
.end method

.method public abstract y()V
.end method

.method public z(Landroid/graphics/Matrix;)V
    .locals 1

    .line 1
    new-instance v0, Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroid/graphics/Matrix;-><init>(Landroid/graphics/Matrix;)V

    .line 4
    .line 5
    .line 6
    iput-object v0, p0, Lb0/z1;->k:Landroid/graphics/Matrix;

    .line 7
    .line 8
    return-void
.end method
