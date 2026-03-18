.class public final Landroidx/fragment/app/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Cloneable;


# direct methods
.method public constructor <init>(Landroid/animation/Animator;)V
    .locals 1

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 7
    iput-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 8
    new-instance v0, Landroid/animation/AnimatorSet;

    invoke-direct {v0}, Landroid/animation/AnimatorSet;-><init>()V

    iput-object v0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 9
    invoke-virtual {v0, p1}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    return-void
.end method

.method public constructor <init>(Landroid/view/animation/Animation;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 5
    iput-object p1, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    return-void
.end method

.method public constructor <init>(Landroidx/fragment/app/j1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 2
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object p1, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    return-void
.end method


# virtual methods
.method public a(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->a(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public b(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v1, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 11
    .line 12
    iget-object v1, v1, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 13
    .line 14
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "parent.getParentFragmentManager()"

    .line 23
    .line 24
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->b(Landroidx/fragment/app/j0;Z)V

    .line 31
    .line 32
    .line 33
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 34
    .line 35
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eqz p1, :cond_2

    .line 46
    .line 47
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Landroidx/fragment/app/w0;

    .line 52
    .line 53
    if-eqz p2, :cond_1

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    return-void
.end method

.method public c(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->c(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public d(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->d(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public e(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->e(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public f(Landroidx/fragment/app/j0;Z)V
    .locals 7

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->f(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_7

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object v0, v0, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    sget-object v1, Lpt/e;->f:Lst/a;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    const-string v3, "FragmentMonitor %s.onFragmentPaused "

    .line 71
    .line 72
    invoke-virtual {v1, v3, v2}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v2, v0, Lpt/e;->a:Ljava/util/WeakHashMap;

    .line 76
    .line 77
    invoke-virtual {v2, p1}, Ljava/util/WeakHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-nez v3, :cond_2

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    const-string v2, "FragmentMonitor: missed a fragment trace from %s"

    .line 96
    .line 97
    invoke-virtual {v1, v2, v0}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_2
    invoke-virtual {v2, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    check-cast v3, Lcom/google/firebase/perf/metrics/Trace;

    .line 106
    .line 107
    invoke-virtual {v2, p1}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    iget-object v0, v0, Lpt/e;->e:Lpt/f;

    .line 111
    .line 112
    iget-object v2, v0, Lpt/f;->c:Ljava/util/HashMap;

    .line 113
    .line 114
    sget-object v4, Lpt/f;->e:Lst/a;

    .line 115
    .line 116
    iget-boolean v5, v0, Lpt/f;->d:Z

    .line 117
    .line 118
    if-nez v5, :cond_3

    .line 119
    .line 120
    const-string v0, "Cannot stop sub-recording because FrameMetricsAggregator is not recording"

    .line 121
    .line 122
    invoke-virtual {v4, v0}, Lst/a;->a(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    new-instance v0, Lzt/d;

    .line 126
    .line 127
    invoke-direct {v0}, Lzt/d;-><init>()V

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_3
    invoke-virtual {v2, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v5

    .line 135
    if-nez v5, :cond_4

    .line 136
    .line 137
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    const-string v2, "Sub-recording associated with key %s was not started or does not exist"

    .line 150
    .line 151
    invoke-virtual {v4, v2, v0}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    new-instance v0, Lzt/d;

    .line 155
    .line 156
    invoke-direct {v0}, Lzt/d;-><init>()V

    .line 157
    .line 158
    .line 159
    goto :goto_1

    .line 160
    :cond_4
    invoke-virtual {v2, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    check-cast v2, Ltt/d;

    .line 165
    .line 166
    invoke-virtual {v0}, Lpt/f;->a()Lzt/d;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    invoke-virtual {v0}, Lzt/d;->b()Z

    .line 171
    .line 172
    .line 173
    move-result v5

    .line 174
    if-nez v5, :cond_5

    .line 175
    .line 176
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    const-string v2, "stopFragment(%s): snapshot() failed"

    .line 189
    .line 190
    invoke-virtual {v4, v2, v0}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    new-instance v0, Lzt/d;

    .line 194
    .line 195
    invoke-direct {v0}, Lzt/d;-><init>()V

    .line 196
    .line 197
    .line 198
    goto :goto_1

    .line 199
    :cond_5
    invoke-virtual {v0}, Lzt/d;->a()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    check-cast v0, Ltt/d;

    .line 204
    .line 205
    iget v4, v0, Ltt/d;->a:I

    .line 206
    .line 207
    iget v5, v2, Ltt/d;->a:I

    .line 208
    .line 209
    sub-int/2addr v4, v5

    .line 210
    iget v5, v0, Ltt/d;->b:I

    .line 211
    .line 212
    iget v6, v2, Ltt/d;->b:I

    .line 213
    .line 214
    sub-int/2addr v5, v6

    .line 215
    iget v0, v0, Ltt/d;->c:I

    .line 216
    .line 217
    iget v2, v2, Ltt/d;->c:I

    .line 218
    .line 219
    sub-int/2addr v0, v2

    .line 220
    new-instance v2, Ltt/d;

    .line 221
    .line 222
    invoke-direct {v2, v4, v5, v0}, Ltt/d;-><init>(III)V

    .line 223
    .line 224
    .line 225
    new-instance v0, Lzt/d;

    .line 226
    .line 227
    invoke-direct {v0, v2}, Lzt/d;-><init>(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    :goto_1
    invoke-virtual {v0}, Lzt/d;->b()Z

    .line 231
    .line 232
    .line 233
    move-result v2

    .line 234
    if-nez v2, :cond_6

    .line 235
    .line 236
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    const-string v2, "onFragmentPaused: recorder failed to trace %s"

    .line 249
    .line 250
    invoke-virtual {v1, v2, v0}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    goto/16 :goto_0

    .line 254
    .line 255
    :cond_6
    invoke-virtual {v0}, Lzt/d;->a()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    check-cast v0, Ltt/d;

    .line 260
    .line 261
    invoke-static {v3, v0}, Lzt/g;->a(Lcom/google/firebase/perf/metrics/Trace;Ltt/d;)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v3}, Lcom/google/firebase/perf/metrics/Trace;->stop()V

    .line 265
    .line 266
    .line 267
    goto/16 :goto_0

    .line 268
    .line 269
    :cond_7
    return-void
.end method

.method public g(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v1, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 11
    .line 12
    iget-object v1, v1, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 13
    .line 14
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "parent.getParentFragmentManager()"

    .line 23
    .line 24
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->g(Landroidx/fragment/app/j0;Z)V

    .line 31
    .line 32
    .line 33
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 34
    .line 35
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-eqz p1, :cond_2

    .line 46
    .line 47
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Landroidx/fragment/app/w0;

    .line 52
    .line 53
    if-eqz p2, :cond_1

    .line 54
    .line 55
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    return-void
.end method

.method public h(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->h(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public i(Landroidx/fragment/app/j0;Z)V
    .locals 6

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->i(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_7

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object v0, v0, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    sget-object v1, Lpt/e;->f:Lst/a;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    const-string v3, "FragmentMonitor %s.onFragmentResumed"

    .line 71
    .line 72
    invoke-virtual {v1, v3, v2}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    new-instance v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 76
    .line 77
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    const-string v3, "_st_"

    .line 86
    .line 87
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    iget-object v3, v0, Lpt/e;->c:Lyt/h;

    .line 92
    .line 93
    iget-object v4, v0, Lpt/e;->b:La61/a;

    .line 94
    .line 95
    iget-object v5, v0, Lpt/e;->d:Lpt/c;

    .line 96
    .line 97
    invoke-direct {v1, v2, v3, v4, v5}, Lcom/google/firebase/perf/metrics/Trace;-><init>(Ljava/lang/String;Lyt/h;La61/a;Lpt/c;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v1}, Lcom/google/firebase/perf/metrics/Trace;->start()V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getParentFragment()Landroidx/fragment/app/j0;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    if-nez v2, :cond_2

    .line 108
    .line 109
    const-string v2, "No parent"

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_2
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getParentFragment()Landroidx/fragment/app/j0;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    :goto_1
    const-string v3, "Parent_fragment"

    .line 125
    .line 126
    invoke-virtual {v1, v3, v2}, Lcom/google/firebase/perf/metrics/Trace;->putAttribute(Ljava/lang/String;Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    if-eqz v2, :cond_3

    .line 134
    .line 135
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getActivity()Landroidx/fragment/app/o0;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v2

    .line 147
    const-string v3, "Hosting_activity"

    .line 148
    .line 149
    invoke-virtual {v1, v3, v2}, Lcom/google/firebase/perf/metrics/Trace;->putAttribute(Ljava/lang/String;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    :cond_3
    iget-object v2, v0, Lpt/e;->a:Ljava/util/WeakHashMap;

    .line 153
    .line 154
    invoke-virtual {v2, p1, v1}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    iget-object v0, v0, Lpt/e;->e:Lpt/f;

    .line 158
    .line 159
    iget-object v1, v0, Lpt/f;->c:Ljava/util/HashMap;

    .line 160
    .line 161
    sget-object v2, Lpt/f;->e:Lst/a;

    .line 162
    .line 163
    iget-boolean v3, v0, Lpt/f;->d:Z

    .line 164
    .line 165
    if-nez v3, :cond_4

    .line 166
    .line 167
    const-string v0, "Cannot start sub-recording because FrameMetricsAggregator is not recording"

    .line 168
    .line 169
    invoke-virtual {v2, v0}, Lst/a;->a(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    goto/16 :goto_0

    .line 173
    .line 174
    :cond_4
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v3

    .line 178
    if-eqz v3, :cond_5

    .line 179
    .line 180
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    const-string v1, "Cannot start sub-recording because one is already ongoing with the key %s"

    .line 193
    .line 194
    invoke-virtual {v2, v1, v0}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    goto/16 :goto_0

    .line 198
    .line 199
    :cond_5
    invoke-virtual {v0}, Lpt/f;->a()Lzt/d;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    invoke-virtual {v0}, Lzt/d;->b()Z

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    if-nez v3, :cond_6

    .line 208
    .line 209
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    const-string v1, "startFragment(%s): snapshot() failed"

    .line 222
    .line 223
    invoke-virtual {v2, v1, v0}, Lst/a;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    goto/16 :goto_0

    .line 227
    .line 228
    :cond_6
    invoke-virtual {v0}, Lzt/d;->a()Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    check-cast v0, Ltt/d;

    .line 233
    .line 234
    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    goto/16 :goto_0

    .line 238
    .line 239
    :cond_7
    return-void
.end method

.method public j(Landroidx/fragment/app/j0;Landroid/os/Bundle;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, p2, v1}, Landroidx/fragment/app/p0;->j(Landroidx/fragment/app/j0;Landroid/os/Bundle;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p3, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public k(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->k(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public l(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->l(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method

.method public m(Landroidx/fragment/app/j0;Landroid/view/View;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "v"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Landroidx/fragment/app/j1;

    .line 14
    .line 15
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "parent.getParentFragmentManager()"

    .line 24
    .line 25
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    invoke-virtual {v0, p1, p2, v1}, Landroidx/fragment/app/p0;->m(Landroidx/fragment/app/j0;Landroid/view/View;Z)V

    .line 32
    .line 33
    .line 34
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 35
    .line 36
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_2

    .line 47
    .line 48
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, Landroidx/fragment/app/w0;

    .line 53
    .line 54
    if-eqz p3, :cond_1

    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    return-void
.end method

.method public n(Landroidx/fragment/app/j0;Z)V
    .locals 2

    .line 1
    const-string v0, "f"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "parent.getParentFragmentManager()"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v0, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/p0;->n(Landroidx/fragment/app/j0;Z)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Landroidx/fragment/app/w0;

    .line 48
    .line 49
    if-eqz p2, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object p1, p1, Landroidx/fragment/app/w0;->a:Lpt/e;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    return-void
.end method
