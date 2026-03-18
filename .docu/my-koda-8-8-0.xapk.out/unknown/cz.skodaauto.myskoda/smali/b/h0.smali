.class public final Lb/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Runnable;

.field public final b:Lmx0/l;

.field public c:Lb/a0;

.field public final d:Landroid/window/OnBackInvokedCallback;

.field public e:Landroid/window/OnBackInvokedDispatcher;

.field public f:Z

.field public g:Z


# direct methods
.method public constructor <init>(Ljava/lang/Runnable;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb/h0;->a:Ljava/lang/Runnable;

    .line 5
    .line 6
    new-instance p1, Lmx0/l;

    .line 7
    .line 8
    invoke-direct {p1}, Lmx0/l;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lb/h0;->b:Lmx0/l;

    .line 12
    .line 13
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 14
    .line 15
    const/16 v0, 0x21

    .line 16
    .line 17
    if-lt p1, v0, :cond_1

    .line 18
    .line 19
    const/16 v0, 0x22

    .line 20
    .line 21
    if-lt p1, v0, :cond_0

    .line 22
    .line 23
    new-instance p1, Lb/b0;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    invoke-direct {p1, p0, v0}, Lb/b0;-><init>(Lb/h0;I)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lb/b0;

    .line 30
    .line 31
    const/4 v1, 0x1

    .line 32
    invoke-direct {v0, p0, v1}, Lb/b0;-><init>(Lb/h0;I)V

    .line 33
    .line 34
    .line 35
    new-instance v1, Lb/c0;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    invoke-direct {v1, p0, v2}, Lb/c0;-><init>(Lb/h0;I)V

    .line 39
    .line 40
    .line 41
    new-instance v2, Lb/c0;

    .line 42
    .line 43
    const/4 v3, 0x1

    .line 44
    invoke-direct {v2, p0, v3}, Lb/c0;-><init>(Lb/h0;I)V

    .line 45
    .line 46
    .line 47
    new-instance v3, Lb/e0;

    .line 48
    .line 49
    invoke-direct {v3, p1, v0, v1, v2}, Lb/e0;-><init>(Lb/b0;Lb/b0;Lb/c0;Lb/c0;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    new-instance p1, Lb/c0;

    .line 54
    .line 55
    const/4 v0, 0x2

    .line 56
    invoke-direct {p1, p0, v0}, Lb/c0;-><init>(Lb/h0;I)V

    .line 57
    .line 58
    .line 59
    new-instance v3, Lb/d0;

    .line 60
    .line 61
    const/4 v0, 0x0

    .line 62
    invoke-direct {v3, p1, v0}, Lb/d0;-><init>(Ljava/lang/Object;I)V

    .line 63
    .line 64
    .line 65
    :goto_0
    iput-object v3, p0, Lb/h0;->d:Landroid/window/OnBackInvokedCallback;

    .line 66
    .line 67
    :cond_1
    return-void
.end method


# virtual methods
.method public final a(Landroidx/lifecycle/x;Lb/a0;)V
    .locals 9

    .line 1
    const-string v0, "owner"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onBackPressedCallback"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p1}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sget-object v1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 20
    .line 21
    if-ne v0, v1, :cond_0

    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance v0, Lb/f0;

    .line 25
    .line 26
    invoke-direct {v0, p0, p1, p2}, Lb/f0;-><init>(Lb/h0;Landroidx/lifecycle/r;Lb/a0;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p2, v0}, Lb/a0;->addCancellable(Lb/d;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Lb/h0;->e()V

    .line 33
    .line 34
    .line 35
    new-instance v1, La71/z;

    .line 36
    .line 37
    const/4 v7, 0x0

    .line 38
    const/16 v8, 0xa

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    const-class v4, Lb/h0;

    .line 42
    .line 43
    const-string v5, "updateEnabledCallbacks"

    .line 44
    .line 45
    const-string v6, "updateEnabledCallbacks()V"

    .line 46
    .line 47
    move-object v3, p0

    .line 48
    invoke-direct/range {v1 .. v8}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p2, v1}, Lb/a0;->setEnabledChangedCallback$activity_release(Lay0/a;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public final b()V
    .locals 4

    .line 1
    iget-object v0, p0, Lb/h0;->c:Lb/a0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_2

    .line 5
    .line 6
    iget-object v0, p0, Lb/h0;->b:Lmx0/l;

    .line 7
    .line 8
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-interface {v0, v2}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :cond_0
    invoke-interface {v0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    move-object v3, v2

    .line 27
    check-cast v3, Lb/a0;

    .line 28
    .line 29
    invoke-virtual {v3}, Lb/a0;->isEnabled()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move-object v2, v1

    .line 37
    :goto_0
    move-object v0, v2

    .line 38
    check-cast v0, Lb/a0;

    .line 39
    .line 40
    :cond_2
    iput-object v1, p0, Lb/h0;->c:Lb/a0;

    .line 41
    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    invoke-virtual {v0}, Lb/a0;->handleOnBackCancelled()V

    .line 45
    .line 46
    .line 47
    :cond_3
    return-void
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lb/h0;->c:Lb/a0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_2

    .line 5
    .line 6
    iget-object v0, p0, Lb/h0;->b:Lmx0/l;

    .line 7
    .line 8
    invoke-virtual {v0}, Lmx0/l;->c()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {v0, v2}, Ljava/util/AbstractList;->listIterator(I)Ljava/util/ListIterator;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :cond_0
    invoke-interface {v0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    move-object v3, v2

    .line 27
    check-cast v3, Lb/a0;

    .line 28
    .line 29
    invoke-virtual {v3}, Lb/a0;->isEnabled()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move-object v2, v1

    .line 37
    :goto_0
    move-object v0, v2

    .line 38
    check-cast v0, Lb/a0;

    .line 39
    .line 40
    :cond_2
    iput-object v1, p0, Lb/h0;->c:Lb/a0;

    .line 41
    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    invoke-virtual {v0}, Lb/a0;->handleOnBackPressed()V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_3
    iget-object p0, p0, Lb/h0;->a:Ljava/lang/Runnable;

    .line 49
    .line 50
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public final d(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lb/h0;->e:Landroid/window/OnBackInvokedDispatcher;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v1, p0, Lb/h0;->d:Landroid/window/OnBackInvokedCallback;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    iget-boolean v2, p0, Lb/h0;->f:Z

    .line 12
    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    invoke-static {v0, v1}, Lb/k;->i(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    iput-boolean p1, p0, Lb/h0;->f:Z

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    if-nez p1, :cond_1

    .line 23
    .line 24
    iget-boolean p1, p0, Lb/h0;->f:Z

    .line 25
    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    invoke-static {v0, v1}, Lb/k;->k(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    const/4 p1, 0x0

    .line 32
    iput-boolean p1, p0, Lb/h0;->f:Z

    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public final e()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lb/h0;->g:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lb/h0;->b:Lmx0/l;

    .line 5
    .line 6
    if-eqz v2, :cond_0

    .line 7
    .line 8
    invoke-virtual {v2}, Lmx0/l;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    if-eqz v3, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {v2}, Ljava/util/AbstractList;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_2

    .line 24
    .line 25
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v3, Lb/a0;

    .line 30
    .line 31
    invoke-virtual {v3}, Lb/a0;->isEnabled()Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    const/4 v1, 0x1

    .line 38
    :cond_2
    :goto_0
    iput-boolean v1, p0, Lb/h0;->g:Z

    .line 39
    .line 40
    if-eq v1, v0, :cond_3

    .line 41
    .line 42
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 43
    .line 44
    const/16 v2, 0x21

    .line 45
    .line 46
    if-lt v0, v2, :cond_3

    .line 47
    .line 48
    invoke-virtual {p0, v1}, Lb/h0;->d(Z)V

    .line 49
    .line 50
    .line 51
    :cond_3
    return-void
.end method
