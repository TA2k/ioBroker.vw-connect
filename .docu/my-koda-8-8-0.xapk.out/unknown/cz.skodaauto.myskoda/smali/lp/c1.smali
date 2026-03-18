.class public abstract Llp/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lhv/b;)Llv/c;
    .locals 5

    .line 1
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-class v1, Llv/b;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Llv/b;

    .line 12
    .line 13
    iget-object v1, v0, Llv/b;->a:Llv/d;

    .line 14
    .line 15
    new-instance v2, Llv/c;

    .line 16
    .line 17
    invoke-virtual {v1, p0}, Lap0/o;->y(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Llv/e;

    .line 22
    .line 23
    iget-object v0, v0, Llv/b;->b:Lfv/d;

    .line 24
    .line 25
    iget-object v0, v0, Lfv/d;->a:Lgt/b;

    .line 26
    .line 27
    invoke-interface {v0}, Lgt/b;->get()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    invoke-static {}, Llv/a;->c()Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eq v3, v4, :cond_0

    .line 39
    .line 40
    const-string v3, "play-services-mlkit-barcode-scanning"

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    const-string v3, "barcode-scanning"

    .line 44
    .line 45
    :goto_0
    invoke-static {v3}, Ljp/yg;->l(Ljava/lang/String;)Ljp/vg;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-direct {v2, p0, v1, v0, v3}, Llv/c;-><init>(Lhv/b;Llv/e;Ljava/util/concurrent/Executor;Ljp/vg;)V

    .line 50
    .line 51
    .line 52
    return-object v2
.end method

.method public static final b(Landroid/content/ComponentCallbacks;)Lk21/a;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Ly11/a;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Ly11/a;

    .line 11
    .line 12
    invoke-interface {p0}, Ly11/a;->b()Landroidx/lifecycle/c1;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Li21/b;

    .line 19
    .line 20
    iget-object p0, p0, Li21/b;->d:Lk21/a;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_0
    sget-object p0, Lz11/a;->b:Landroidx/lifecycle/c1;

    .line 24
    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Li21/b;

    .line 30
    .line 31
    iget-object p0, p0, Li21/b;->d:Lk21/a;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v0, "KoinApplication has not been started"

    .line 37
    .line 38
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0
.end method
