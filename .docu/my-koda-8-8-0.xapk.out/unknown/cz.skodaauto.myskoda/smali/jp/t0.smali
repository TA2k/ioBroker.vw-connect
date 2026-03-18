.class public abstract Ljp/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/content/Context;)Lz9/y;
    .locals 3

    .line 1
    new-instance v0, Lz9/y;

    .line 2
    .line 3
    const-string v1, "context"

    .line 4
    .line 5
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, p0}, Lz9/y;-><init>(Landroid/content/Context;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, v0, Lz9/y;->b:Lca/g;

    .line 12
    .line 13
    iget-object v1, p0, Lca/g;->s:Lz9/k0;

    .line 14
    .line 15
    new-instance v2, Laa/g;

    .line 16
    .line 17
    invoke-direct {v2, v1}, Lz9/x;-><init>(Lz9/k0;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v2}, Lz9/k0;->a(Lz9/j0;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lca/g;->s:Lz9/k0;

    .line 24
    .line 25
    new-instance v1, Laa/i;

    .line 26
    .line 27
    invoke-direct {v1}, Laa/i;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, v1}, Lz9/k0;->a(Lz9/j0;)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Laa/v;

    .line 34
    .line 35
    invoke-direct {v1}, Laa/v;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v1}, Lz9/k0;->a(Lz9/j0;)V

    .line 39
    .line 40
    .line 41
    return-object v0
.end method

.method public static b(Landroid/content/Context;)Z
    .locals 5

    .line 1
    const-string v0, "display"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/hardware/display/DisplayManager;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Landroid/hardware/display/DisplayManager;->getDisplay(I)Landroid/view/Display;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    if-eqz p0, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/view/Display;->isHdr()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_2

    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/view/Display;->getHdrCapabilities()Landroid/view/Display$HdrCapabilities;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-virtual {p0}, Landroid/view/Display$HdrCapabilities;->getSupportedHdrTypes()[I

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    array-length v1, p0

    .line 35
    move v2, v0

    .line 36
    :goto_1
    if-ge v2, v1, :cond_2

    .line 37
    .line 38
    aget v3, p0, v2

    .line 39
    .line 40
    const/4 v4, 0x1

    .line 41
    if-ne v3, v4, :cond_1

    .line 42
    .line 43
    return v4

    .line 44
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    return v0
.end method

.method public static final c(Landroidx/lifecycle/s0;Lhy0/d;)Ljava/lang/Object;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "route"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-static {p1}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 21
    .line 22
    invoke-static {p1, v1}, Lda/d;->c(Lqz0/a;Ljava/util/Map;)Ljava/util/ArrayList;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_0

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Lz9/h;

    .line 41
    .line 42
    iget-object v3, v2, Lz9/h;->a:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v2, v2, Lz9/h;->b:Lz9/i;

    .line 45
    .line 46
    iget-object v2, v2, Lz9/i;->a:Lz9/g0;

    .line 47
    .line 48
    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    new-instance v1, Lda/g;

    .line 53
    .line 54
    invoke-direct {v1, p0, v0}, Lda/g;-><init>(Landroidx/lifecycle/s0;Ljava/util/LinkedHashMap;)V

    .line 55
    .line 56
    .line 57
    check-cast p1, Lqz0/a;

    .line 58
    .line 59
    invoke-interface {p1, v1}, Lqz0/a;->deserialize(Ltz0/c;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0
.end method
