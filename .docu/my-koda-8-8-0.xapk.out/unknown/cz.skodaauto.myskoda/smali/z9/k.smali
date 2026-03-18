.class public final Lz9/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/x;
.implements Landroidx/lifecycle/i1;
.implements Landroidx/lifecycle/k;
.implements Lra/f;


# instance fields
.field public final d:Lca/d;

.field public e:Lz9/u;

.field public final f:Landroid/os/Bundle;

.field public g:Landroidx/lifecycle/q;

.field public final h:Lz9/n;

.field public final i:Ljava/lang/String;

.field public final j:Landroid/os/Bundle;

.field public final k:Lca/c;

.field public final l:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Lca/d;Lz9/u;Landroid/os/Bundle;Landroidx/lifecycle/q;Lz9/n;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz9/k;->d:Lca/d;

    .line 5
    .line 6
    iput-object p2, p0, Lz9/k;->e:Lz9/u;

    .line 7
    .line 8
    iput-object p3, p0, Lz9/k;->f:Landroid/os/Bundle;

    .line 9
    .line 10
    iput-object p4, p0, Lz9/k;->g:Landroidx/lifecycle/q;

    .line 11
    .line 12
    iput-object p5, p0, Lz9/k;->h:Lz9/n;

    .line 13
    .line 14
    iput-object p6, p0, Lz9/k;->i:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lz9/k;->j:Landroid/os/Bundle;

    .line 17
    .line 18
    new-instance p1, Lca/c;

    .line 19
    .line 20
    invoke-direct {p1, p0}, Lca/c;-><init>(Lz9/k;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lz9/k;->k:Lca/c;

    .line 24
    .line 25
    new-instance p1, Ly1/i;

    .line 26
    .line 27
    const/16 p2, 0xd

    .line 28
    .line 29
    invoke-direct {p1, p0, p2}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lz9/k;->l:Llx0/q;

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final a(Landroidx/lifecycle/q;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lca/c;->k:Landroidx/lifecycle/q;

    .line 7
    .line 8
    invoke-virtual {p0}, Lca/c;->b()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_5

    .line 3
    .line 4
    instance-of v1, p1, Lz9/k;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    goto/16 :goto_2

    .line 9
    .line 10
    :cond_0
    check-cast p1, Lz9/k;

    .line 11
    .line 12
    iget-object v1, p1, Lz9/k;->f:Landroid/os/Bundle;

    .line 13
    .line 14
    iget-object v2, p1, Lz9/k;->i:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, p0, Lz9/k;->i:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_5

    .line 23
    .line 24
    iget-object v2, p0, Lz9/k;->e:Lz9/u;

    .line 25
    .line 26
    iget-object v3, p1, Lz9/k;->e:Lz9/u;

    .line 27
    .line 28
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_5

    .line 33
    .line 34
    iget-object v2, p0, Lz9/k;->k:Lca/c;

    .line 35
    .line 36
    iget-object v2, v2, Lca/c;->j:Landroidx/lifecycle/z;

    .line 37
    .line 38
    iget-object v3, p1, Lz9/k;->k:Lca/c;

    .line 39
    .line 40
    iget-object v3, v3, Lca/c;->j:Landroidx/lifecycle/z;

    .line 41
    .line 42
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_5

    .line 47
    .line 48
    invoke-virtual {p0}, Lz9/k;->getSavedStateRegistry()Lra/d;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {p1}, Lz9/k;->getSavedStateRegistry()Lra/d;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_5

    .line 61
    .line 62
    iget-object p0, p0, Lz9/k;->f:Landroid/os/Bundle;

    .line 63
    .line 64
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-nez p1, :cond_4

    .line 69
    .line 70
    if-eqz p0, :cond_5

    .line 71
    .line 72
    invoke-virtual {p0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-eqz p1, :cond_5

    .line 77
    .line 78
    check-cast p1, Ljava/lang/Iterable;

    .line 79
    .line 80
    instance-of v2, p1, Ljava/util/Collection;

    .line 81
    .line 82
    if-eqz v2, :cond_1

    .line 83
    .line 84
    move-object v2, p1

    .line 85
    check-cast v2, Ljava/util/Collection;

    .line 86
    .line 87
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    if-eqz v2, :cond_1

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    if-eqz v2, :cond_4

    .line 103
    .line 104
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Ljava/lang/String;

    .line 109
    .line 110
    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    if-eqz v1, :cond_3

    .line 115
    .line 116
    invoke-virtual {v1, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    goto :goto_0

    .line 121
    :cond_3
    const/4 v2, 0x0

    .line 122
    :goto_0
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    if-nez v2, :cond_2

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_4
    :goto_1
    const/4 p0, 0x1

    .line 130
    return p0

    .line 131
    :cond_5
    :goto_2
    return v0
.end method

.method public final getDefaultViewModelCreationExtras()Lp7/c;
    .locals 5

    .line 1
    iget-object v0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v1, Lp7/e;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, v2}, Lp7/e;-><init>(I)V

    .line 10
    .line 11
    .line 12
    sget-object v2, Landroidx/lifecycle/v0;->a:Lmb/e;

    .line 13
    .line 14
    iget-object v3, v0, Lca/c;->a:Lz9/k;

    .line 15
    .line 16
    iget-object v4, v1, Lp7/c;->a:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    invoke-interface {v4, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    sget-object v2, Landroidx/lifecycle/v0;->b:Lnm0/b;

    .line 22
    .line 23
    invoke-interface {v4, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Lca/c;->a()Landroid/os/Bundle;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    sget-object v2, Landroidx/lifecycle/v0;->c:Lpy/a;

    .line 33
    .line 34
    invoke-interface {v4, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    :cond_0
    const/4 v0, 0x0

    .line 38
    iget-object p0, p0, Lz9/k;->d:Lca/d;

    .line 39
    .line 40
    if-eqz p0, :cond_2

    .line 41
    .line 42
    iget-object p0, p0, Lca/d;->d:Landroid/content/Context;

    .line 43
    .line 44
    if-eqz p0, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    goto :goto_0

    .line 51
    :cond_1
    move-object p0, v0

    .line 52
    :goto_0
    instance-of v2, p0, Landroid/app/Application;

    .line 53
    .line 54
    if-eqz v2, :cond_2

    .line 55
    .line 56
    check-cast p0, Landroid/app/Application;

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    move-object p0, v0

    .line 60
    :goto_1
    if-eqz p0, :cond_3

    .line 61
    .line 62
    move-object v0, p0

    .line 63
    :cond_3
    if-eqz v0, :cond_4

    .line 64
    .line 65
    sget-object p0, Landroidx/lifecycle/d1;->d:Lrb0/a;

    .line 66
    .line 67
    invoke-interface {v4, p0, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    :cond_4
    return-object v1
.end method

.method public final getDefaultViewModelProviderFactory()Landroidx/lifecycle/e1;
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    iget-object p0, p0, Lca/c;->l:Landroidx/lifecycle/y0;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getLifecycle()Landroidx/lifecycle/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    iget-object p0, p0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getSavedStateRegistry()Lra/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    iget-object p0, p0, Lca/c;->h:Lra/e;

    .line 4
    .line 5
    iget-object p0, p0, Lra/e;->b:Lra/d;

    .line 6
    .line 7
    return-object p0
.end method

.method public final getViewModelStore()Landroidx/lifecycle/h1;
    .locals 2

    .line 1
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    iget-boolean v0, p0, Lca/c;->i:Z

    .line 4
    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    iget-object v0, p0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 8
    .line 9
    iget-object v0, v0, Landroidx/lifecycle/z;->d:Landroidx/lifecycle/q;

    .line 10
    .line 11
    sget-object v1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 12
    .line 13
    if-eq v0, v1, :cond_2

    .line 14
    .line 15
    iget-object v0, p0, Lca/c;->e:Lz9/n;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Lca/c;->f:Ljava/lang/String;

    .line 20
    .line 21
    const-string v1, "backStackEntryId"

    .line 22
    .line 23
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, v0, Lz9/n;->d:Ljava/util/LinkedHashMap;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Landroidx/lifecycle/h1;

    .line 33
    .line 34
    if-nez v1, :cond_0

    .line 35
    .line 36
    new-instance v1, Landroidx/lifecycle/h1;

    .line 37
    .line 38
    invoke-direct {v1}, Landroidx/lifecycle/h1;-><init>()V

    .line 39
    .line 40
    .line 41
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    :cond_0
    return-object v1

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string v0, "You must call setViewModelStore() on your NavHostController before accessing the ViewModelStore of a navigation graph."

    .line 48
    .line 49
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v0, "You cannot access the NavBackStackEntry\'s ViewModels after the NavBackStackEntry is destroyed."

    .line 56
    .line 57
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v0, "You cannot access the NavBackStackEntry\'s ViewModels until it is added to the NavController\'s back stack (i.e., the Lifecycle of the NavBackStackEntry reaches the CREATED state)."

    .line 64
    .line 65
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lz9/k;->i:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lz9/k;->e:Lz9/u;

    .line 10
    .line 11
    invoke-virtual {v1}, Lz9/u;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    iget-object v0, p0, Lz9/k;->f:Landroid/os/Bundle;

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    invoke-virtual {v0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    check-cast v2, Ljava/lang/Iterable;

    .line 27
    .line 28
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    check-cast v3, Ljava/lang/String;

    .line 43
    .line 44
    mul-int/lit8 v1, v1, 0x1f

    .line 45
    .line 46
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    if-eqz v3, :cond_0

    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    goto :goto_1

    .line 57
    :cond_0
    const/4 v3, 0x0

    .line 58
    :goto_1
    add-int/2addr v1, v3

    .line 59
    goto :goto_0

    .line 60
    :cond_1
    mul-int/lit8 v1, v1, 0x1f

    .line 61
    .line 62
    iget-object v0, p0, Lz9/k;->k:Lca/c;

    .line 63
    .line 64
    iget-object v0, v0, Lca/c;->j:Landroidx/lifecycle/z;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    add-int/2addr v0, v1

    .line 71
    mul-int/lit8 v0, v0, 0x1f

    .line 72
    .line 73
    invoke-virtual {p0}, Lz9/k;->getSavedStateRegistry()Lra/d;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    add-int/2addr p0, v0

    .line 82
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/k;->k:Lca/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Lca/c;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
