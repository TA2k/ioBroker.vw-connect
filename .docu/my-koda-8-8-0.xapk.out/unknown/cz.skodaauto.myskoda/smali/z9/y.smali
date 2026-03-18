.class public final Lz9/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lca/g;

.field public final c:Lca/d;

.field public final d:Landroid/app/Activity;

.field public e:Z

.field public final f:Lb/i0;

.field public final g:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lz9/y;->a:Landroid/content/Context;

    .line 10
    .line 11
    new-instance v0, Lca/g;

    .line 12
    .line 13
    new-instance v1, Lle/a;

    .line 14
    .line 15
    const/16 v2, 0x10

    .line 16
    .line 17
    invoke-direct {v1, p0, v2}, Lle/a;-><init>(Lz9/y;I)V

    .line 18
    .line 19
    .line 20
    invoke-direct {v0, p0, v1}, Lca/g;-><init>(Lz9/y;Lle/a;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lz9/y;->b:Lca/g;

    .line 24
    .line 25
    new-instance v0, Lca/d;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-direct {v0, p1, v1}, Lca/d;-><init>(Landroid/content/Context;Z)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lz9/y;->c:Lca/d;

    .line 32
    .line 33
    new-instance v0, Lz70/e0;

    .line 34
    .line 35
    const/4 v1, 0x3

    .line 36
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p1, v0}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-interface {p1}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_1

    .line 52
    .line 53
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    move-object v1, v0

    .line 58
    check-cast v1, Landroid/content/Context;

    .line 59
    .line 60
    instance-of v1, v1, Landroid/app/Activity;

    .line 61
    .line 62
    if-eqz v1, :cond_0

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    const/4 v0, 0x0

    .line 66
    :goto_0
    check-cast v0, Landroid/app/Activity;

    .line 67
    .line 68
    iput-object v0, p0, Lz9/y;->d:Landroid/app/Activity;

    .line 69
    .line 70
    new-instance p1, Lb/i0;

    .line 71
    .line 72
    invoke-direct {p1, p0}, Lb/i0;-><init>(Lz9/y;)V

    .line 73
    .line 74
    .line 75
    iput-object p1, p0, Lz9/y;->f:Lb/i0;

    .line 76
    .line 77
    const/4 p1, 0x1

    .line 78
    iput-boolean p1, p0, Lz9/y;->g:Z

    .line 79
    .line 80
    iget-object p1, p0, Lz9/y;->b:Lca/g;

    .line 81
    .line 82
    iget-object p1, p1, Lca/g;->s:Lz9/k0;

    .line 83
    .line 84
    new-instance v0, Lz9/x;

    .line 85
    .line 86
    invoke-direct {v0, p1}, Lz9/x;-><init>(Lz9/k0;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1, v0}, Lz9/k0;->a(Lz9/j0;)V

    .line 90
    .line 91
    .line 92
    iget-object p1, p0, Lz9/y;->b:Lca/g;

    .line 93
    .line 94
    iget-object p1, p1, Lca/g;->s:Lz9/k0;

    .line 95
    .line 96
    new-instance v0, Lz9/b;

    .line 97
    .line 98
    iget-object v1, p0, Lz9/y;->a:Landroid/content/Context;

    .line 99
    .line 100
    invoke-direct {v0, v1}, Lz9/b;-><init>(Landroid/content/Context;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {p1, v0}, Lz9/k0;->a(Lz9/j0;)V

    .line 104
    .line 105
    .line 106
    new-instance p1, Lle/a;

    .line 107
    .line 108
    const/16 v0, 0x11

    .line 109
    .line 110
    invoke-direct {p1, p0, v0}, Lle/a;-><init>(Lz9/y;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 114
    .line 115
    .line 116
    return-void
.end method

.method public static e(Lz9/y;Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "route"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lca/g;->f(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    const/4 v0, 0x0

    .line 19
    invoke-virtual {p0, p1, v0}, Lca/g;->m(Ljava/lang/String;Lz9/b0;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public static f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const-string p3, "route"

    .line 10
    .line 11
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 15
    .line 16
    invoke-virtual {p0, p1, p2}, Lca/g;->m(Ljava/lang/String;Lz9/b0;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public static i(Lz9/y;Ljava/lang/String;Z)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const-string v0, "route"

    .line 5
    .line 6
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-virtual {p0, p1, p2, v0}, Lca/g;->p(Ljava/lang/String;ZZ)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Lca/g;->b()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_0
    return v0
.end method


# virtual methods
.method public final a(Lny/b0;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lca/g;->p:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lca/g;->f:Lmx0/l;

    .line 12
    .line 13
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0}, Lmx0/l;->last()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lz9/k;

    .line 24
    .line 25
    iget-object p0, p0, Lca/g;->a:Lz9/y;

    .line 26
    .line 27
    iget-object v1, v0, Lz9/k;->e:Lz9/u;

    .line 28
    .line 29
    iget-object v0, v0, Lz9/k;->k:Lca/c;

    .line 30
    .line 31
    invoke-virtual {v0}, Lca/c;->a()Landroid/os/Bundle;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1, p0, v1}, Lny/b0;->a(Lz9/y;Lz9/u;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method public final b(Ljava/lang/String;)Lz9/k;
    .locals 4

    .line 1
    const-string v0, "route"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lca/g;->f:Lmx0/l;

    .line 12
    .line 13
    invoke-virtual {v0}, Lmx0/l;->c()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {v0, v1}, Ljava/util/AbstractList;->listIterator(I)Ljava/util/ListIterator;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :cond_0
    invoke-interface {v0}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    move-object v2, v1

    .line 32
    check-cast v2, Lz9/k;

    .line 33
    .line 34
    iget-object v3, v2, Lz9/k;->e:Lz9/u;

    .line 35
    .line 36
    iget-object v2, v2, Lz9/k;->k:Lca/c;

    .line 37
    .line 38
    invoke-virtual {v2}, Lca/c;->a()Landroid/os/Bundle;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-virtual {v3, p1, v2}, Lz9/u;->k(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    const/4 v1, 0x0

    .line 50
    :goto_0
    check-cast v1, Lz9/k;

    .line 51
    .line 52
    if-eqz v1, :cond_2

    .line 53
    .line 54
    return-object v1

    .line 55
    :cond_2
    const-string v0, "No destination with route "

    .line 56
    .line 57
    const-string v1, " is on the NavController\'s back stack. The current destination is "

    .line 58
    .line 59
    invoke-static {v0, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-virtual {p0}, Lca/g;->h()Lz9/u;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p1
.end method

.method public final c()I
    .locals 2

    .line 1
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 2
    .line 3
    iget-object p0, p0, Lca/g;->f:Lmx0/l;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_3

    .line 24
    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Lz9/k;

    .line 30
    .line 31
    iget-object v1, v1, Lz9/k;->e:Lz9/u;

    .line 32
    .line 33
    instance-of v1, v1, Lz9/v;

    .line 34
    .line 35
    if-nez v1, :cond_1

    .line 36
    .line 37
    add-int/lit8 v0, v0, 0x1

    .line 38
    .line 39
    if-ltz v0, :cond_2

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x0

    .line 46
    throw p0

    .line 47
    :cond_3
    return v0
.end method

.method public final d(Ljava/lang/String;Lay0/k;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p2}, Ljp/r0;->d(Lay0/k;)Lz9/b0;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    invoke-virtual {p0, p1, p2}, Lca/g;->m(Ljava/lang/String;Lz9/b0;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final g()V
    .locals 12

    .line 1
    invoke-virtual {p0}, Lz9/y;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-ne v0, v1, :cond_11

    .line 7
    .line 8
    iget-object v0, p0, Lz9/y;->d:Landroid/app/Activity;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    invoke-virtual {v2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move-object v2, v1

    .line 25
    :goto_0
    const-string v3, "android-support-nav:controller:deepLinkIds"

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    invoke-virtual {v2, v3}, Landroid/os/BaseBundle;->getIntArray(Ljava/lang/String;)[I

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move-object v2, v1

    .line 35
    :goto_1
    const-string v4, "android-support-nav:controller:deepLinkExtras"

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    iget-object v6, p0, Lz9/y;->b:Lca/g;

    .line 39
    .line 40
    if-eqz v2, :cond_b

    .line 41
    .line 42
    iget-boolean v2, p0, Lz9/y;->e:Z

    .line 43
    .line 44
    if-nez v2, :cond_2

    .line 45
    .line 46
    goto/16 :goto_6

    .line 47
    .line 48
    :cond_2
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 56
    .line 57
    .line 58
    move-result-object v7

    .line 59
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v7, v3}, Landroid/os/BaseBundle;->getIntArray(Ljava/lang/String;)[I

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    invoke-static {v3}, Lmx0/n;->g0([I)Ljava/util/ArrayList;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const-string v8, "android-support-nav:controller:deepLinkArgs"

    .line 74
    .line 75
    invoke-virtual {v7, v8}, Landroid/os/Bundle;->getParcelableArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 80
    .line 81
    .line 82
    move-result v9

    .line 83
    const/4 v10, 0x2

    .line 84
    if-ge v9, v10, :cond_3

    .line 85
    .line 86
    goto/16 :goto_6

    .line 87
    .line 88
    :cond_3
    invoke-static {v3}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v9

    .line 92
    check-cast v9, Ljava/lang/Number;

    .line 93
    .line 94
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v9

    .line 98
    if-eqz v8, :cond_4

    .line 99
    .line 100
    invoke-static {v8}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v10

    .line 104
    check-cast v10, Landroid/os/Bundle;

    .line 105
    .line 106
    :cond_4
    invoke-virtual {v6}, Lca/g;->i()Lz9/v;

    .line 107
    .line 108
    .line 109
    move-result-object v10

    .line 110
    invoke-static {v9, v10, v1, v5}, Lca/g;->e(ILz9/u;Lz9/u;Z)Lz9/u;

    .line 111
    .line 112
    .line 113
    move-result-object v10

    .line 114
    instance-of v11, v10, Lz9/v;

    .line 115
    .line 116
    if-eqz v11, :cond_5

    .line 117
    .line 118
    sget v9, Lz9/v;->j:I

    .line 119
    .line 120
    check-cast v10, Lz9/v;

    .line 121
    .line 122
    new-instance v9, Lz70/e0;

    .line 123
    .line 124
    const/16 v11, 0x8

    .line 125
    .line 126
    invoke-direct {v9, v11}, Lz70/e0;-><init>(I)V

    .line 127
    .line 128
    .line 129
    invoke-static {v10, v9}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 130
    .line 131
    .line 132
    move-result-object v9

    .line 133
    invoke-static {v9}, Lky0/l;->m(Lky0/j;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v9

    .line 137
    check-cast v9, Lz9/u;

    .line 138
    .line 139
    iget-object v9, v9, Lz9/u;->e:Lca/j;

    .line 140
    .line 141
    iget v9, v9, Lca/j;->a:I

    .line 142
    .line 143
    :cond_5
    invoke-virtual {v6}, Lca/g;->h()Lz9/u;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    if-eqz v6, :cond_10

    .line 148
    .line 149
    iget-object v6, v6, Lz9/u;->e:Lca/j;

    .line 150
    .line 151
    iget v6, v6, Lca/j;->a:I

    .line 152
    .line 153
    if-ne v9, v6, :cond_10

    .line 154
    .line 155
    new-instance v6, Landroidx/lifecycle/c1;

    .line 156
    .line 157
    invoke-direct {v6, p0}, Landroidx/lifecycle/c1;-><init>(Lz9/y;)V

    .line 158
    .line 159
    .line 160
    new-array p0, v5, [Llx0/l;

    .line 161
    .line 162
    invoke-static {p0, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    check-cast p0, [Llx0/l;

    .line 167
    .line 168
    invoke-static {p0}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    invoke-static {v2, p0}, Lkp/v;->c(Landroid/content/Intent;Landroid/os/Bundle;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v7, v4}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    if-eqz v2, :cond_6

    .line 180
    .line 181
    invoke-virtual {p0, v2}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 182
    .line 183
    .line 184
    :cond_6
    iget-object v2, v6, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v2, Landroid/content/Intent;

    .line 187
    .line 188
    invoke-virtual {v2, v4, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;

    .line 189
    .line 190
    .line 191
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    if-eqz v2, :cond_a

    .line 200
    .line 201
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    add-int/lit8 v3, v5, 0x1

    .line 206
    .line 207
    if-ltz v5, :cond_9

    .line 208
    .line 209
    check-cast v2, Ljava/lang/Number;

    .line 210
    .line 211
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 212
    .line 213
    .line 214
    move-result v2

    .line 215
    if-eqz v8, :cond_7

    .line 216
    .line 217
    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v4

    .line 221
    check-cast v4, Landroid/os/Bundle;

    .line 222
    .line 223
    goto :goto_3

    .line 224
    :cond_7
    move-object v4, v1

    .line 225
    :goto_3
    iget-object v5, v6, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v5, Ljava/util/ArrayList;

    .line 228
    .line 229
    new-instance v7, Lz9/s;

    .line 230
    .line 231
    invoke-direct {v7, v2, v4}, Lz9/s;-><init>(ILandroid/os/Bundle;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    iget-object v2, v6, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v2, Lz9/v;

    .line 240
    .line 241
    if-eqz v2, :cond_8

    .line 242
    .line 243
    invoke-virtual {v6}, Landroidx/lifecycle/c1;->K()V

    .line 244
    .line 245
    .line 246
    :cond_8
    move v5, v3

    .line 247
    goto :goto_2

    .line 248
    :cond_9
    invoke-static {}, Ljp/k1;->r()V

    .line 249
    .line 250
    .line 251
    throw v1

    .line 252
    :cond_a
    invoke-virtual {v6}, Landroidx/lifecycle/c1;->p()Landroidx/core/app/m0;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    invoke-virtual {p0}, Landroidx/core/app/m0;->i()V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v0}, Landroid/app/Activity;->finish()V

    .line 260
    .line 261
    .line 262
    return-void

    .line 263
    :cond_b
    invoke-virtual {v6}, Lca/g;->h()Lz9/u;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    iget-object v3, v2, Lz9/u;->e:Lca/j;

    .line 271
    .line 272
    iget v3, v3, Lca/j;->a:I

    .line 273
    .line 274
    iget-object v2, v2, Lz9/u;->f:Lz9/v;

    .line 275
    .line 276
    :goto_4
    if-eqz v2, :cond_10

    .line 277
    .line 278
    iget-object v7, v2, Lz9/u;->e:Lca/j;

    .line 279
    .line 280
    iget-object v8, v2, Lz9/v;->i:Lca/m;

    .line 281
    .line 282
    iget v8, v8, Lca/m;->d:I

    .line 283
    .line 284
    if-eq v8, v3, :cond_f

    .line 285
    .line 286
    new-array v2, v5, [Llx0/l;

    .line 287
    .line 288
    invoke-static {v2, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    check-cast v2, [Llx0/l;

    .line 293
    .line 294
    invoke-static {v2}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    if-eqz v0, :cond_d

    .line 299
    .line 300
    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 301
    .line 302
    .line 303
    move-result-object v3

    .line 304
    if-eqz v3, :cond_d

    .line 305
    .line 306
    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 307
    .line 308
    .line 309
    move-result-object v3

    .line 310
    invoke-virtual {v3}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 311
    .line 312
    .line 313
    move-result-object v3

    .line 314
    if-eqz v3, :cond_d

    .line 315
    .line 316
    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 317
    .line 318
    .line 319
    move-result-object v3

    .line 320
    const-string v5, "getIntent(...)"

    .line 321
    .line 322
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    invoke-static {v3, v2}, Lkp/v;->c(Landroid/content/Intent;Landroid/os/Bundle;)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {v6}, Lca/g;->k()Lz9/v;

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    invoke-virtual {v0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    .line 333
    .line 334
    .line 335
    move-result-object v6

    .line 336
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 337
    .line 338
    .line 339
    new-instance v5, Lrn/i;

    .line 340
    .line 341
    invoke-virtual {v6}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 342
    .line 343
    .line 344
    move-result-object v8

    .line 345
    invoke-virtual {v6}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v9

    .line 349
    invoke-virtual {v6}, Landroid/content/Intent;->getType()Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v6

    .line 353
    const/16 v10, 0x19

    .line 354
    .line 355
    invoke-direct {v5, v8, v9, v6, v10}, Lrn/i;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;I)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v3, v5, v3}, Lz9/v;->n(Lrn/i;Lz9/u;)Lz9/t;

    .line 359
    .line 360
    .line 361
    move-result-object v3

    .line 362
    if-eqz v3, :cond_c

    .line 363
    .line 364
    iget-object v5, v3, Lz9/t;->e:Landroid/os/Bundle;

    .line 365
    .line 366
    goto :goto_5

    .line 367
    :cond_c
    move-object v5, v1

    .line 368
    :goto_5
    if-eqz v5, :cond_d

    .line 369
    .line 370
    iget-object v5, v3, Lz9/t;->d:Lz9/u;

    .line 371
    .line 372
    iget-object v3, v3, Lz9/t;->e:Landroid/os/Bundle;

    .line 373
    .line 374
    invoke-virtual {v5, v3}, Lz9/u;->e(Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 375
    .line 376
    .line 377
    move-result-object v3

    .line 378
    if-eqz v3, :cond_d

    .line 379
    .line 380
    invoke-virtual {v2, v3}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 381
    .line 382
    .line 383
    :cond_d
    new-instance v3, Landroidx/lifecycle/c1;

    .line 384
    .line 385
    invoke-direct {v3, p0}, Landroidx/lifecycle/c1;-><init>(Lz9/y;)V

    .line 386
    .line 387
    .line 388
    iget p0, v7, Lca/j;->a:I

    .line 389
    .line 390
    iget-object v5, v3, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 391
    .line 392
    check-cast v5, Ljava/util/ArrayList;

    .line 393
    .line 394
    invoke-virtual {v5}, Ljava/util/ArrayList;->clear()V

    .line 395
    .line 396
    .line 397
    new-instance v6, Lz9/s;

    .line 398
    .line 399
    invoke-direct {v6, p0, v1}, Lz9/s;-><init>(ILandroid/os/Bundle;)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    iget-object p0, v3, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 406
    .line 407
    check-cast p0, Lz9/v;

    .line 408
    .line 409
    if-eqz p0, :cond_e

    .line 410
    .line 411
    invoke-virtual {v3}, Landroidx/lifecycle/c1;->K()V

    .line 412
    .line 413
    .line 414
    :cond_e
    iget-object p0, v3, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 415
    .line 416
    check-cast p0, Landroid/content/Intent;

    .line 417
    .line 418
    invoke-virtual {p0, v4, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;

    .line 419
    .line 420
    .line 421
    invoke-virtual {v3}, Landroidx/lifecycle/c1;->p()Landroidx/core/app/m0;

    .line 422
    .line 423
    .line 424
    move-result-object p0

    .line 425
    invoke-virtual {p0}, Landroidx/core/app/m0;->i()V

    .line 426
    .line 427
    .line 428
    if-eqz v0, :cond_10

    .line 429
    .line 430
    invoke-virtual {v0}, Landroid/app/Activity;->finish()V

    .line 431
    .line 432
    .line 433
    return-void

    .line 434
    :cond_f
    iget v3, v7, Lca/j;->a:I

    .line 435
    .line 436
    iget-object v2, v2, Lz9/u;->f:Lz9/v;

    .line 437
    .line 438
    goto/16 :goto_4

    .line 439
    .line 440
    :cond_10
    :goto_6
    return-void

    .line 441
    :cond_11
    invoke-virtual {p0}, Lz9/y;->h()Z

    .line 442
    .line 443
    .line 444
    return-void
.end method

.method public final h()Z
    .locals 3

    .line 1
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 2
    .line 3
    iget-object v0, p0, Lca/g;->f:Lmx0/l;

    .line 4
    .line 5
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    return v1

    .line 13
    :cond_0
    invoke-virtual {p0}, Lca/g;->h()Lz9/u;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 21
    .line 22
    iget v0, v0, Lca/j;->a:I

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    invoke-virtual {p0, v0, v2, v1}, Lca/g;->o(IZZ)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0}, Lca/g;->b()Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-eqz p0, :cond_1

    .line 36
    .line 37
    return v2

    .line 38
    :cond_1
    return v1
.end method
