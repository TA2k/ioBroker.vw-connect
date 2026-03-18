.class public final Lvp/m1;
.super Lcom/google/android/gms/internal/measurement/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvp/c0;


# instance fields
.field public final c:Lvp/z3;

.field public d:Ljava/lang/Boolean;

.field public e:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lvp/z3;)V
    .locals 1

    .line 1
    const-string v0, "com.google.android.gms.measurement.internal.IMeasurementService"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/measurement/y;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lvp/m1;->c:Lvp/z3;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    iput-object p1, p0, Lvp/m1;->e:Ljava/lang/String;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final D(Lvp/f4;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvp/i1;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lvp/i1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final E(Lvp/f4;)V
    .locals 2

    .line 1
    iget-object v0, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lvp/f4;->v:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lvp/h1;

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    invoke-direct {v0, p0, p1, v1}, Lvp/h1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lvp/m1;->b(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final F(Lvp/f4;)V
    .locals 2

    .line 1
    iget-object v0, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lvp/f4;->v:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lvp/i1;

    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    invoke-direct {v0, p0, p1, v1}, Lvp/i1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lvp/m1;->b(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final H(Ljava/lang/String;Ljava/lang/String;ZLvp/f4;)Ljava/util/List;
    .locals 7

    .line 1
    invoke-virtual {p0, p4}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object v2, p4, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p4, p0, Lvp/m1;->c:Lvp/z3;

    .line 10
    .line 11
    invoke-virtual {p4}, Lvp/z3;->f()Lvp/e1;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    new-instance v0, Lvp/k1;

    .line 16
    .line 17
    const/4 v5, 0x0

    .line 18
    move-object v1, p0

    .line 19
    move-object v3, p1

    .line 20
    move-object v4, p2

    .line 21
    invoke-direct/range {v0 .. v5}, Lvp/k1;-><init>(Lvp/m1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v6, v0}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :try_start_0
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Ljava/util/List;

    .line 33
    .line 34
    new-instance p1, Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_2

    .line 52
    .line 53
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    check-cast p2, Lvp/c4;

    .line 58
    .line 59
    if-nez p3, :cond_1

    .line 60
    .line 61
    iget-object v0, p2, Lvp/c4;->c:Ljava/lang/String;

    .line 62
    .line 63
    invoke-static {v0}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-nez v0, :cond_0

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :catch_0
    move-exception v0

    .line 71
    move-object p0, v0

    .line 72
    goto :goto_2

    .line 73
    :cond_1
    :goto_1
    new-instance v0, Lvp/b4;

    .line 74
    .line 75
    invoke-direct {v0, p2}, Lvp/b4;-><init>(Lvp/c4;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_2
    return-object p1

    .line 83
    :goto_2
    invoke-virtual {p4}, Lvp/z3;->d()Lvp/p0;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 88
    .line 89
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    const-string p3, "Failed to query user properties. appId"

    .line 94
    .line 95
    invoke-virtual {p1, p2, p0, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 99
    .line 100
    return-object p0
.end method

.method public final J(Lvp/f4;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvp/h1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lvp/h1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final M(Lvp/f4;)Lvp/j;
    .locals 5

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lvp/m1;->c:Lvp/z3;

    .line 10
    .line 11
    invoke-virtual {v1}, Lvp/z3;->f()Lvp/e1;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    new-instance v3, Lcq/s1;

    .line 16
    .line 17
    const/4 v4, 0x4

    .line 18
    invoke-direct {v3, p0, p1, v4}, Lcq/s1;-><init>(Lvp/m1;Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2, v3}, Lvp/e1;->i0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :try_start_0
    sget-object p1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 26
    .line 27
    const-wide/16 v2, 0x2710

    .line 28
    .line 29
    invoke-virtual {p0, v2, v3, p1}, Ljava/util/concurrent/FutureTask;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lvp/j;
    :try_end_0
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 34
    .line 35
    return-object p0

    .line 36
    :catch_0
    move-exception p0

    .line 37
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 42
    .line 43
    invoke-static {v0}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const-string v1, "Failed to get consent. appId"

    .line 48
    .line 49
    invoke-virtual {p1, v0, p0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance p0, Lvp/j;

    .line 53
    .line 54
    const/4 p1, 0x0

    .line 55
    invoke-direct {p0, p1}, Lvp/j;-><init>(Landroid/os/Bundle;)V

    .line 56
    .line 57
    .line 58
    return-object p0
.end method

.method public final N(Landroid/os/Bundle;Lvp/f4;)V
    .locals 6

    .line 1
    invoke-virtual {p0, p2}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object v3, p2, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    new-instance v0, Ld6/z0;

    .line 10
    .line 11
    const/4 v5, 0x6

    .line 12
    move-object v1, p0

    .line 13
    move-object v2, p1

    .line 14
    move-object v4, p2

    .line 15
    invoke-direct/range {v0 .. v5}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final O(Lvp/f4;)V
    .locals 2

    .line 1
    iget-object v0, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p1, Lvp/f4;->v:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lvp/i1;

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    invoke-direct {v0, p0, p1, v1}, Lvp/i1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lvp/m1;->b(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final P(Lvp/b4;Lvp/f4;)V
    .locals 6

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p2}, Lvp/m1;->c(Lvp/f4;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lio/i;

    .line 8
    .line 9
    const/4 v5, 0x7

    .line 10
    const/4 v3, 0x0

    .line 11
    move-object v1, p0

    .line 12
    move-object v2, p1

    .line 13
    move-object v4, p2

    .line 14
    invoke-direct/range {v0 .. v5}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final Q(Ljava/lang/String;Z)V
    .locals 4

    .line 1
    const-string v0, "Unknown calling package name \'"

    .line 2
    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object v2, p0, Lvp/m1;->c:Lvp/z3;

    .line 8
    .line 9
    if-nez v1, :cond_7

    .line 10
    .line 11
    if-eqz p2, :cond_3

    .line 12
    .line 13
    :try_start_0
    iget-object p2, p0, Lvp/m1;->d:Ljava/lang/Boolean;

    .line 14
    .line 15
    if-nez p2, :cond_2

    .line 16
    .line 17
    const-string p2, "com.google.android.gms"

    .line 18
    .line 19
    iget-object v1, p0, Lvp/m1;->e:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {p2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    const/4 v1, 0x1

    .line 26
    if-nez p2, :cond_1

    .line 27
    .line 28
    iget-object p2, v2, Lvp/z3;->o:Lvp/g1;

    .line 29
    .line 30
    iget-object p2, p2, Lvp/g1;->d:Landroid/content/Context;

    .line 31
    .line 32
    invoke-static {}, Landroid/os/Binder;->getCallingUid()I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    invoke-static {p2, v3}, Lto/b;->d(Landroid/content/Context;I)Z

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    if-nez p2, :cond_1

    .line 41
    .line 42
    iget-object p2, v2, Lvp/z3;->o:Lvp/g1;

    .line 43
    .line 44
    iget-object p2, p2, Lvp/g1;->d:Landroid/content/Context;

    .line 45
    .line 46
    invoke-static {p2}, Ljo/i;->a(Landroid/content/Context;)Ljo/i;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    invoke-static {}, Landroid/os/Binder;->getCallingUid()I

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    invoke-virtual {p2, v3}, Ljo/i;->b(I)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_0

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    const/4 v1, 0x0

    .line 62
    goto :goto_0

    .line 63
    :catch_0
    move-exception p0

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    :goto_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    iput-object p2, p0, Lvp/m1;->d:Ljava/lang/Boolean;

    .line 70
    .line 71
    :cond_2
    iget-object p2, p0, Lvp/m1;->d:Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    if-nez p2, :cond_5

    .line 78
    .line 79
    :cond_3
    iget-object p2, p0, Lvp/m1;->e:Ljava/lang/String;

    .line 80
    .line 81
    if-nez p2, :cond_4

    .line 82
    .line 83
    iget-object p2, v2, Lvp/z3;->o:Lvp/g1;

    .line 84
    .line 85
    iget-object p2, p2, Lvp/g1;->d:Landroid/content/Context;

    .line 86
    .line 87
    invoke-static {}, Landroid/os/Binder;->getCallingUid()I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    sget-object v3, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 92
    .line 93
    invoke-static {p2, p1, v1}, Lto/b;->f(Landroid/content/Context;Ljava/lang/String;I)Z

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    if-eqz p2, :cond_4

    .line 98
    .line 99
    iput-object p1, p0, Lvp/m1;->e:Ljava/lang/String;

    .line 100
    .line 101
    :cond_4
    iget-object p0, p0, Lvp/m1;->e:Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {p1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-eqz p0, :cond_6

    .line 108
    .line 109
    :cond_5
    return-void

    .line 110
    :cond_6
    new-instance p0, Ljava/lang/SecurityException;

    .line 111
    .line 112
    new-instance p2, Ljava/lang/StringBuilder;

    .line 113
    .line 114
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string v0, "\'."

    .line 121
    .line 122
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p2

    .line 129
    invoke-direct {p0, p2}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 133
    :goto_1
    invoke-virtual {v2}, Lvp/z3;->d()Lvp/p0;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    iget-object p2, p2, Lvp/p0;->j:Lvp/n0;

    .line 138
    .line 139
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    const-string v0, "Measurement Service called with invalid calling package. appId"

    .line 144
    .line 145
    invoke-virtual {p2, p1, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_7
    invoke-virtual {v2}, Lvp/z3;->d()Lvp/p0;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 154
    .line 155
    const-string p1, "Measurement Service called without app package"

    .line 156
    .line 157
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    new-instance p0, Ljava/lang/SecurityException;

    .line 161
    .line 162
    invoke-direct {p0, p1}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw p0
.end method

.method public final R(Ljava/lang/Runnable;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lvp/m1;->c:Lvp/z3;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvp/z3;->f()Lvp/e1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lvp/e1;->g0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p0}, Lvp/z3;->f()Lvp/e1;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0, p1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final a(ILandroid/os/Parcel;Landroid/os/Parcel;)Z
    .locals 10

    .line 1
    iget-object v2, p0, Lvp/m1;->c:Lvp/z3;

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    const/4 v4, 0x0

    .line 5
    const/4 v6, 0x1

    .line 6
    packed-switch p1, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    :pswitch_0
    return v4

    .line 10
    :pswitch_1
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 11
    .line 12
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    check-cast v2, Lvp/f4;

    .line 17
    .line 18
    sget-object v4, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 19
    .line 20
    invoke-static {p2, v4}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Landroid/os/Bundle;

    .line 25
    .line 26
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    if-nez v5, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const-string v3, "com.google.android.gms.measurement.internal.ITriggerUrisCallback"

    .line 34
    .line 35
    invoke-interface {v5, v3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    instance-of v8, v7, Lvp/e0;

    .line 40
    .line 41
    if-eqz v8, :cond_1

    .line 42
    .line 43
    move-object v3, v7

    .line 44
    check-cast v3, Lvp/e0;

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    new-instance v7, Lvp/d0;

    .line 48
    .line 49
    invoke-direct {v7, v5, v3, v6}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 50
    .line 51
    .line 52
    move-object v3, v7

    .line 53
    :goto_0
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0, v2, v4, v3}, Lvp/m1;->v(Lvp/f4;Landroid/os/Bundle;Lvp/e0;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 60
    .line 61
    .line 62
    return v6

    .line 63
    :pswitch_2
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 64
    .line 65
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    check-cast v2, Lvp/f4;

    .line 70
    .line 71
    sget-object v3, Lvp/e;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 72
    .line 73
    invoke-static {p2, v3}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    check-cast v3, Lvp/e;

    .line 78
    .line 79
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, v2, v3}, Lvp/m1;->l(Lvp/f4;Lvp/e;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 86
    .line 87
    .line 88
    return v6

    .line 89
    :pswitch_3
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 90
    .line 91
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    check-cast v2, Lvp/f4;

    .line 96
    .line 97
    sget-object v4, Lvp/s3;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 98
    .line 99
    invoke-static {p2, v4}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    check-cast v4, Lvp/s3;

    .line 104
    .line 105
    invoke-virtual {p2}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 106
    .line 107
    .line 108
    move-result-object v5

    .line 109
    if-nez v5, :cond_2

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_2
    const-string v3, "com.google.android.gms.measurement.internal.IUploadBatchesCallback"

    .line 113
    .line 114
    invoke-interface {v5, v3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    instance-of v8, v7, Lvp/g0;

    .line 119
    .line 120
    if-eqz v8, :cond_3

    .line 121
    .line 122
    move-object v3, v7

    .line 123
    check-cast v3, Lvp/g0;

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_3
    new-instance v7, Lvp/f0;

    .line 127
    .line 128
    invoke-direct {v7, v5, v3, v6}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 129
    .line 130
    .line 131
    move-object v3, v7

    .line 132
    :goto_1
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p0, v2, v4, v3}, Lvp/m1;->d(Lvp/f4;Lvp/s3;Lvp/g0;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 139
    .line 140
    .line 141
    return v6

    .line 142
    :pswitch_4
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 143
    .line 144
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    check-cast v2, Lvp/f4;

    .line 149
    .line 150
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0, v2}, Lvp/m1;->f(Lvp/f4;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 157
    .line 158
    .line 159
    return v6

    .line 160
    :pswitch_5
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 161
    .line 162
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    check-cast v2, Lvp/f4;

    .line 167
    .line 168
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p0, v2}, Lvp/m1;->E(Lvp/f4;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 175
    .line 176
    .line 177
    return v6

    .line 178
    :pswitch_6
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 179
    .line 180
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    check-cast v2, Lvp/f4;

    .line 185
    .line 186
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p0, v2}, Lvp/m1;->F(Lvp/f4;)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 193
    .line 194
    .line 195
    return v6

    .line 196
    :pswitch_7
    sget-object v5, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 197
    .line 198
    invoke-static {p2, v5}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    check-cast v5, Lvp/f4;

    .line 203
    .line 204
    sget-object v7, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 205
    .line 206
    invoke-static {p2, v7}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 207
    .line 208
    .line 209
    move-result-object v7

    .line 210
    check-cast v7, Landroid/os/Bundle;

    .line 211
    .line 212
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p0, v5}, Lvp/m1;->c(Lvp/f4;)V

    .line 216
    .line 217
    .line 218
    iget-object v1, v5, Lvp/f4;->d:Ljava/lang/String;

    .line 219
    .line 220
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v2}, Lvp/z3;->d0()Lvp/h;

    .line 224
    .line 225
    .line 226
    move-result-object v8

    .line 227
    sget-object v9, Lvp/z;->Y0:Lvp/y;

    .line 228
    .line 229
    invoke-virtual {v8, v3, v9}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    const-string v8, "Failed to get trigger URIs. appId"

    .line 234
    .line 235
    if-eqz v3, :cond_4

    .line 236
    .line 237
    invoke-virtual {v2}, Lvp/z3;->f()Lvp/e1;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    new-instance v9, Lvp/l1;

    .line 242
    .line 243
    invoke-direct {v9, p0, v5, v7, v4}, Lvp/l1;-><init>(Lvp/m1;Lvp/f4;Landroid/os/Bundle;I)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v3, v9}, Lvp/e1;->i0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    :try_start_0
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 251
    .line 252
    const-wide/16 v4, 0x2710

    .line 253
    .line 254
    invoke-virtual {v0, v4, v5, v3}, Ljava/util/concurrent/FutureTask;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    check-cast v0, Ljava/util/List;
    :try_end_0
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 259
    .line 260
    goto :goto_2

    .line 261
    :catch_0
    move-exception v0

    .line 262
    invoke-virtual {v2}, Lvp/z3;->d()Lvp/p0;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 267
    .line 268
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    invoke-virtual {v2, v1, v0, v8}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 276
    .line 277
    goto :goto_2

    .line 278
    :cond_4
    invoke-virtual {v2}, Lvp/z3;->f()Lvp/e1;

    .line 279
    .line 280
    .line 281
    move-result-object v3

    .line 282
    new-instance v4, Lvp/l1;

    .line 283
    .line 284
    invoke-direct {v4, p0, v5, v7, v6}, Lvp/l1;-><init>(Lvp/m1;Lvp/f4;Landroid/os/Bundle;I)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v3, v4}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    :try_start_1
    invoke-virtual {v0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v0

    .line 295
    check-cast v0, Ljava/util/List;
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_1 .. :try_end_1} :catch_1

    .line 296
    .line 297
    goto :goto_2

    .line 298
    :catch_1
    move-exception v0

    .line 299
    invoke-virtual {v2}, Lvp/z3;->d()Lvp/p0;

    .line 300
    .line 301
    .line 302
    move-result-object v2

    .line 303
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 304
    .line 305
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-virtual {v2, v1, v0, v8}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 313
    .line 314
    :goto_2
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 315
    .line 316
    .line 317
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 318
    .line 319
    .line 320
    goto/16 :goto_7

    .line 321
    .line 322
    :pswitch_8
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 323
    .line 324
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 325
    .line 326
    .line 327
    move-result-object v2

    .line 328
    check-cast v2, Lvp/f4;

    .line 329
    .line 330
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {p0, v2}, Lvp/m1;->M(Lvp/f4;)Lvp/j;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 338
    .line 339
    .line 340
    if-nez v0, :cond_5

    .line 341
    .line 342
    invoke-virtual {p3, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 343
    .line 344
    .line 345
    return v6

    .line 346
    :cond_5
    invoke-virtual {p3, v6}, Landroid/os/Parcel;->writeInt(I)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v0, p3, v6}, Lvp/j;->writeToParcel(Landroid/os/Parcel;I)V

    .line 350
    .line 351
    .line 352
    return v6

    .line 353
    :pswitch_9
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 354
    .line 355
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    check-cast v2, Lvp/f4;

    .line 360
    .line 361
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {p0, v2}, Lvp/m1;->O(Lvp/f4;)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 368
    .line 369
    .line 370
    return v6

    .line 371
    :pswitch_a
    sget-object v2, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 372
    .line 373
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 374
    .line 375
    .line 376
    move-result-object v2

    .line 377
    check-cast v2, Landroid/os/Bundle;

    .line 378
    .line 379
    sget-object v3, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 380
    .line 381
    invoke-static {p2, v3}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 382
    .line 383
    .line 384
    move-result-object v3

    .line 385
    check-cast v3, Lvp/f4;

    .line 386
    .line 387
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {p0, v2, v3}, Lvp/m1;->N(Landroid/os/Bundle;Lvp/f4;)V

    .line 391
    .line 392
    .line 393
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 394
    .line 395
    .line 396
    return v6

    .line 397
    :pswitch_b
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 398
    .line 399
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 400
    .line 401
    .line 402
    move-result-object v2

    .line 403
    check-cast v2, Lvp/f4;

    .line 404
    .line 405
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {p0, v2}, Lvp/m1;->g(Lvp/f4;)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 412
    .line 413
    .line 414
    return v6

    .line 415
    :pswitch_c
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v2

    .line 419
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v3

    .line 423
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 424
    .line 425
    .line 426
    move-result-object v4

    .line 427
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 428
    .line 429
    .line 430
    invoke-virtual {p0, v2, v3, v4}, Lvp/m1;->h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 431
    .line 432
    .line 433
    move-result-object v0

    .line 434
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 435
    .line 436
    .line 437
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 438
    .line 439
    .line 440
    return v6

    .line 441
    :pswitch_d
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 442
    .line 443
    .line 444
    move-result-object v2

    .line 445
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 446
    .line 447
    .line 448
    move-result-object v3

    .line 449
    sget-object v4, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 450
    .line 451
    invoke-static {p2, v4}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 452
    .line 453
    .line 454
    move-result-object v4

    .line 455
    check-cast v4, Lvp/f4;

    .line 456
    .line 457
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {p0, v2, v3, v4}, Lvp/m1;->t(Ljava/lang/String;Ljava/lang/String;Lvp/f4;)Ljava/util/List;

    .line 461
    .line 462
    .line 463
    move-result-object v0

    .line 464
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 465
    .line 466
    .line 467
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 468
    .line 469
    .line 470
    return v6

    .line 471
    :pswitch_e
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 472
    .line 473
    .line 474
    move-result-object v2

    .line 475
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 476
    .line 477
    .line 478
    move-result-object v3

    .line 479
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object v5

    .line 483
    sget-object v7, Lcom/google/android/gms/internal/measurement/z;->a:Ljava/lang/ClassLoader;

    .line 484
    .line 485
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 486
    .line 487
    .line 488
    move-result v7

    .line 489
    if-eqz v7, :cond_6

    .line 490
    .line 491
    move v4, v6

    .line 492
    :cond_6
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 493
    .line 494
    .line 495
    invoke-virtual {p0, v4, v2, v3, v5}, Lvp/m1;->r(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 500
    .line 501
    .line 502
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 503
    .line 504
    .line 505
    return v6

    .line 506
    :pswitch_f
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object v2

    .line 510
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 511
    .line 512
    .line 513
    move-result-object v3

    .line 514
    sget-object v5, Lcom/google/android/gms/internal/measurement/z;->a:Ljava/lang/ClassLoader;

    .line 515
    .line 516
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 517
    .line 518
    .line 519
    move-result v5

    .line 520
    if-eqz v5, :cond_7

    .line 521
    .line 522
    move v4, v6

    .line 523
    :cond_7
    sget-object v5, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 524
    .line 525
    invoke-static {p2, v5}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 526
    .line 527
    .line 528
    move-result-object v5

    .line 529
    check-cast v5, Lvp/f4;

    .line 530
    .line 531
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 532
    .line 533
    .line 534
    invoke-virtual {p0, v2, v3, v4, v5}, Lvp/m1;->H(Ljava/lang/String;Ljava/lang/String;ZLvp/f4;)Ljava/util/List;

    .line 535
    .line 536
    .line 537
    move-result-object v0

    .line 538
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 539
    .line 540
    .line 541
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 542
    .line 543
    .line 544
    return v6

    .line 545
    :pswitch_10
    sget-object v2, Lvp/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 546
    .line 547
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 548
    .line 549
    .line 550
    move-result-object v2

    .line 551
    check-cast v2, Lvp/f;

    .line 552
    .line 553
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 554
    .line 555
    .line 556
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 557
    .line 558
    .line 559
    iget-object v1, v2, Lvp/f;->f:Lvp/b4;

    .line 560
    .line 561
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 562
    .line 563
    .line 564
    iget-object v1, v2, Lvp/f;->d:Ljava/lang/String;

    .line 565
    .line 566
    invoke-static {v1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 567
    .line 568
    .line 569
    iget-object v1, v2, Lvp/f;->d:Ljava/lang/String;

    .line 570
    .line 571
    invoke-virtual {p0, v1, v6}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 572
    .line 573
    .line 574
    new-instance v1, Lvp/f;

    .line 575
    .line 576
    invoke-direct {v1, v2}, Lvp/f;-><init>(Lvp/f;)V

    .line 577
    .line 578
    .line 579
    new-instance v2, Lk0/g;

    .line 580
    .line 581
    const/16 v3, 0xf

    .line 582
    .line 583
    invoke-direct {v2, p0, v1, v4, v3}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 584
    .line 585
    .line 586
    invoke-virtual {p0, v2}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 590
    .line 591
    .line 592
    return v6

    .line 593
    :pswitch_11
    sget-object v2, Lvp/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 594
    .line 595
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 596
    .line 597
    .line 598
    move-result-object v2

    .line 599
    check-cast v2, Lvp/f;

    .line 600
    .line 601
    sget-object v3, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 602
    .line 603
    invoke-static {p2, v3}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 604
    .line 605
    .line 606
    move-result-object v3

    .line 607
    check-cast v3, Lvp/f4;

    .line 608
    .line 609
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 610
    .line 611
    .line 612
    invoke-virtual {p0, v2, v3}, Lvp/m1;->i(Lvp/f;Lvp/f4;)V

    .line 613
    .line 614
    .line 615
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 616
    .line 617
    .line 618
    return v6

    .line 619
    :pswitch_12
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 620
    .line 621
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 622
    .line 623
    .line 624
    move-result-object v2

    .line 625
    check-cast v2, Lvp/f4;

    .line 626
    .line 627
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 628
    .line 629
    .line 630
    invoke-virtual {p0, v2}, Lvp/m1;->u(Lvp/f4;)Ljava/lang/String;

    .line 631
    .line 632
    .line 633
    move-result-object v0

    .line 634
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 635
    .line 636
    .line 637
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 638
    .line 639
    .line 640
    return v6

    .line 641
    :pswitch_13
    invoke-virtual {p2}, Landroid/os/Parcel;->readLong()J

    .line 642
    .line 643
    .line 644
    move-result-wide v1

    .line 645
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 646
    .line 647
    .line 648
    move-result-object v3

    .line 649
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 650
    .line 651
    .line 652
    move-result-object v4

    .line 653
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 654
    .line 655
    .line 656
    move-result-object v5

    .line 657
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 658
    .line 659
    .line 660
    move-object v0, p0

    .line 661
    invoke-virtual/range {v0 .. v5}, Lvp/m1;->w(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 665
    .line 666
    .line 667
    return v6

    .line 668
    :pswitch_14
    sget-object v1, Lvp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 669
    .line 670
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 671
    .line 672
    .line 673
    move-result-object v1

    .line 674
    check-cast v1, Lvp/t;

    .line 675
    .line 676
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 677
    .line 678
    .line 679
    move-result-object v2

    .line 680
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 681
    .line 682
    .line 683
    invoke-virtual {p0, v2, v1}, Lvp/m1;->q(Ljava/lang/String;Lvp/t;)[B

    .line 684
    .line 685
    .line 686
    move-result-object v0

    .line 687
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 688
    .line 689
    .line 690
    invoke-virtual {p3, v0}, Landroid/os/Parcel;->writeByteArray([B)V

    .line 691
    .line 692
    .line 693
    return v6

    .line 694
    :pswitch_15
    sget-object v1, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 695
    .line 696
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 697
    .line 698
    .line 699
    move-result-object v1

    .line 700
    check-cast v1, Lvp/f4;

    .line 701
    .line 702
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 703
    .line 704
    .line 705
    move-result v5

    .line 706
    if-eqz v5, :cond_8

    .line 707
    .line 708
    move v4, v6

    .line 709
    :cond_8
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 710
    .line 711
    .line 712
    invoke-virtual {p0, v1}, Lvp/m1;->c(Lvp/f4;)V

    .line 713
    .line 714
    .line 715
    iget-object v1, v1, Lvp/f4;->d:Ljava/lang/String;

    .line 716
    .line 717
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 718
    .line 719
    .line 720
    invoke-virtual {v2}, Lvp/z3;->f()Lvp/e1;

    .line 721
    .line 722
    .line 723
    move-result-object v5

    .line 724
    new-instance v7, Lcq/s1;

    .line 725
    .line 726
    const/4 v8, 0x3

    .line 727
    invoke-direct {v7, p0, v1, v8}, Lcq/s1;-><init>(Lvp/m1;Ljava/lang/Object;I)V

    .line 728
    .line 729
    .line 730
    invoke-virtual {v5, v7}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 731
    .line 732
    .line 733
    move-result-object v0

    .line 734
    :try_start_2
    invoke-virtual {v0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    move-result-object v0

    .line 738
    check-cast v0, Ljava/util/List;

    .line 739
    .line 740
    new-instance v5, Ljava/util/ArrayList;

    .line 741
    .line 742
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 743
    .line 744
    .line 745
    move-result v7

    .line 746
    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 747
    .line 748
    .line 749
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 750
    .line 751
    .line 752
    move-result-object v0

    .line 753
    :cond_9
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 754
    .line 755
    .line 756
    move-result v7

    .line 757
    if-eqz v7, :cond_b

    .line 758
    .line 759
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 760
    .line 761
    .line 762
    move-result-object v7

    .line 763
    check-cast v7, Lvp/c4;

    .line 764
    .line 765
    if-nez v4, :cond_a

    .line 766
    .line 767
    iget-object v8, v7, Lvp/c4;->c:Ljava/lang/String;

    .line 768
    .line 769
    invoke-static {v8}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 770
    .line 771
    .line 772
    move-result v8

    .line 773
    if-nez v8, :cond_9

    .line 774
    .line 775
    goto :goto_4

    .line 776
    :catch_2
    move-exception v0

    .line 777
    goto :goto_5

    .line 778
    :cond_a
    :goto_4
    new-instance v8, Lvp/b4;

    .line 779
    .line 780
    invoke-direct {v8, v7}, Lvp/b4;-><init>(Lvp/c4;)V

    .line 781
    .line 782
    .line 783
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_2 .. :try_end_2} :catch_2

    .line 784
    .line 785
    .line 786
    goto :goto_3

    .line 787
    :cond_b
    move-object v3, v5

    .line 788
    goto :goto_6

    .line 789
    :goto_5
    invoke-virtual {v2}, Lvp/z3;->d()Lvp/p0;

    .line 790
    .line 791
    .line 792
    move-result-object v2

    .line 793
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 794
    .line 795
    invoke-static {v1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 796
    .line 797
    .line 798
    move-result-object v1

    .line 799
    const-string v4, "Failed to get user properties. appId"

    .line 800
    .line 801
    invoke-virtual {v2, v1, v0, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 802
    .line 803
    .line 804
    :goto_6
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 805
    .line 806
    .line 807
    invoke-virtual {p3, v3}, Landroid/os/Parcel;->writeTypedList(Ljava/util/List;)V

    .line 808
    .line 809
    .line 810
    :goto_7
    return v6

    .line 811
    :pswitch_16
    sget-object v1, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 812
    .line 813
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 814
    .line 815
    .line 816
    move-result-object v1

    .line 817
    check-cast v1, Lvp/f4;

    .line 818
    .line 819
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 820
    .line 821
    .line 822
    invoke-virtual {p0, v1}, Lvp/m1;->D(Lvp/f4;)V

    .line 823
    .line 824
    .line 825
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 826
    .line 827
    .line 828
    return v6

    .line 829
    :pswitch_17
    sget-object v1, Lvp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 830
    .line 831
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 832
    .line 833
    .line 834
    move-result-object v1

    .line 835
    move-object v2, v1

    .line 836
    check-cast v2, Lvp/t;

    .line 837
    .line 838
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 839
    .line 840
    .line 841
    move-result-object v4

    .line 842
    invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 843
    .line 844
    .line 845
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 846
    .line 847
    .line 848
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 849
    .line 850
    .line 851
    invoke-static {v4}, Lno/c0;->e(Ljava/lang/String;)V

    .line 852
    .line 853
    .line 854
    invoke-virtual {p0, v4, v6}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 855
    .line 856
    .line 857
    new-instance v0, Lio/i;

    .line 858
    .line 859
    const/4 v5, 0x6

    .line 860
    const/4 v3, 0x0

    .line 861
    move-object v1, p0

    .line 862
    invoke-direct/range {v0 .. v5}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 863
    .line 864
    .line 865
    move-object v1, v0

    .line 866
    invoke-virtual {p0, v1}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 867
    .line 868
    .line 869
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 870
    .line 871
    .line 872
    return v6

    .line 873
    :pswitch_18
    sget-object v1, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 874
    .line 875
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 876
    .line 877
    .line 878
    move-result-object v1

    .line 879
    check-cast v1, Lvp/f4;

    .line 880
    .line 881
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 882
    .line 883
    .line 884
    invoke-virtual {p0, v1}, Lvp/m1;->J(Lvp/f4;)V

    .line 885
    .line 886
    .line 887
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 888
    .line 889
    .line 890
    return v6

    .line 891
    :pswitch_19
    sget-object v1, Lvp/b4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 892
    .line 893
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 894
    .line 895
    .line 896
    move-result-object v1

    .line 897
    check-cast v1, Lvp/b4;

    .line 898
    .line 899
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 900
    .line 901
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 902
    .line 903
    .line 904
    move-result-object v2

    .line 905
    check-cast v2, Lvp/f4;

    .line 906
    .line 907
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 908
    .line 909
    .line 910
    invoke-virtual {p0, v1, v2}, Lvp/m1;->P(Lvp/b4;Lvp/f4;)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 914
    .line 915
    .line 916
    return v6

    .line 917
    :pswitch_1a
    sget-object v1, Lvp/t;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 918
    .line 919
    invoke-static {p2, v1}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 920
    .line 921
    .line 922
    move-result-object v1

    .line 923
    check-cast v1, Lvp/t;

    .line 924
    .line 925
    sget-object v2, Lvp/f4;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 926
    .line 927
    invoke-static {p2, v2}, Lcom/google/android/gms/internal/measurement/z;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 928
    .line 929
    .line 930
    move-result-object v2

    .line 931
    check-cast v2, Lvp/f4;

    .line 932
    .line 933
    invoke-static {p2}, Lcom/google/android/gms/internal/measurement/z;->d(Landroid/os/Parcel;)V

    .line 934
    .line 935
    .line 936
    invoke-virtual {p0, v1, v2}, Lvp/m1;->o(Lvp/t;Lvp/f4;)V

    .line 937
    .line 938
    .line 939
    invoke-virtual {p3}, Landroid/os/Parcel;->writeNoException()V

    .line 940
    .line 941
    .line 942
    return v6

    .line 943
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1a
        :pswitch_19
        :pswitch_0
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_0
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_0
        :pswitch_0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_0
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public final b(Ljava/lang/Runnable;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lvp/m1;->c:Lvp/z3;

    .line 2
    .line 3
    invoke-virtual {p0}, Lvp/z3;->f()Lvp/e1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lvp/e1;->g0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p0}, Lvp/z3;->f()Lvp/e1;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0, p1}, Lvp/e1;->l0(Ljava/lang/Runnable;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final c(Lvp/f4;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-virtual {p0, v0, v1}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lvp/m1;->c:Lvp/z3;

    .line 14
    .line 15
    invoke-virtual {p0}, Lvp/z3;->j0()Lvp/d4;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iget-object p1, p1, Lvp/f4;->e:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lvp/d4;->e0(Ljava/lang/String;)Z

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final d(Lvp/f4;Lvp/s3;Lvp/g0;)V
    .locals 6

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object v2, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lvp/m1;->c:Lvp/z3;

    .line 10
    .line 11
    invoke-virtual {p1}, Lvp/z3;->f()Lvp/e1;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    new-instance v0, Ld6/z0;

    .line 16
    .line 17
    const/4 v5, 0x4

    .line 18
    move-object v1, p0

    .line 19
    move-object v3, p2

    .line 20
    move-object v4, p3

    .line 21
    invoke-direct/range {v0 .. v5}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final f(Lvp/f4;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvp/i1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, p1, v1}, Lvp/i1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final g(Lvp/f4;)V
    .locals 2

    .line 1
    iget-object v0, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {p0, v0, v1}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lvp/h1;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, p0, p1, v1}, Lvp/h1;-><init>(Lvp/m1;Lvp/f4;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, v0}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 3
    .line 4
    .line 5
    iget-object v1, p0, Lvp/m1;->c:Lvp/z3;

    .line 6
    .line 7
    invoke-virtual {v1}, Lvp/z3;->f()Lvp/e1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    new-instance v2, Lvp/k1;

    .line 12
    .line 13
    const/4 v7, 0x3

    .line 14
    move-object v3, p0

    .line 15
    move-object v4, p1

    .line 16
    move-object v5, p2

    .line 17
    move-object v6, p3

    .line 18
    invoke-direct/range {v2 .. v7}, Lvp/k1;-><init>(Lvp/m1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v2}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :try_start_0
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ljava/util/List;
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    return-object p0

    .line 32
    :catch_0
    move-exception v0

    .line 33
    move-object p0, v0

    .line 34
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 39
    .line 40
    const-string p2, "Failed to get conditional user properties as"

    .line 41
    .line 42
    invoke-virtual {p1, p0, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 46
    .line 47
    return-object p0
.end method

.method public final i(Lvp/f;Lvp/f4;)V
    .locals 7

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lvp/f;->f:Lvp/b4;

    .line 5
    .line 6
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p2}, Lvp/m1;->c(Lvp/f4;)V

    .line 10
    .line 11
    .line 12
    new-instance v3, Lvp/f;

    .line 13
    .line 14
    invoke-direct {v3, p1}, Lvp/f;-><init>(Lvp/f;)V

    .line 15
    .line 16
    .line 17
    iget-object p1, p2, Lvp/f4;->d:Ljava/lang/String;

    .line 18
    .line 19
    iput-object p1, v3, Lvp/f;->d:Ljava/lang/String;

    .line 20
    .line 21
    new-instance v1, Lio/i;

    .line 22
    .line 23
    const/4 v6, 0x4

    .line 24
    const/4 v4, 0x0

    .line 25
    move-object v2, p0

    .line 26
    move-object v5, p2

    .line 27
    invoke-direct/range {v1 .. v6}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, v1}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final l(Lvp/f4;Lvp/e;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/i;

    .line 5
    .line 6
    const/16 v1, 0x8

    .line 7
    .line 8
    invoke-direct {v0, p0, p1, p2, v1}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final o(Lvp/t;Lvp/f4;)V
    .locals 6

    .line 1
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p2}, Lvp/m1;->c(Lvp/f4;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lio/i;

    .line 8
    .line 9
    const/4 v5, 0x5

    .line 10
    const/4 v3, 0x0

    .line 11
    move-object v1, p0

    .line 12
    move-object v2, p1

    .line 13
    move-object v4, p2

    .line 14
    invoke-direct/range {v0 .. v5}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final q(Ljava/lang/String;Lvp/t;)[B
    .locals 11

    .line 1
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    invoke-virtual {p0, p1, v0}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lvp/m1;->c:Lvp/z3;

    .line 12
    .line 13
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-object v1, v1, Lvp/p0;->q:Lvp/n0;

    .line 18
    .line 19
    iget-object v2, v0, Lvp/z3;->o:Lvp/g1;

    .line 20
    .line 21
    iget-object v3, v2, Lvp/g1;->m:Lvp/k0;

    .line 22
    .line 23
    iget-object v4, p2, Lvp/t;->d:Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v3, v4}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    const-string v5, "Log and bundle. event"

    .line 30
    .line 31
    invoke-virtual {v1, v3, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Lvp/z3;->l()Lto/a;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 42
    .line 43
    .line 44
    move-result-wide v5

    .line 45
    const-wide/32 v7, 0xf4240

    .line 46
    .line 47
    .line 48
    div-long/2addr v5, v7

    .line 49
    invoke-virtual {v0}, Lvp/z3;->f()Lvp/e1;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    new-instance v3, Lip/p;

    .line 54
    .line 55
    invoke-direct {v3, p0, p2, p1}, Lip/p;-><init>(Lvp/m1;Lvp/t;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1, v3}, Lvp/e1;->i0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    :try_start_0
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, [B

    .line 67
    .line 68
    if-nez p0, :cond_0

    .line 69
    .line 70
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 75
    .line 76
    const-string p2, "Log and bundle returned null. appId"

    .line 77
    .line 78
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {p0, v1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const/4 p0, 0x0

    .line 86
    new-array p0, p0, [B

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :catch_0
    move-exception p0

    .line 90
    goto :goto_1

    .line 91
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lvp/z3;->l()Lto/a;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 99
    .line 100
    .line 101
    move-result-wide v9

    .line 102
    div-long/2addr v9, v7

    .line 103
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    iget-object p2, p2, Lvp/p0;->q:Lvp/n0;

    .line 108
    .line 109
    const-string v1, "Log and bundle processed. event, size, time_ms"

    .line 110
    .line 111
    iget-object v3, v2, Lvp/g1;->m:Lvp/k0;

    .line 112
    .line 113
    invoke-virtual {v3, v4}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    array-length v7, p0

    .line 118
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 119
    .line 120
    .line 121
    move-result-object v7

    .line 122
    sub-long/2addr v9, v5

    .line 123
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    invoke-virtual {p2, v1, v3, v7, v5}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 128
    .line 129
    .line 130
    return-object p0

    .line 131
    :goto_1
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 132
    .line 133
    .line 134
    move-result-object p2

    .line 135
    iget-object p2, p2, Lvp/p0;->j:Lvp/n0;

    .line 136
    .line 137
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    iget-object v0, v2, Lvp/g1;->m:Lvp/k0;

    .line 142
    .line 143
    invoke-virtual {v0, v4}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    const-string v1, "Failed to log and bundle. appId, event, error"

    .line 148
    .line 149
    invoke-virtual {p2, v1, p1, v0, p0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    const/4 p0, 0x0

    .line 153
    return-object p0
.end method

.method public final r(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p2, v0}, Lvp/m1;->Q(Ljava/lang/String;Z)V

    .line 3
    .line 4
    .line 5
    iget-object v1, p0, Lvp/m1;->c:Lvp/z3;

    .line 6
    .line 7
    invoke-virtual {v1}, Lvp/z3;->f()Lvp/e1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    new-instance v2, Lvp/k1;

    .line 12
    .line 13
    const/4 v7, 0x1

    .line 14
    move-object v3, p0

    .line 15
    move-object v4, p2

    .line 16
    move-object v5, p3

    .line 17
    move-object v6, p4

    .line 18
    invoke-direct/range {v2 .. v7}, Lvp/k1;-><init>(Lvp/m1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v2}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :try_start_0
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ljava/util/List;

    .line 30
    .line 31
    new-instance p2, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 34
    .line 35
    .line 36
    move-result p3

    .line 37
    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result p3

    .line 48
    if-eqz p3, :cond_2

    .line 49
    .line 50
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p3

    .line 54
    check-cast p3, Lvp/c4;

    .line 55
    .line 56
    if-nez p1, :cond_1

    .line 57
    .line 58
    iget-object p4, p3, Lvp/c4;->c:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {p4}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 61
    .line 62
    .line 63
    move-result p4

    .line 64
    if-nez p4, :cond_0

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :catch_0
    move-exception v0

    .line 68
    move-object p0, v0

    .line 69
    goto :goto_2

    .line 70
    :cond_1
    :goto_1
    new-instance p4, Lvp/b4;

    .line 71
    .line 72
    invoke-direct {p4, p3}, Lvp/b4;-><init>(Lvp/c4;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_2
    return-object p2

    .line 80
    :goto_2
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 85
    .line 86
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    const-string p3, "Failed to get user properties as. appId"

    .line 91
    .line 92
    invoke-virtual {p1, p2, p0, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 96
    .line 97
    return-object p0
.end method

.method public final t(Ljava/lang/String;Ljava/lang/String;Lvp/f4;)Ljava/util/List;
    .locals 7

    .line 1
    invoke-virtual {p0, p3}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object v2, p3, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p3, p0, Lvp/m1;->c:Lvp/z3;

    .line 10
    .line 11
    invoke-virtual {p3}, Lvp/z3;->f()Lvp/e1;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    new-instance v0, Lvp/k1;

    .line 16
    .line 17
    const/4 v5, 0x2

    .line 18
    move-object v1, p0

    .line 19
    move-object v3, p1

    .line 20
    move-object v4, p2

    .line 21
    invoke-direct/range {v0 .. v5}, Lvp/k1;-><init>(Lvp/m1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v6, v0}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :try_start_0
    invoke-virtual {p0}, Ljava/util/concurrent/FutureTask;->get()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Ljava/util/List;
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    .line 34
    return-object p0

    .line 35
    :catch_0
    move-exception v0

    .line 36
    move-object p0, v0

    .line 37
    invoke-virtual {p3}, Lvp/z3;->d()Lvp/p0;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 42
    .line 43
    const-string p2, "Failed to get conditional user properties"

    .line 44
    .line 45
    invoke-virtual {p1, p0, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 49
    .line 50
    return-object p0
.end method

.method public final u(Lvp/f4;)Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lvp/m1;->c:Lvp/z3;

    .line 5
    .line 6
    invoke-virtual {p0}, Lvp/z3;->f()Lvp/e1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Lcq/s1;

    .line 11
    .line 12
    invoke-direct {v1, p0, p1}, Lcq/s1;-><init>(Lvp/z3;Lvp/f4;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Lvp/e1;->h0(Ljava/util/concurrent/Callable;)Lvp/c1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :try_start_0
    sget-object v1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 20
    .line 21
    const-wide/16 v2, 0x7530

    .line 22
    .line 23
    invoke-virtual {v0, v2, v3, v1}, Ljava/util/concurrent/FutureTask;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Ljava/lang/String;
    :try_end_0
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    .line 29
    return-object v0

    .line 30
    :catch_0
    move-exception v0

    .line 31
    invoke-virtual {p0}, Lvp/z3;->d()Lvp/p0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 36
    .line 37
    iget-object p1, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {p1}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    const-string v1, "Failed to get app instance id. appId"

    .line 44
    .line 45
    invoke-virtual {p0, p1, v0, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const/4 p0, 0x0

    .line 49
    return-object p0
.end method

.method public final v(Lvp/f4;Landroid/os/Bundle;Lvp/e0;)V
    .locals 8

    .line 1
    invoke-virtual {p0, p1}, Lvp/m1;->c(Lvp/f4;)V

    .line 2
    .line 3
    .line 4
    iget-object v5, p1, Lvp/f4;->d:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v5}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lvp/m1;->c:Lvp/z3;

    .line 10
    .line 11
    invoke-virtual {v0}, Lvp/z3;->f()Lvp/e1;

    .line 12
    .line 13
    .line 14
    move-result-object v7

    .line 15
    new-instance v0, Lfv/p;

    .line 16
    .line 17
    const/4 v6, 0x1

    .line 18
    move-object v1, p0

    .line 19
    move-object v2, p1

    .line 20
    move-object v3, p2

    .line 21
    move-object v4, p3

    .line 22
    invoke-direct/range {v0 .. v6}, Lfv/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v7, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final w(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 8

    .line 1
    new-instance v0, Lvp/j1;

    .line 2
    .line 3
    const/4 v7, 0x0

    .line 4
    move-object v1, p0

    .line 5
    move-wide v5, p1

    .line 6
    move-object v4, p3

    .line 7
    move-object v2, p4

    .line 8
    move-object v3, p5

    .line 9
    invoke-direct/range {v0 .. v7}, Lvp/j1;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;JI)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lvp/m1;->R(Ljava/lang/Runnable;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
