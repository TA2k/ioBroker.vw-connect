.class public final Llo/e0;
.super Llo/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lhr/b0;

.field public final c:Laq/k;

.field public final d:Llo/a;


# direct methods
.method public constructor <init>(ILhr/b0;Laq/k;Llo/a;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Llo/f0;-><init>(I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Llo/e0;->c:Laq/k;

    .line 5
    .line 6
    iput-object p2, p0, Llo/e0;->b:Lhr/b0;

    .line 7
    .line 8
    iput-object p4, p0, Llo/e0;->d:Llo/a;

    .line 9
    .line 10
    const/4 p0, 0x2

    .line 11
    if-ne p1, p0, :cond_1

    .line 12
    .line 13
    iget-boolean p0, p2, Lhr/b0;->d:Z

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    const-string p1, "Best-effort write calls cannot pass methods that should auto-resolve missing features."

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    :goto_0
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/android/gms/common/api/Status;)V
    .locals 1

    .line 1
    iget-object v0, p0, Llo/e0;->d:Llo/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lno/c0;->m(Lcom/google/android/gms/common/api/Status;)Lko/e;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iget-object p0, p0, Llo/e0;->c:Laq/k;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final b(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, Llo/e0;->c:Laq/k;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Llo/s;)V
    .locals 2

    .line 1
    iget-object v0, p0, Llo/e0;->c:Laq/k;

    .line 2
    .line 3
    :try_start_0
    iget-object v1, p0, Llo/e0;->b:Lhr/b0;

    .line 4
    .line 5
    iget-object p1, p1, Llo/s;->d:Lko/c;

    .line 6
    .line 7
    invoke-virtual {v1, p1, v0}, Lhr/b0;->f(Lko/c;Laq/k;)V
    :try_end_0
    .catch Landroid/os/DeadObjectException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :catch_0
    move-exception p0

    .line 12
    goto :goto_0

    .line 13
    :catch_1
    move-exception p1

    .line 14
    goto :goto_1

    .line 15
    :goto_0
    invoke-virtual {v0, p0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :goto_1
    invoke-static {p1}, Llo/f0;->e(Landroid/os/RemoteException;)Lcom/google/android/gms/common/api/Status;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Llo/e0;->a(Lcom/google/android/gms/common/api/Status;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :catch_2
    move-exception p0

    .line 28
    throw p0
.end method

.method public final d(Lvp/y1;Z)V
    .locals 3

    .line 1
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-object v0, p1, Lvp/y1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Ljava/util/Map;

    .line 8
    .line 9
    iget-object p0, p0, Llo/e0;->c:Laq/k;

    .line 10
    .line 11
    invoke-interface {v0, p0, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    iget-object p2, p0, Laq/k;->a:Laq/t;

    .line 15
    .line 16
    new-instance v0, Lc2/k;

    .line 17
    .line 18
    const/16 v1, 0xf

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-direct {v0, p1, p0, v2, v1}, Lc2/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2, v0}, Laq/t;->k(Laq/e;)Laq/t;

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final f(Llo/s;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Llo/e0;->b:Lhr/b0;

    .line 2
    .line 3
    iget-boolean p0, p0, Lhr/b0;->d:Z

    .line 4
    .line 5
    return p0
.end method

.method public final g(Llo/s;)[Ljo/d;
    .locals 0

    .line 1
    iget-object p0, p0, Llo/e0;->b:Lhr/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lhr/b0;->f:[Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, [Ljo/d;

    .line 6
    .line 7
    return-object p0
.end method
