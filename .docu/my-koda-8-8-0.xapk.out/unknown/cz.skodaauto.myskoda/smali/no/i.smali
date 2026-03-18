.class public abstract Lno/i;
.super Lno/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/c;


# instance fields
.field public final y:Ljava/util/Set;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V
    .locals 9

    .line 1
    invoke-static {p1}, Lno/n0;->a(Landroid/content/Context;)Lno/n0;

    .line 2
    .line 3
    .line 4
    move-result-object v3

    .line 5
    sget-object v4, Ljo/e;->d:Ljo/e;

    .line 6
    .line 7
    invoke-static {p5}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    new-instance v6, Lno/n;

    .line 14
    .line 15
    invoke-direct {v6, p5}, Lno/n;-><init>(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    new-instance v7, Lno/n;

    .line 19
    .line 20
    invoke-direct {v7, p6}, Lno/n;-><init>(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget-object p5, p4, Lin/z1;->d:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v8, p5

    .line 26
    check-cast v8, Ljava/lang/String;

    .line 27
    .line 28
    move-object v0, p0

    .line 29
    move-object v1, p1

    .line 30
    move-object v2, p2

    .line 31
    move v5, p3

    .line 32
    invoke-direct/range {v0 .. v8}, Lno/e;-><init>(Landroid/content/Context;Landroid/os/Looper;Lno/n0;Ljo/f;ILno/b;Lno/c;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p4, Lin/z1;->b:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Ljava/util/Set;

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result p3

    .line 47
    if-eqz p3, :cond_1

    .line 48
    .line 49
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p3

    .line 53
    check-cast p3, Lcom/google/android/gms/common/api/Scope;

    .line 54
    .line 55
    invoke-interface {p1, p3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p3

    .line 59
    if-eqz p3, :cond_0

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string p1, "Expanding scopes is not permitted, use implied scopes instead"

    .line 65
    .line 66
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_1
    iput-object p1, p0, Lno/i;->y:Ljava/util/Set;

    .line 71
    .line 72
    return-void
.end method


# virtual methods
.method public final i()Ljava/util/Set;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lno/e;->h()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lno/i;->y:Ljava/util/Set;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 11
    .line 12
    return-object p0
.end method

.method public final n()Landroid/accounts/Account;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final q()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/i;->y:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method
