.class public final Lis0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lks0/c;


# virtual methods
.method public final a(Lne0/t;)Lne0/t;
    .locals 6

    .line 1
    const-string p0, "event"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of p0, p1, Lne0/e;

    .line 7
    .line 8
    if-eqz p0, :cond_1

    .line 9
    .line 10
    :try_start_0
    new-instance p0, Lis0/e;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-direct {p0, v0}, Lis0/e;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1, p0}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 17
    .line 18
    .line 19
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    goto :goto_0

    .line 21
    :catchall_0
    move-exception v0

    .line 22
    move-object p0, v0

    .line 23
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :goto_0
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    if-nez v1, :cond_0

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_0
    new-instance v0, Lne0/c;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    const/16 v5, 0x1e

    .line 38
    .line 39
    const/4 v2, 0x0

    .line 40
    const/4 v3, 0x0

    .line 41
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 42
    .line 43
    .line 44
    move-object p0, v0

    .line 45
    :goto_1
    check-cast p0, Lne0/t;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    instance-of p0, p1, Lne0/c;

    .line 49
    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    new-instance v0, Lne0/c;

    .line 53
    .line 54
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string p0, "Unable to parse AsyncMessage because of error while observing AsyncMessage."

    .line 57
    .line 58
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    move-object v2, p1

    .line 62
    check-cast v2, Lne0/c;

    .line 63
    .line 64
    const/4 v4, 0x0

    .line 65
    const/16 v5, 0x1c

    .line 66
    .line 67
    const/4 v3, 0x0

    .line 68
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 69
    .line 70
    .line 71
    return-object v0

    .line 72
    :cond_2
    new-instance p0, La8/r0;

    .line 73
    .line 74
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 75
    .line 76
    .line 77
    throw p0
.end method
