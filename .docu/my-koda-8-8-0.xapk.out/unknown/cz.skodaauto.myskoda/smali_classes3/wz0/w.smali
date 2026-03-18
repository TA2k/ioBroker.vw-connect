.class public final Lwz0/w;
.super Lwz0/s;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public i:Ljava/lang/String;

.field public j:Z


# virtual methods
.method public final J()Lvz0/n;
    .locals 1

    .line 1
    new-instance v0, Lvz0/a0;

    .line 2
    .line 3
    iget-object p0, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lvz0/a0;-><init>(Ljava/util/Map;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final M(Ljava/lang/String;Lvz0/n;)V
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "element"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-boolean p1, p0, Lwz0/w;->j:Z

    .line 12
    .line 13
    if-eqz p1, :cond_3

    .line 14
    .line 15
    instance-of p1, p2, Lvz0/e0;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    check-cast p2, Lvz0/e0;

    .line 20
    .line 21
    invoke-virtual {p2}, Lvz0/e0;->c()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lwz0/w;->i:Ljava/lang/String;

    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    iput-boolean p1, p0, Lwz0/w;->j:Z

    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    instance-of p0, p2, Lvz0/a0;

    .line 32
    .line 33
    if-nez p0, :cond_2

    .line 34
    .line 35
    instance-of p0, p2, Lvz0/f;

    .line 36
    .line 37
    if-eqz p0, :cond_1

    .line 38
    .line 39
    sget-object p0, Lvz0/h;->b:Lvz0/g;

    .line 40
    .line 41
    invoke-static {p0}, Lwz0/p;->b(Lsz0/g;)Lwz0/l;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    throw p0

    .line 46
    :cond_1
    new-instance p0, La8/r0;

    .line 47
    .line 48
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    sget-object p0, Lvz0/c0;->b:Lvz0/b0;

    .line 53
    .line 54
    invoke-static {p0}, Lwz0/p;->b(Lsz0/g;)Lwz0/l;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    throw p0

    .line 59
    :cond_3
    iget-object p1, p0, Lwz0/s;->h:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p1, Ljava/util/LinkedHashMap;

    .line 62
    .line 63
    iget-object v0, p0, Lwz0/w;->i:Ljava/lang/String;

    .line 64
    .line 65
    if-eqz v0, :cond_4

    .line 66
    .line 67
    invoke-interface {p1, v0, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    const/4 p1, 0x1

    .line 71
    iput-boolean p1, p0, Lwz0/w;->j:Z

    .line 72
    .line 73
    return-void

    .line 74
    :cond_4
    const-string p0, "tag"

    .line 75
    .line 76
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const/4 p0, 0x0

    .line 80
    throw p0
.end method
