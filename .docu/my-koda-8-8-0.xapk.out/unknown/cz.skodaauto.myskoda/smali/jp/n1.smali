.class public abstract Ljp/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/k;)Lzv0/c;
    .locals 5

    .line 1
    new-instance v0, Lzv0/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lzv0/e;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    iget-object p0, v0, Lzv0/e;->d:Lay0/k;

    .line 10
    .line 11
    const-string v1, "block"

    .line 12
    .line 13
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Ldw0/d;

    .line 17
    .line 18
    new-instance v2, Ldw0/a;

    .line 19
    .line 20
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    new-instance v3, Ldj/a;

    .line 24
    .line 25
    const/16 v4, 0x9

    .line 26
    .line 27
    invoke-direct {v3, v4}, Ldj/a;-><init>(I)V

    .line 28
    .line 29
    .line 30
    iput-object v3, v2, Ldw0/a;->a:Ldj/a;

    .line 31
    .line 32
    invoke-interface {p0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    invoke-direct {v1, v2}, Ldw0/d;-><init>(Ldw0/a;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Lzv0/c;

    .line 39
    .line 40
    const/4 v2, 0x1

    .line 41
    invoke-direct {p0, v1, v0, v2}, Lzv0/c;-><init>(Lcw0/c;Lzv0/e;Z)V

    .line 42
    .line 43
    .line 44
    iget-object v0, p0, Lzv0/c;->h:Lpx0/g;

    .line 45
    .line 46
    sget-object v2, Lvy0/h1;->d:Lvy0/h1;

    .line 47
    .line 48
    invoke-interface {v0, v2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    check-cast v0, Lvy0/i1;

    .line 56
    .line 57
    new-instance v2, Lyp0/d;

    .line 58
    .line 59
    const/16 v3, 0xd

    .line 60
    .line 61
    invoke-direct {v2, v1, v3}, Lyp0/d;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    invoke-interface {v0, v2}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 65
    .line 66
    .line 67
    return-object p0
.end method

.method public static final b(Lmz/e;)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    if-eq p0, v1, :cond_1

    .line 17
    .line 18
    const/4 v1, 0x3

    .line 19
    if-eq p0, v1, :cond_1

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    if-eq p0, v0, :cond_2

    .line 23
    .line 24
    const/4 v0, 0x5

    .line 25
    if-ne p0, v0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, La8/r0;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    return v0

    .line 35
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public static final c(Lmz/e;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x1

    .line 6
    if-eqz p0, :cond_2

    .line 7
    .line 8
    if-eq p0, v0, :cond_2

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    if-eq p0, v1, :cond_2

    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    if-eq p0, v1, :cond_2

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    if-eq p0, v0, :cond_1

    .line 18
    .line 19
    const/4 v0, 0x5

    .line 20
    if-ne p0, v0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 30
    return p0

    .line 31
    :cond_2
    return v0
.end method
