.class public abstract Ljp/va;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lu01/y;Lu01/k;Ljava/lang/String;Lcm/f;I)Lbm/p;
    .locals 2

    .line 1
    and-int/lit8 v0, p4, 0x4

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p2, v1

    .line 7
    :cond_0
    and-int/lit8 p4, p4, 0x8

    .line 8
    .line 9
    if-eqz p4, :cond_1

    .line 10
    .line 11
    move-object p3, v1

    .line 12
    :cond_1
    new-instance p4, Lbm/p;

    .line 13
    .line 14
    invoke-direct {p4, p0, p1, p2, p3}, Lbm/p;-><init>(Lu01/y;Lu01/k;Ljava/lang/String;Ljava/lang/AutoCloseable;)V

    .line 15
    .line 16
    .line 17
    return-object p4
.end method

.method public static final b(Lij0/a;Lmq0/b;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p1, :cond_2

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-eq p1, v1, :cond_1

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-ne p1, v1, :cond_0

    .line 13
    .line 14
    new-array p1, v0, [Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ljj0/f;

    .line 17
    .line 18
    const v0, 0x7f12121f

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, v0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    new-instance p0, La8/r0;

    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    new-array p1, v0, [Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Ljj0/f;

    .line 35
    .line 36
    const v0, 0x7f121221

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, v0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_2
    new-array p1, v0, [Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Ljj0/f;

    .line 47
    .line 48
    const v0, 0x7f121222

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v0, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method
