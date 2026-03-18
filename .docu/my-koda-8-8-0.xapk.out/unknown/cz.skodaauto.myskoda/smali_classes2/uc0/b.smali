.class public final Luc0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxl0/g;


# virtual methods
.method public final a(Lcm0/b;)Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "environment"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_4

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    if-eq p0, p1, :cond_3

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    if-eq p0, p1, :cond_2

    .line 17
    .line 18
    const/4 p1, 0x3

    .line 19
    if-eq p0, p1, :cond_1

    .line 20
    .line 21
    const/4 p1, 0x4

    .line 22
    if-ne p0, p1, :cond_0

    .line 23
    .line 24
    const-string p0, "mock-myskoda-backend.skoq.cz"

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    const-string p0, "mocck.test-api.connect.skoda-auto.cz"

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_2
    const-string p0, "mysmob.test-api.connect.skoda-auto.cz"

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_3
    const-string p0, "mysmob.prelive-api.connect.skoda-auto.cz"

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_4
    const-string p0, "mysmob.api.connect.skoda-auto.cz"

    .line 43
    .line 44
    return-object p0
.end method

.method public final getSystemId()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "GW"

    .line 2
    .line 3
    return-object p0
.end method
