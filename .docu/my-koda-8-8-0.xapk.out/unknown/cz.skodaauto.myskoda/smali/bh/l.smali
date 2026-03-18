.class public final synthetic Lbh/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lbh/l;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lbh/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lbh/l;->a:Lbh/l;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.onboarding.ChargingStationSupportedConfigurationResponse"

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "configurations"

    .line 17
    .line 18
    invoke-virtual {v1, v0, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Lbh/l;->descriptor:Lsz0/g;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    sget-object p0, Lbh/n;->b:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget-object p0, p0, v1

    .line 8
    .line 9
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    aput-object p0, v0, v1

    .line 14
    .line 15
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object p0, Lbh/l;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lbh/n;->b:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v4, v1

    .line 13
    move v5, v2

    .line 14
    :goto_0
    if-eqz v4, :cond_2

    .line 15
    .line 16
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 17
    .line 18
    .line 19
    move-result v6

    .line 20
    const/4 v7, -0x1

    .line 21
    if-eq v6, v7, :cond_1

    .line 22
    .line 23
    if-nez v6, :cond_0

    .line 24
    .line 25
    aget-object v5, v0, v2

    .line 26
    .line 27
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    check-cast v5, Lqz0/a;

    .line 32
    .line 33
    invoke-interface {p1, p0, v2, v5, v3}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    check-cast v3, Ljava/util/List;

    .line 38
    .line 39
    move v5, v1

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Lqz0/k;

    .line 42
    .line 43
    invoke-direct {p0, v6}, Lqz0/k;-><init>(I)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    move v4, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_2
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 50
    .line 51
    .line 52
    new-instance p0, Lbh/n;

    .line 53
    .line 54
    invoke-direct {p0, v5, v3}, Lbh/n;-><init>(ILjava/util/List;)V

    .line 55
    .line 56
    .line 57
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lbh/l;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Lbh/n;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lbh/n;->a:Ljava/util/List;

    .line 9
    .line 10
    sget-object p2, Lbh/l;->descriptor:Lsz0/g;

    .line 11
    .line 12
    invoke-interface {p1, p2}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v0, Lbh/n;->b:[Llx0/i;

    .line 17
    .line 18
    invoke-interface {p1, p2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 26
    .line 27
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    :goto_0
    const/4 v1, 0x0

    .line 34
    aget-object v0, v0, v1

    .line 35
    .line 36
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Lqz0/a;

    .line 41
    .line 42
    invoke-interface {p1, p2, v1, v0, p0}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    invoke-interface {p1, p2}, Ltz0/b;->b(Lsz0/g;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method
