.class public final synthetic Lwb/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lwb/i;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lwb/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lwb/i;->a:Lwb/i;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.common.api.chargingcard.models.ChargingCardResponse"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "subscriptionId"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "chargingCards"

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "hasWallbox"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Lwb/i;->descriptor:Lsz0/g;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lwb/k;->g:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 7
    .line 8
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x0

    .line 13
    aput-object v1, v0, v2

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    aget-object p0, p0, v1

    .line 17
    .line 18
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    aput-object p0, v0, v1

    .line 23
    .line 24
    const/4 p0, 0x2

    .line 25
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 26
    .line 27
    aput-object v1, v0, p0

    .line 28
    .line 29
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object p0, Lwb/i;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lwb/k;->g:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v5, v1

    .line 13
    move v6, v2

    .line 14
    move v7, v6

    .line 15
    move-object v4, v3

    .line 16
    :goto_0
    if-eqz v5, :cond_4

    .line 17
    .line 18
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 19
    .line 20
    .line 21
    move-result v8

    .line 22
    const/4 v9, -0x1

    .line 23
    if-eq v8, v9, :cond_3

    .line 24
    .line 25
    if-eqz v8, :cond_2

    .line 26
    .line 27
    if-eq v8, v1, :cond_1

    .line 28
    .line 29
    const/4 v7, 0x2

    .line 30
    if-ne v8, v7, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0, v7}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 33
    .line 34
    .line 35
    move-result v7

    .line 36
    or-int/lit8 v6, v6, 0x4

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    new-instance p0, Lqz0/k;

    .line 40
    .line 41
    invoke-direct {p0, v8}, Lqz0/k;-><init>(I)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_1
    aget-object v8, v0, v1

    .line 46
    .line 47
    invoke-interface {v8}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v8

    .line 51
    check-cast v8, Lqz0/a;

    .line 52
    .line 53
    invoke-interface {p1, p0, v1, v8, v4}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    check-cast v4, Ljava/util/List;

    .line 58
    .line 59
    or-int/lit8 v6, v6, 0x2

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    sget-object v8, Luz0/q1;->a:Luz0/q1;

    .line 63
    .line 64
    invoke-interface {p1, p0, v2, v8, v3}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    check-cast v3, Ljava/lang/String;

    .line 69
    .line 70
    or-int/lit8 v6, v6, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    move v5, v2

    .line 74
    goto :goto_0

    .line 75
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 76
    .line 77
    .line 78
    new-instance p0, Lwb/k;

    .line 79
    .line 80
    invoke-direct {p0, v6, v3, v4, v7}, Lwb/k;-><init>(ILjava/lang/String;Ljava/util/List;Z)V

    .line 81
    .line 82
    .line 83
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lwb/i;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lwb/k;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lwb/k;->d:Ljava/lang/String;

    .line 9
    .line 10
    sget-object v0, Lwb/i;->descriptor:Lsz0/g;

    .line 11
    .line 12
    invoke-interface {p1, v0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v1, Lwb/k;->g:[Llx0/i;

    .line 17
    .line 18
    invoke-interface {p1, v0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    if-eqz p0, :cond_1

    .line 26
    .line 27
    :goto_0
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-interface {p1, v0, v3, v2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    const/4 p0, 0x1

    .line 34
    aget-object v1, v1, p0

    .line 35
    .line 36
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Lqz0/a;

    .line 41
    .line 42
    iget-object v2, p2, Lwb/k;->e:Ljava/util/List;

    .line 43
    .line 44
    invoke-interface {p1, v0, p0, v1, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    const/4 p0, 0x2

    .line 48
    iget-boolean p2, p2, Lwb/k;->f:Z

    .line 49
    .line 50
    invoke-interface {p1, v0, p0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p1, v0}, Ltz0/b;->b(Lsz0/g;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method
