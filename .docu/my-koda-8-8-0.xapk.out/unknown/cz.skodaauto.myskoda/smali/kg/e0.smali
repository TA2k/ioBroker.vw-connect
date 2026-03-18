.class public final synthetic Lkg/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lkg/e0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lkg/e0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/e0;->a:Lkg/e0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.SubscriptionUpgradeInitResponse"

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "tariffs"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "documents"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "paymentOption"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "formattedFollowUpStartDate"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Lkg/e0;->descriptor:Lsz0/g;

    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lkg/g0;->e:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget-object v2, p0, v1

    .line 8
    .line 9
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    aput-object v2, v0, v1

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
    sget-object v1, Lnc/x;->a:Lnc/x;

    .line 26
    .line 27
    aput-object v1, v0, p0

    .line 28
    .line 29
    const/4 p0, 0x3

    .line 30
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 31
    .line 32
    aput-object v1, v0, p0

    .line 33
    .line 34
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object p0, Lkg/e0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lkg/g0;->e:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v5, v2

    .line 13
    move-object v6, v3

    .line 14
    move-object v7, v6

    .line 15
    move-object v8, v7

    .line 16
    move-object v9, v8

    .line 17
    move v3, v1

    .line 18
    :goto_0
    if-eqz v3, :cond_5

    .line 19
    .line 20
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    const/4 v10, -0x1

    .line 25
    if-eq v4, v10, :cond_4

    .line 26
    .line 27
    if-eqz v4, :cond_3

    .line 28
    .line 29
    if-eq v4, v1, :cond_2

    .line 30
    .line 31
    const/4 v10, 0x2

    .line 32
    if-eq v4, v10, :cond_1

    .line 33
    .line 34
    const/4 v9, 0x3

    .line 35
    if-ne v4, v9, :cond_0

    .line 36
    .line 37
    invoke-interface {p1, p0, v9}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v9

    .line 41
    or-int/lit8 v5, v5, 0x8

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    new-instance p0, Lqz0/k;

    .line 45
    .line 46
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_1
    sget-object v4, Lnc/x;->a:Lnc/x;

    .line 51
    .line 52
    invoke-interface {p1, p0, v10, v4, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    move-object v8, v4

    .line 57
    check-cast v8, Lnc/z;

    .line 58
    .line 59
    or-int/lit8 v5, v5, 0x4

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    aget-object v4, v0, v1

    .line 63
    .line 64
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    check-cast v4, Lqz0/a;

    .line 69
    .line 70
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    move-object v7, v4

    .line 75
    check-cast v7, Ljava/util/List;

    .line 76
    .line 77
    or-int/lit8 v5, v5, 0x2

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    aget-object v4, v0, v2

    .line 81
    .line 82
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    check-cast v4, Lqz0/a;

    .line 87
    .line 88
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    move-object v6, v4

    .line 93
    check-cast v6, Ljava/util/List;

    .line 94
    .line 95
    or-int/lit8 v5, v5, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_4
    move v3, v2

    .line 99
    goto :goto_0

    .line 100
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 101
    .line 102
    .line 103
    new-instance v4, Lkg/g0;

    .line 104
    .line 105
    invoke-direct/range {v4 .. v9}, Lkg/g0;-><init>(ILjava/util/List;Ljava/util/List;Lnc/z;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lkg/e0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lkg/g0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lkg/e0;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lkg/g0;->e:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v2, v0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lqz0/a;

    .line 24
    .line 25
    iget-object v3, p2, Lkg/g0;->a:Ljava/util/List;

    .line 26
    .line 27
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    aget-object v0, v0, v1

    .line 32
    .line 33
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Lqz0/a;

    .line 38
    .line 39
    iget-object v2, p2, Lkg/g0;->b:Ljava/util/List;

    .line 40
    .line 41
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    sget-object v0, Lnc/x;->a:Lnc/x;

    .line 45
    .line 46
    iget-object v1, p2, Lkg/g0;->c:Lnc/z;

    .line 47
    .line 48
    const/4 v2, 0x2

    .line 49
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    const/4 v0, 0x3

    .line 53
    iget-object p2, p2, Lkg/g0;->d:Ljava/lang/String;

    .line 54
    .line 55
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 59
    .line 60
    .line 61
    return-void
.end method
