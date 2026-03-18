.class public final synthetic Lae/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lae/j;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lae/j;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lae/j;->a:Lae/j;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.cpoi.models.ChargingPoint"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "evseId"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "availabilityStatus"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "availabilityInformation"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "isAuthorizationEnabled"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "connectorDetails"

    .line 38
    .line 39
    const/4 v2, 0x1

    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    sput-object v1, Lae/j;->descriptor:Lsz0/g;

    .line 44
    .line 45
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lae/n;->f:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    aput-object v1, v0, v2

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    aget-object p0, p0, v2

    .line 13
    .line 14
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    aput-object p0, v0, v2

    .line 19
    .line 20
    const/4 p0, 0x2

    .line 21
    aput-object v1, v0, p0

    .line 22
    .line 23
    const/4 p0, 0x3

    .line 24
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 25
    .line 26
    aput-object v1, v0, p0

    .line 27
    .line 28
    sget-object p0, Lzi/e;->a:Lzi/e;

    .line 29
    .line 30
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const/4 v1, 0x4

    .line 35
    aput-object p0, v0, v1

    .line 36
    .line 37
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Lae/j;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lae/n;->f:[Llx0/i;

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
    move v9, v5

    .line 14
    move-object v6, v3

    .line 15
    move-object v7, v6

    .line 16
    move-object v8, v7

    .line 17
    move-object v10, v8

    .line 18
    move v3, v1

    .line 19
    :goto_0
    if-eqz v3, :cond_6

    .line 20
    .line 21
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    const/4 v11, -0x1

    .line 26
    if-eq v4, v11, :cond_5

    .line 27
    .line 28
    if-eqz v4, :cond_4

    .line 29
    .line 30
    if-eq v4, v1, :cond_3

    .line 31
    .line 32
    const/4 v11, 0x2

    .line 33
    if-eq v4, v11, :cond_2

    .line 34
    .line 35
    const/4 v11, 0x3

    .line 36
    if-eq v4, v11, :cond_1

    .line 37
    .line 38
    const/4 v11, 0x4

    .line 39
    if-ne v4, v11, :cond_0

    .line 40
    .line 41
    sget-object v4, Lzi/e;->a:Lzi/e;

    .line 42
    .line 43
    invoke-interface {p1, p0, v11, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    move-object v10, v4

    .line 48
    check-cast v10, Lzi/g;

    .line 49
    .line 50
    or-int/lit8 v5, v5, 0x10

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    new-instance p0, Lqz0/k;

    .line 54
    .line 55
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_1
    invoke-interface {p1, p0, v11}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 60
    .line 61
    .line 62
    move-result v9

    .line 63
    or-int/lit8 v5, v5, 0x8

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    invoke-interface {p1, p0, v11}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    or-int/lit8 v5, v5, 0x4

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    aget-object v4, v0, v1

    .line 74
    .line 75
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    check-cast v4, Lqz0/a;

    .line 80
    .line 81
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    move-object v7, v4

    .line 86
    check-cast v7, Lae/l;

    .line 87
    .line 88
    or-int/lit8 v5, v5, 0x2

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_4
    invoke-interface {p1, p0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v6

    .line 95
    or-int/lit8 v5, v5, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_5
    move v3, v2

    .line 99
    goto :goto_0

    .line 100
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 101
    .line 102
    .line 103
    new-instance v4, Lae/n;

    .line 104
    .line 105
    invoke-direct/range {v4 .. v10}, Lae/n;-><init>(ILjava/lang/String;Lae/l;Ljava/lang/String;ZLzi/g;)V

    .line 106
    .line 107
    .line 108
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lae/j;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lae/n;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lae/j;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lae/n;->f:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lae/n;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lae/n;->e:Lzi/g;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-interface {p1, p0, v3, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    aget-object v0, v0, v1

    .line 26
    .line 27
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lqz0/a;

    .line 32
    .line 33
    iget-object v3, p2, Lae/n;->b:Lae/l;

    .line 34
    .line 35
    invoke-interface {p1, p0, v1, v0, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    const/4 v0, 0x2

    .line 39
    iget-object v1, p2, Lae/n;->c:Ljava/lang/String;

    .line 40
    .line 41
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const/4 v0, 0x3

    .line 45
    iget-boolean p2, p2, Lae/n;->d:Z

    .line 46
    .line 47
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 48
    .line 49
    .line 50
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    if-eqz p2, :cond_0

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_0
    if-eqz v2, :cond_1

    .line 58
    .line 59
    :goto_0
    sget-object p2, Lzi/e;->a:Lzi/e;

    .line 60
    .line 61
    const/4 v0, 0x4

    .line 62
    invoke-interface {p1, p0, v0, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method
