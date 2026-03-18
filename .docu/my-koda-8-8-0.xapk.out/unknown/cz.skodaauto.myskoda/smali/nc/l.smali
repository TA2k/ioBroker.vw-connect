.class public final synthetic Lnc/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lnc/l;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lnc/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnc/l;->a:Lnc/l;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.common.presentation.payment.models.PaymentAddOrReplaceInitRequest"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "code"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "address"

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "taxNumber"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Lnc/l;->descriptor:Lsz0/g;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 2
    .line 3
    sget-object v0, Lac/a;->a:Lac/a;

    .line 4
    .line 5
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const/4 v2, 0x3

    .line 14
    new-array v2, v2, [Lqz0/a;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    aput-object p0, v2, v3

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    aput-object v0, v2, p0

    .line 21
    .line 22
    const/4 p0, 0x2

    .line 23
    aput-object v1, v2, p0

    .line 24
    .line 25
    return-object v2
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object p0, Lnc/l;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v5, v0

    .line 11
    move v6, v1

    .line 12
    move-object v3, v2

    .line 13
    move-object v4, v3

    .line 14
    :goto_0
    if-eqz v5, :cond_4

    .line 15
    .line 16
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 17
    .line 18
    .line 19
    move-result v7

    .line 20
    const/4 v8, -0x1

    .line 21
    if-eq v7, v8, :cond_3

    .line 22
    .line 23
    if-eqz v7, :cond_2

    .line 24
    .line 25
    if-eq v7, v0, :cond_1

    .line 26
    .line 27
    const/4 v8, 0x2

    .line 28
    if-ne v7, v8, :cond_0

    .line 29
    .line 30
    sget-object v7, Luz0/q1;->a:Luz0/q1;

    .line 31
    .line 32
    invoke-interface {p1, p0, v8, v7, v4}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Ljava/lang/String;

    .line 37
    .line 38
    or-int/lit8 v6, v6, 0x4

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Lqz0/k;

    .line 42
    .line 43
    invoke-direct {p0, v7}, Lqz0/k;-><init>(I)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    sget-object v7, Lac/a;->a:Lac/a;

    .line 48
    .line 49
    invoke-interface {p1, p0, v0, v7, v3}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Lac/c;

    .line 54
    .line 55
    or-int/lit8 v6, v6, 0x2

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    or-int/lit8 v6, v6, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_3
    move v5, v1

    .line 66
    goto :goto_0

    .line 67
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 68
    .line 69
    .line 70
    new-instance p0, Lnc/n;

    .line 71
    .line 72
    invoke-direct {p0, v6, v2, v3, v4}, Lnc/n;-><init>(ILjava/lang/String;Lac/c;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lnc/l;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lnc/n;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lnc/l;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v0, p2, Lnc/n;->a:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v1, p2, Lnc/n;->c:Ljava/lang/String;

    .line 17
    .line 18
    iget-object p2, p2, Lnc/n;->b:Lac/c;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-interface {p1, p0, v2, v0}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    if-eqz p2, :cond_1

    .line 32
    .line 33
    :goto_0
    sget-object v0, Lac/a;->a:Lac/a;

    .line 34
    .line 35
    const/4 v2, 0x1

    .line 36
    invoke-interface {p1, p0, v2, v0, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    if-eqz p2, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    if-eqz v1, :cond_3

    .line 47
    .line 48
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 49
    .line 50
    const/4 v0, 0x2

    .line 51
    invoke-interface {p1, p0, v0, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 55
    .line 56
    .line 57
    return-void
.end method
