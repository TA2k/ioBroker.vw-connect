.class public final synthetic Ltb/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Ltb/p;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltb/p;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltb/p;->a:Ltb/p;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.bff.api.models.HeadlessConsentHeader"

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "status"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "count"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    sput-object v1, Ltb/p;->descriptor:Lsz0/g;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    sget-object p0, Ltb/t;->c:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x2

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
    const/4 p0, 0x1

    .line 16
    sget-object v1, Luz0/k0;->a:Luz0/k0;

    .line 17
    .line 18
    aput-object v1, v0, p0

    .line 19
    .line 20
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object p0, Ltb/p;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Ltb/t;->c:[Llx0/i;

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
    move v6, v5

    .line 15
    :goto_0
    if-eqz v4, :cond_3

    .line 16
    .line 17
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 18
    .line 19
    .line 20
    move-result v7

    .line 21
    const/4 v8, -0x1

    .line 22
    if-eq v7, v8, :cond_2

    .line 23
    .line 24
    if-eqz v7, :cond_1

    .line 25
    .line 26
    if-ne v7, v1, :cond_0

    .line 27
    .line 28
    invoke-interface {p1, p0, v1}, Ltz0/a;->l(Lsz0/g;I)I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    or-int/lit8 v5, v5, 0x2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    new-instance p0, Lqz0/k;

    .line 36
    .line 37
    invoke-direct {p0, v7}, Lqz0/k;-><init>(I)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    aget-object v7, v0, v2

    .line 42
    .line 43
    invoke-interface {v7}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    check-cast v7, Lqz0/a;

    .line 48
    .line 49
    invoke-interface {p1, p0, v2, v7, v3}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Ltb/s;

    .line 54
    .line 55
    or-int/lit8 v5, v5, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    move v4, v2

    .line 59
    goto :goto_0

    .line 60
    :cond_3
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 61
    .line 62
    .line 63
    new-instance p0, Ltb/t;

    .line 64
    .line 65
    invoke-direct {p0, v5, v3, v6}, Ltb/t;-><init>(ILtb/s;I)V

    .line 66
    .line 67
    .line 68
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Ltb/p;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Ltb/t;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Ltb/p;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Ltb/t;->c:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v0, v0, v1

    .line 18
    .line 19
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lqz0/a;

    .line 24
    .line 25
    iget-object v2, p2, Ltb/t;->a:Ltb/s;

    .line 26
    .line 27
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    iget p2, p2, Ltb/t;->b:I

    .line 32
    .line 33
    invoke-interface {p1, v0, p2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
