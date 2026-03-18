.class public final Lmz0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lmz0/j;

.field public static final b:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lmz0/j;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lmz0/j;->a:Lmz0/j;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lmz0/b;

    .line 11
    .line 12
    const/4 v2, 0x2

    .line 13
    invoke-direct {v1, v2}, Lmz0/b;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sput-object v0, Lmz0/j;->b:Ljava/lang/Object;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lmz0/j;->getDescriptor()Lsz0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {p1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const/4 v1, 0x0

    .line 10
    move v2, v1

    .line 11
    move v3, v2

    .line 12
    :goto_0
    sget-object v4, Lmz0/j;->a:Lmz0/j;

    .line 13
    .line 14
    invoke-virtual {v4}, Lmz0/j;->getDescriptor()Lsz0/g;

    .line 15
    .line 16
    .line 17
    move-result-object v5

    .line 18
    invoke-interface {p1, v5}, Ltz0/a;->E(Lsz0/g;)I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    const/4 v6, -0x1

    .line 23
    if-eq v5, v6, :cond_1

    .line 24
    .line 25
    if-nez v5, :cond_0

    .line 26
    .line 27
    invoke-virtual {v4}, Lmz0/j;->getDescriptor()Lsz0/g;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-interface {p1, v2, v1}, Ltz0/a;->l(Lsz0/g;I)I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    const/4 v2, 0x1

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-static {v5}, Ljp/o1;->d(I)V

    .line 38
    .line 39
    .line 40
    const/4 p0, 0x0

    .line 41
    throw p0

    .line 42
    :cond_1
    invoke-interface {p1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 43
    .line 44
    .line 45
    if-eqz v2, :cond_2

    .line 46
    .line 47
    new-instance p0, Lgz0/h;

    .line 48
    .line 49
    invoke-direct {p0, v3}, Lgz0/h;-><init>(I)V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_2
    new-instance p1, Lqz0/b;

    .line 54
    .line 55
    invoke-virtual {p0}, Lmz0/j;->getDescriptor()Lsz0/g;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string v0, "months"

    .line 64
    .line 65
    invoke-direct {p1, v0, p0}, Lqz0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lmz0/j;->b:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lsz0/g;

    .line 8
    .line 9
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Lgz0/h;

    .line 2
    .line 3
    const-string v0, "value"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lmz0/j;->getDescriptor()Lsz0/g;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    sget-object v0, Lmz0/j;->a:Lmz0/j;

    .line 17
    .line 18
    invoke-virtual {v0}, Lmz0/j;->getDescriptor()Lsz0/g;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const/4 v1, 0x0

    .line 23
    iget p2, p2, Lgz0/h;->b:I

    .line 24
    .line 25
    invoke-interface {p1, v1, p2, v0}, Ltz0/b;->n(IILsz0/g;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
