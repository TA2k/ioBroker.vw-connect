.class public final Lmz0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lmz0/k;

.field public static final b:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lmz0/k;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lmz0/k;->a:Lmz0/k;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lmz0/b;

    .line 11
    .line 12
    const/4 v2, 0x3

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
    sput-object v0, Lmz0/k;->b:Ljava/lang/Object;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Lmz0/k;->getDescriptor()Lsz0/g;

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
    const-wide/16 v2, 0x0

    .line 11
    .line 12
    move v4, v1

    .line 13
    :goto_0
    sget-object v5, Lmz0/k;->a:Lmz0/k;

    .line 14
    .line 15
    invoke-virtual {v5}, Lmz0/k;->getDescriptor()Lsz0/g;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    invoke-interface {p1, v6}, Ltz0/a;->E(Lsz0/g;)I

    .line 20
    .line 21
    .line 22
    move-result v6

    .line 23
    const/4 v7, -0x1

    .line 24
    if-eq v6, v7, :cond_1

    .line 25
    .line 26
    if-nez v6, :cond_0

    .line 27
    .line 28
    invoke-virtual {v5}, Lmz0/k;->getDescriptor()Lsz0/g;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-interface {p1, v2, v1}, Ltz0/a;->A(Lsz0/g;I)J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    const/4 v4, 0x1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-static {v6}, Ljp/o1;->d(I)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    throw p0

    .line 43
    :cond_1
    invoke-interface {p1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 44
    .line 45
    .line 46
    if-eqz v4, :cond_2

    .line 47
    .line 48
    new-instance p0, Lgz0/j;

    .line 49
    .line 50
    invoke-direct {p0, v2, v3}, Lgz0/j;-><init>(J)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_2
    new-instance p1, Lqz0/b;

    .line 55
    .line 56
    invoke-virtual {p0}, Lmz0/k;->getDescriptor()Lsz0/g;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const-string v0, "nanoseconds"

    .line 65
    .line 66
    invoke-direct {p1, v0, p0}, Lqz0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lmz0/k;->b:Ljava/lang/Object;

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
    .locals 4

    .line 1
    check-cast p2, Lgz0/j;

    .line 2
    .line 3
    const-string v0, "value"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lmz0/k;->getDescriptor()Lsz0/g;

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
    sget-object v0, Lmz0/k;->a:Lmz0/k;

    .line 17
    .line 18
    invoke-virtual {v0}, Lmz0/k;->getDescriptor()Lsz0/g;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const/4 v1, 0x0

    .line 23
    iget-wide v2, p2, Lgz0/j;->b:J

    .line 24
    .line 25
    invoke-interface {p1, v0, v1, v2, v3}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
