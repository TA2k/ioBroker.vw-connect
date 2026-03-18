.class public final Lpv/d;
.super Lnv/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lov/e;


# instance fields
.field public final i:Lov/f;


# direct methods
.method public constructor <init>(Lpv/a;Ljava/util/concurrent/Executor;Llp/lg;Lov/f;)V
    .locals 6

    .line 1
    invoke-direct {p0, p1, p2}, Lnv/b;-><init>(Leb/j0;Ljava/util/concurrent/Executor;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lpv/d;->i:Lov/f;

    .line 5
    .line 6
    new-instance p0, Lin/z1;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    check-cast p4, Lqv/a;

    .line 12
    .line 13
    invoke-virtual {p4}, Lqv/a;->a()Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    sget-object p1, Llp/sb;->f:Llp/sb;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    sget-object p1, Llp/sb;->e:Llp/sb;

    .line 23
    .line 24
    :goto_0
    iput-object p1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 25
    .line 26
    new-instance p1, Llp/f0;

    .line 27
    .line 28
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    new-instance p2, Lh6/e;

    .line 32
    .line 33
    const/16 p4, 0x12

    .line 34
    .line 35
    invoke-direct {p2, p4}, Lh6/e;-><init>(I)V

    .line 36
    .line 37
    .line 38
    sget-object p4, Llp/ve;->e:Llp/ve;

    .line 39
    .line 40
    iput-object p4, p2, Lh6/e;->e:Ljava/lang/Object;

    .line 41
    .line 42
    new-instance p4, Llp/we;

    .line 43
    .line 44
    invoke-direct {p4, p2}, Llp/we;-><init>(Lh6/e;)V

    .line 45
    .line 46
    .line 47
    iput-object p4, p1, Llp/f0;->f:Ljava/lang/Object;

    .line 48
    .line 49
    new-instance p2, Llp/ue;

    .line 50
    .line 51
    invoke-direct {p2, p1}, Llp/ue;-><init>(Llp/f0;)V

    .line 52
    .line 53
    .line 54
    iput-object p2, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 55
    .line 56
    new-instance v2, Lbb/g0;

    .line 57
    .line 58
    const/4 p1, 0x0

    .line 59
    const/4 p2, 0x1

    .line 60
    invoke-direct {v2, p0, p2, p1}, Lbb/g0;-><init>(Lin/z1;IB)V

    .line 61
    .line 62
    .line 63
    sget-object v3, Llp/ub;->k:Llp/ub;

    .line 64
    .line 65
    invoke-virtual {p3}, Llp/lg;->c()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    new-instance v0, Ld6/z0;

    .line 70
    .line 71
    const/4 v5, 0x3

    .line 72
    move-object v1, p3

    .line 73
    invoke-direct/range {v0 .. v5}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    sget-object p0, Lfv/l;->d:Lfv/l;

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method


# virtual methods
.method public final a()[Ljo/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lpv/d;->i:Lov/f;

    .line 2
    .line 3
    check-cast p0, Lqv/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lqv/a;->a()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lfv/h;->a:[Ljo/d;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    sget-object p0, Lfv/h;->c:Ljo/d;

    .line 15
    .line 16
    filled-new-array {p0}, [Ljo/d;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
