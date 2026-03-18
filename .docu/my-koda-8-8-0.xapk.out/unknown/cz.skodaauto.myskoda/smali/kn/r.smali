.class public final Lkn/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:Lkotlin/jvm/internal/n;

.field public final synthetic b:Lx2/d;

.field public final synthetic c:Lkn/m0;


# direct methods
.method public constructor <init>(Lay0/k;Lx2/d;Lkn/m0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    check-cast p1, Lkotlin/jvm/internal/n;

    .line 5
    .line 6
    iput-object p1, p0, Lkn/r;->a:Lkotlin/jvm/internal/n;

    .line 7
    .line 8
    iput-object p2, p0, Lkn/r;->b:Lx2/d;

    .line 9
    .line 10
    iput-object p3, p0, Lkn/r;->c:Lkn/m0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 10

    .line 1
    const-string v0, "$this$Layout"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "measurables"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    check-cast p2, Lt3/p0;

    .line 17
    .line 18
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 19
    .line 20
    .line 21
    move-result-object v9

    .line 22
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    invoke-virtual {v9}, Lt3/e1;->d0()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    invoke-virtual {v9}, Lt3/e1;->b0()I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    new-instance v0, Lkn/q;

    .line 51
    .line 52
    iget-object v6, p0, Lkn/r;->b:Lx2/d;

    .line 53
    .line 54
    iget-object v8, p0, Lkn/r;->c:Lkn/m0;

    .line 55
    .line 56
    iget-object v1, p0, Lkn/r;->a:Lkotlin/jvm/internal/n;

    .line 57
    .line 58
    move-object v7, p1

    .line 59
    move-wide v4, p3

    .line 60
    invoke-direct/range {v0 .. v9}, Lkn/q;-><init>(Lay0/k;IIJLx2/d;Lt3/s0;Lkn/m0;Lt3/e1;)V

    .line 61
    .line 62
    .line 63
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 64
    .line 65
    invoke-interface {v7, v2, p2, p0, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method
