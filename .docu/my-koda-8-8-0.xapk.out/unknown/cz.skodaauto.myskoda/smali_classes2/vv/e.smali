.class public final Lvv/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final a:Lvv/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lvv/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvv/e;->a:Lvv/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 9

    .line 1
    const-string p0, "$this$Layout"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "measurables"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    invoke-interface {p2, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lt3/p0;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    check-cast p2, Lt3/p0;

    .line 24
    .line 25
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-interface {v0, v1}, Lt3/p0;->G(I)I

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    neg-int v1, v5

    .line 34
    const/4 v2, 0x2

    .line 35
    invoke-static {p3, p4, v1, p0, v2}, Lt4/b;->j(JIII)J

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    invoke-interface {p2, v1, v2}, Lt3/p0;->L(J)Lt3/e1;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    iget p2, p0, Lt3/e1;->d:I

    .line 44
    .line 45
    add-int/2addr p2, v5

    .line 46
    iget v6, p0, Lt3/e1;->e:I

    .line 47
    .line 48
    const/4 v4, 0x0

    .line 49
    const/4 v8, 0x1

    .line 50
    move v7, v6

    .line 51
    move-wide v2, p3

    .line 52
    invoke-static/range {v2 .. v8}, Lt4/a;->a(JIIIII)J

    .line 53
    .line 54
    .line 55
    move-result-wide p3

    .line 56
    invoke-interface {v0, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 57
    .line 58
    .line 59
    move-result-object p3

    .line 60
    new-instance p4, Lvv/d;

    .line 61
    .line 62
    invoke-direct {p4, p3, p0, v5}, Lvv/d;-><init>(Lt3/e1;Lt3/e1;I)V

    .line 63
    .line 64
    .line 65
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 66
    .line 67
    invoke-interface {p1, p2, v6, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method
