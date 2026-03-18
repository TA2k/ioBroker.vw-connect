.class public final Lt1/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# static fields
.field public static final d:Lt1/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lt1/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lt1/a;->d:Lt1/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lx2/s;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    check-cast p2, Ll2/t;

    .line 11
    .line 12
    const p0, -0x7ec5e7f9

    .line 13
    .line 14
    .line 15
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 16
    .line 17
    .line 18
    sget-object p0, Le2/e1;->a:Ll2/e0;

    .line 19
    .line 20
    invoke-virtual {p2, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Le2/d1;

    .line 25
    .line 26
    iget-wide v0, p0, Le2/d1;->a:J

    .line 27
    .line 28
    invoke-virtual {p2, v0, v1}, Ll2/t;->f(J)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p3

    .line 36
    if-nez p0, :cond_0

    .line 37
    .line 38
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 39
    .line 40
    if-ne p3, p0, :cond_1

    .line 41
    .line 42
    :cond_0
    new-instance p3, Le81/e;

    .line 43
    .line 44
    const/16 p0, 0x9

    .line 45
    .line 46
    invoke-direct {p3, v0, v1, p0}, Le81/e;-><init>(JI)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    :cond_1
    check-cast p3, Lay0/k;

    .line 53
    .line 54
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 55
    .line 56
    invoke-static {p0, p3}, Landroidx/compose/ui/draw/a;->b(Lx2/s;Lay0/k;)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-interface {p1, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    const/4 p1, 0x0

    .line 65
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    return-object p0
.end method
