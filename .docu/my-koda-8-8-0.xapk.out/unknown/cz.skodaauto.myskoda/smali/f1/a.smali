.class public final Lf1/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# static fields
.field public static final d:Lf1/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lf1/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lf1/a;->d:Lf1/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Lf1/c;

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
    move-result p0

    .line 11
    and-int/lit8 p3, p0, 0x6

    .line 12
    .line 13
    if-nez p3, :cond_1

    .line 14
    .line 15
    move-object p3, p2

    .line 16
    check-cast p3, Ll2/t;

    .line 17
    .line 18
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p3

    .line 22
    if-eqz p3, :cond_0

    .line 23
    .line 24
    const/4 p3, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p3, 0x2

    .line 27
    :goto_0
    or-int/2addr p0, p3

    .line 28
    :cond_1
    and-int/lit8 p3, p0, 0x13

    .line 29
    .line 30
    const/16 v0, 0x12

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    const/4 v2, 0x1

    .line 34
    if-eq p3, v0, :cond_2

    .line 35
    .line 36
    move p3, v2

    .line 37
    goto :goto_1

    .line 38
    :cond_2
    move p3, v1

    .line 39
    :goto_1
    and-int/2addr p0, v2

    .line 40
    check-cast p2, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {p2, p0, p3}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_3

    .line 47
    .line 48
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 49
    .line 50
    sget p3, Lf1/f;->l:F

    .line 51
    .line 52
    const/4 v0, 0x0

    .line 53
    invoke-static {p0, v0, p3, v2}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    const/high16 p3, 0x3f800000    # 1.0f

    .line 58
    .line 59
    invoke-static {p0, p3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    sget p3, Lf1/f;->k:F

    .line 64
    .line 65
    invoke-static {p0, p3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    iget-wide v2, p1, Lf1/c;->c:J

    .line 70
    .line 71
    sget-object p1, Le3/j0;->a:Le3/i0;

    .line 72
    .line 73
    invoke-static {p0, v2, v3, p1}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-static {p0, p2, v1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object p0
.end method
