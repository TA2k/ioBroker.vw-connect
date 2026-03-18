.class public abstract Lha0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lha0/c;->a:F

    .line 5
    .line 6
    sput v0, Lha0/c;->b:F

    .line 7
    .line 8
    const/16 v0, 0x14

    .line 9
    .line 10
    int-to-float v0, v0

    .line 11
    sput v0, Lha0/c;->c:F

    .line 12
    .line 13
    return-void
.end method

.method public static final a(Lst0/n;Ll2/o;)J
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p0, :cond_2

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-eq p0, v1, :cond_1

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-ne p0, v1, :cond_0

    .line 13
    .line 14
    check-cast p1, Ll2/t;

    .line 15
    .line 16
    const p0, 0x5ce76005

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lj91/e;

    .line 29
    .line 30
    invoke-virtual {p0}, Lj91/e;->r()J

    .line 31
    .line 32
    .line 33
    move-result-wide v1

    .line 34
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 35
    .line 36
    .line 37
    return-wide v1

    .line 38
    :cond_0
    const p0, 0x5ce748ac

    .line 39
    .line 40
    .line 41
    check-cast p1, Ll2/t;

    .line 42
    .line 43
    invoke-static {p0, p1, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    throw p0

    .line 48
    :cond_1
    check-cast p1, Ll2/t;

    .line 49
    .line 50
    const p0, 0x5ce7585e

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 57
    .line 58
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lj91/e;

    .line 63
    .line 64
    invoke-virtual {p0}, Lj91/e;->u()J

    .line 65
    .line 66
    .line 67
    move-result-wide v1

    .line 68
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 69
    .line 70
    .line 71
    return-wide v1

    .line 72
    :cond_2
    check-cast p1, Ll2/t;

    .line 73
    .line 74
    const p0, 0x5ce75042

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 78
    .line 79
    .line 80
    sget-object p0, Lj91/h;->a:Ll2/u2;

    .line 81
    .line 82
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    check-cast p0, Lj91/e;

    .line 87
    .line 88
    invoke-virtual {p0}, Lj91/e;->q()J

    .line 89
    .line 90
    .line 91
    move-result-wide v1

    .line 92
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 93
    .line 94
    .line 95
    return-wide v1
.end method
