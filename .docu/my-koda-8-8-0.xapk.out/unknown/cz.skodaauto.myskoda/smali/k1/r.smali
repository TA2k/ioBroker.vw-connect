.class public abstract Lk1/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/s;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lk1/s;

    .line 2
    .line 3
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 4
    .line 5
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Lk1/s;-><init>(Lk1/i;Lx2/d;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lk1/r;->a:Lk1/s;

    .line 11
    .line 12
    return-void
.end method

.method public static final a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;
    .locals 5

    .line 1
    sget-object v0, Lk1/j;->c:Lk1/e;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    check-cast p2, Ll2/t;

    .line 19
    .line 20
    const p0, -0x5638e738

    .line 21
    .line 22
    .line 23
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Lk1/r;->a:Lk1/s;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    check-cast p2, Ll2/t;

    .line 33
    .line 34
    const v0, -0x563814e1

    .line 35
    .line 36
    .line 37
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 38
    .line 39
    .line 40
    and-int/lit8 v0, p3, 0xe

    .line 41
    .line 42
    xor-int/lit8 v0, v0, 0x6

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    const/4 v3, 0x4

    .line 46
    if-le v0, v3, :cond_1

    .line 47
    .line 48
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-nez v0, :cond_2

    .line 53
    .line 54
    :cond_1
    and-int/lit8 v0, p3, 0x6

    .line 55
    .line 56
    if-ne v0, v3, :cond_3

    .line 57
    .line 58
    :cond_2
    move v0, v2

    .line 59
    goto :goto_0

    .line 60
    :cond_3
    move v0, v1

    .line 61
    :goto_0
    and-int/lit8 v3, p3, 0x70

    .line 62
    .line 63
    xor-int/lit8 v3, v3, 0x30

    .line 64
    .line 65
    const/16 v4, 0x20

    .line 66
    .line 67
    if-le v3, v4, :cond_4

    .line 68
    .line 69
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    if-nez v3, :cond_6

    .line 74
    .line 75
    :cond_4
    and-int/lit8 p3, p3, 0x30

    .line 76
    .line 77
    if-ne p3, v4, :cond_5

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_5
    move v2, v1

    .line 81
    :cond_6
    :goto_1
    or-int p3, v0, v2

    .line 82
    .line 83
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    if-nez p3, :cond_7

    .line 88
    .line 89
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 90
    .line 91
    if-ne v0, p3, :cond_8

    .line 92
    .line 93
    :cond_7
    new-instance v0, Lk1/s;

    .line 94
    .line 95
    invoke-direct {v0, p0, p1}, Lk1/s;-><init>(Lk1/i;Lx2/d;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    :cond_8
    check-cast v0, Lk1/s;

    .line 102
    .line 103
    invoke-virtual {p2, v1}, Ll2/t;->q(Z)V

    .line 104
    .line 105
    .line 106
    return-object v0
.end method
