.class public final Lsk/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/lang/Object;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:F


# direct methods
.method public constructor <init>(FLjava/lang/String;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lsk/a;->d:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Lsk/a;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput p1, p0, Lsk/a;->f:F

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    check-cast p3, Ll2/o;

    .line 10
    .line 11
    check-cast p4, Ljava/lang/Number;

    .line 12
    .line 13
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    and-int/lit8 p4, p2, 0x6

    .line 18
    .line 19
    if-nez p4, :cond_1

    .line 20
    .line 21
    move-object p4, p3

    .line 22
    check-cast p4, Ll2/t;

    .line 23
    .line 24
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    const/4 p1, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p1, 0x2

    .line 33
    :goto_0
    or-int/2addr p1, p2

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move p1, p2

    .line 36
    :goto_1
    and-int/lit8 p2, p2, 0x30

    .line 37
    .line 38
    if-nez p2, :cond_3

    .line 39
    .line 40
    move-object p2, p3

    .line 41
    check-cast p2, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {p2, v1}, Ll2/t;->e(I)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-eqz p2, :cond_2

    .line 48
    .line 49
    const/16 p2, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 p2, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr p1, p2

    .line 55
    :cond_3
    and-int/lit16 p2, p1, 0x93

    .line 56
    .line 57
    const/16 p4, 0x92

    .line 58
    .line 59
    const/4 v6, 0x0

    .line 60
    if-eq p2, p4, :cond_4

    .line 61
    .line 62
    const/4 p2, 0x1

    .line 63
    goto :goto_3

    .line 64
    :cond_4
    move p2, v6

    .line 65
    :goto_3
    and-int/lit8 p4, p1, 0x1

    .line 66
    .line 67
    move-object v4, p3

    .line 68
    check-cast v4, Ll2/t;

    .line 69
    .line 70
    invoke-virtual {v4, p4, p2}, Ll2/t;->O(IZ)Z

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    if-eqz p2, :cond_5

    .line 75
    .line 76
    iget-object p2, p0, Lsk/a;->d:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    move-object v0, p2

    .line 83
    check-cast v0, Lug/d;

    .line 84
    .line 85
    const p2, 0x366bfc9f

    .line 86
    .line 87
    .line 88
    invoke-virtual {v4, p2}, Ll2/t;->Y(I)V

    .line 89
    .line 90
    .line 91
    and-int/lit8 p1, p1, 0x70

    .line 92
    .line 93
    const/16 p2, 0x8

    .line 94
    .line 95
    or-int v5, p2, p1

    .line 96
    .line 97
    iget-object v2, p0, Lsk/a;->e:Ljava/lang/String;

    .line 98
    .line 99
    iget v3, p0, Lsk/a;->f:F

    .line 100
    .line 101
    invoke-static/range {v0 .. v5}, Lkp/d8;->b(Lug/d;ILjava/lang/String;FLl2/o;I)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v4, v6}, Ll2/t;->q(Z)V

    .line 105
    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_5
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 109
    .line 110
    .line 111
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0
.end method
