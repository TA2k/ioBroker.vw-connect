.class public final Lvv/r;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:Lvv/m0;

.field public final synthetic g:Lvv/f0;

.field public final synthetic h:I

.field public final synthetic i:Lt2/b;

.field public final synthetic j:Ljava/util/List;


# direct methods
.method public constructor <init>(Lvv/m0;Lvv/f0;ILt2/b;Ljava/util/List;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/r;->f:Lvv/m0;

    .line 2
    .line 3
    iput-object p2, p0, Lvv/r;->g:Lvv/f0;

    .line 4
    .line 5
    iput p3, p0, Lvv/r;->h:I

    .line 6
    .line 7
    iput-object p4, p0, Lvv/r;->i:Lt2/b;

    .line 8
    .line 9
    iput-object p5, p0, Lvv/r;->j:Ljava/util/List;

    .line 10
    .line 11
    const/4 p1, 0x3

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    move-object v4, p2

    .line 8
    check-cast v4, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    and-int/lit8 p3, p2, 0xe

    .line 17
    .line 18
    if-nez p3, :cond_1

    .line 19
    .line 20
    move-object p3, v4

    .line 21
    check-cast p3, Ll2/t;

    .line 22
    .line 23
    invoke-virtual {p3, p1}, Ll2/t;->e(I)Z

    .line 24
    .line 25
    .line 26
    move-result p3

    .line 27
    if-eqz p3, :cond_0

    .line 28
    .line 29
    const/4 p3, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p3, 0x2

    .line 32
    :goto_0
    or-int/2addr p2, p3

    .line 33
    :cond_1
    and-int/lit8 p2, p2, 0x5b

    .line 34
    .line 35
    const/16 p3, 0x12

    .line 36
    .line 37
    if-ne p2, p3, :cond_3

    .line 38
    .line 39
    move-object p2, v4

    .line 40
    check-cast p2, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 43
    .line 44
    .line 45
    move-result p3

    .line 46
    if-nez p3, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_3
    :goto_1
    iget-object p2, p0, Lvv/r;->f:Lvv/m0;

    .line 54
    .line 55
    invoke-static {p2, v4}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    iget-object p2, p0, Lvv/r;->g:Lvv/f0;

    .line 60
    .line 61
    iget-object v6, p2, Lvv/f0;->c:Lt4/o;

    .line 62
    .line 63
    const/4 v9, 0x0

    .line 64
    const/16 v10, 0xfe

    .line 65
    .line 66
    const/4 v7, 0x0

    .line 67
    const/4 v8, 0x0

    .line 68
    invoke-static/range {v5 .. v10}, Lvv/n0;->a(Lvv/n0;Lt4/o;Lay0/n;Lvv/f0;Lxv/p;I)Lvv/n0;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    new-instance p2, Lvv/q;

    .line 73
    .line 74
    iget-object p3, p0, Lvv/r;->i:Lt2/b;

    .line 75
    .line 76
    iget-object v0, p0, Lvv/r;->j:Ljava/util/List;

    .line 77
    .line 78
    iget p0, p0, Lvv/r;->h:I

    .line 79
    .line 80
    invoke-direct {p2, p0, p3, v0, p1}, Lvv/q;-><init>(ILt2/b;Ljava/util/List;I)V

    .line 81
    .line 82
    .line 83
    const p0, 0x57bd5424

    .line 84
    .line 85
    .line 86
    invoke-static {p0, v4, p2}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    const/16 v5, 0xc00

    .line 91
    .line 92
    const/4 v6, 0x5

    .line 93
    const/4 v0, 0x0

    .line 94
    const/4 v2, 0x0

    .line 95
    invoke-static/range {v0 .. v6}, Llp/dc;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V

    .line 96
    .line 97
    .line 98
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0
.end method
