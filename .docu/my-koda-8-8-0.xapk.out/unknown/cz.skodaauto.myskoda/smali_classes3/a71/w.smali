.class public final synthetic La71/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La71/w;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, La71/w;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-boolean p3, p0, La71/w;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, La71/w;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, La71/w;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, La71/w;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, La71/w;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, La71/w;->k:Lay0/a;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-object v3, p2

    .line 7
    check-cast v3, Lay0/a;

    .line 8
    .line 9
    check-cast p3, Ll2/o;

    .line 10
    .line 11
    check-cast p4, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    const-string p2, "onShowStopDrivingBottomSheet"

    .line 18
    .line 19
    invoke-static {v3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    and-int/lit8 p2, p1, 0x30

    .line 23
    .line 24
    if-nez p2, :cond_1

    .line 25
    .line 26
    move-object p2, p3

    .line 27
    check-cast p2, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {p2, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    if-eqz p2, :cond_0

    .line 34
    .line 35
    const/16 p2, 0x20

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/16 p2, 0x10

    .line 39
    .line 40
    :goto_0
    or-int/2addr p1, p2

    .line 41
    :cond_1
    and-int/lit16 p2, p1, 0x91

    .line 42
    .line 43
    const/16 p4, 0x90

    .line 44
    .line 45
    if-eq p2, p4, :cond_2

    .line 46
    .line 47
    const/4 p2, 0x1

    .line 48
    goto :goto_1

    .line 49
    :cond_2
    const/4 p2, 0x0

    .line 50
    :goto_1
    and-int/lit8 p4, p1, 0x1

    .line 51
    .line 52
    check-cast p3, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {p3, p4, p2}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_3

    .line 59
    .line 60
    sget-object p2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 61
    .line 62
    iget-object p4, p0, La71/w;->d:Lx2/s;

    .line 63
    .line 64
    invoke-interface {p4, p2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    sget-object p4, Lh71/a;->d:Lh71/a;

    .line 69
    .line 70
    sget-object p4, La71/b;->f:Lt2/b;

    .line 71
    .line 72
    new-instance v0, La71/y;

    .line 73
    .line 74
    iget-boolean v1, p0, La71/w;->f:Z

    .line 75
    .line 76
    iget-boolean v2, p0, La71/w;->g:Z

    .line 77
    .line 78
    iget-object v4, p0, La71/w;->h:Lay0/a;

    .line 79
    .line 80
    iget-object v5, p0, La71/w;->i:Lay0/a;

    .line 81
    .line 82
    iget-object v6, p0, La71/w;->j:Lay0/a;

    .line 83
    .line 84
    iget-object v7, p0, La71/w;->k:Lay0/a;

    .line 85
    .line 86
    invoke-direct/range {v0 .. v7}, La71/y;-><init>(ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V

    .line 87
    .line 88
    .line 89
    const v1, 0x65d1fc60

    .line 90
    .line 91
    .line 92
    invoke-static {v1, p3, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    shl-int/lit8 p1, p1, 0x9

    .line 97
    .line 98
    const v0, 0xe000

    .line 99
    .line 100
    .line 101
    and-int/2addr p1, v0

    .line 102
    const v0, 0x30c30

    .line 103
    .line 104
    .line 105
    or-int v6, p1, v0

    .line 106
    .line 107
    iget-object v1, p0, La71/w;->e:Ljava/lang/String;

    .line 108
    .line 109
    move-object v0, p2

    .line 110
    move-object v5, p3

    .line 111
    move-object v2, p4

    .line 112
    invoke-static/range {v0 .. v6}, La71/b;->n(Lx2/s;Ljava/lang/String;Lt2/b;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 113
    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_3
    move-object v5, p3

    .line 117
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 118
    .line 119
    .line 120
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0
.end method
