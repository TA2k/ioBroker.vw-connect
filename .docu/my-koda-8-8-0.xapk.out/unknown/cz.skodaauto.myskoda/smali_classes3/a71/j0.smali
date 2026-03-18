.class public final synthetic La71/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/lang/String;

.field public final synthetic e:Lx61/b;

.field public final synthetic f:Lt71/d;

.field public final synthetic g:Z

.field public final synthetic h:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lx61/b;Lt71/d;ZLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La71/j0;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, La71/j0;->e:Lx61/b;

    .line 7
    .line 8
    iput-object p3, p0, La71/j0;->f:Lt71/d;

    .line 9
    .line 10
    iput-boolean p4, p0, La71/j0;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, La71/j0;->h:Lt2/b;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    move-object v3, p2

    .line 8
    check-cast v3, Lay0/a;

    .line 9
    .line 10
    check-cast p3, Ll2/o;

    .line 11
    .line 12
    check-cast p4, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    const-string p4, "onShowStopDrivingBottomSheet"

    .line 19
    .line 20
    invoke-static {v3, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    and-int/lit8 p4, p2, 0x6

    .line 24
    .line 25
    if-nez p4, :cond_1

    .line 26
    .line 27
    move-object p4, p3

    .line 28
    check-cast p4, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {p4, p1}, Ll2/t;->h(Z)Z

    .line 31
    .line 32
    .line 33
    move-result p4

    .line 34
    if-eqz p4, :cond_0

    .line 35
    .line 36
    const/4 p4, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 p4, 0x2

    .line 39
    :goto_0
    or-int/2addr p4, p2

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move p4, p2

    .line 42
    :goto_1
    and-int/lit8 p2, p2, 0x30

    .line 43
    .line 44
    if-nez p2, :cond_3

    .line 45
    .line 46
    move-object p2, p3

    .line 47
    check-cast p2, Ll2/t;

    .line 48
    .line 49
    invoke-virtual {p2, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    if-eqz p2, :cond_2

    .line 54
    .line 55
    const/16 p2, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 p2, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr p4, p2

    .line 61
    :cond_3
    and-int/lit16 p2, p4, 0x93

    .line 62
    .line 63
    const/16 v0, 0x92

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    const/4 v2, 0x1

    .line 67
    if-eq p2, v0, :cond_4

    .line 68
    .line 69
    move p2, v2

    .line 70
    goto :goto_3

    .line 71
    :cond_4
    move p2, v1

    .line 72
    :goto_3
    and-int/lit8 v0, p4, 0x1

    .line 73
    .line 74
    move-object v5, p3

    .line 75
    check-cast v5, Ll2/t;

    .line 76
    .line 77
    invoke-virtual {v5, v0, p2}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    if-eqz p2, :cond_5

    .line 82
    .line 83
    sget-object v0, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 84
    .line 85
    sget-object p2, Lh71/a;->d:Lh71/a;

    .line 86
    .line 87
    new-instance p2, La71/m0;

    .line 88
    .line 89
    iget-object p3, p0, La71/j0;->e:Lx61/b;

    .line 90
    .line 91
    iget-object v4, p0, La71/j0;->f:Lt71/d;

    .line 92
    .line 93
    iget-boolean v6, p0, La71/j0;->g:Z

    .line 94
    .line 95
    invoke-direct {p2, p3, v4, v6, v1}, La71/m0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 96
    .line 97
    .line 98
    const p3, 0x46840a66

    .line 99
    .line 100
    .line 101
    invoke-static {p3, v5, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 102
    .line 103
    .line 104
    move-result-object p2

    .line 105
    new-instance p3, La71/l0;

    .line 106
    .line 107
    iget-object v1, p0, La71/j0;->h:Lt2/b;

    .line 108
    .line 109
    invoke-direct {p3, v1, p1, v3, v2}, La71/l0;-><init>(Ljava/lang/Object;ZLlx0/e;I)V

    .line 110
    .line 111
    .line 112
    const p1, -0x6e031b8

    .line 113
    .line 114
    .line 115
    invoke-static {p1, v5, p3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    shl-int/lit8 p1, p4, 0x9

    .line 120
    .line 121
    const p3, 0xe000

    .line 122
    .line 123
    .line 124
    and-int/2addr p1, p3

    .line 125
    const p3, 0x30c36

    .line 126
    .line 127
    .line 128
    or-int v6, p1, p3

    .line 129
    .line 130
    iget-object v1, p0, La71/j0;->d:Ljava/lang/String;

    .line 131
    .line 132
    move-object v2, p2

    .line 133
    invoke-static/range {v0 .. v6}, La71/b;->n(Lx2/s;Ljava/lang/String;Lt2/b;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 134
    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_5
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 138
    .line 139
    .line 140
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 141
    .line 142
    return-object p0
.end method
