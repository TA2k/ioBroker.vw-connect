.class public final synthetic Lot0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lnt0/e;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lnt0/e;Lay0/a;ZLay0/n;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lot0/d;->d:Lnt0/e;

    .line 5
    .line 6
    iput-object p2, p0, Lot0/d;->e:Lay0/a;

    .line 7
    .line 8
    iput-boolean p3, p0, Lot0/d;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lot0/d;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lot0/d;->h:Lay0/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/z0;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "paddingValues"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v3, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    move-object v4, v2

    .line 29
    check-cast v4, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    if-eq v4, v5, :cond_2

    .line 47
    .line 48
    move v4, v6

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    const/4 v4, 0x0

    .line 51
    :goto_1
    and-int/2addr v3, v6

    .line 52
    move-object v12, v2

    .line 53
    check-cast v12, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v12, v3, v4}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_3

    .line 60
    .line 61
    invoke-static {v12}, Lj2/i;->d(Ll2/o;)Lj2/p;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    iget-object v2, v0, Lot0/d;->d:Lnt0/e;

    .line 66
    .line 67
    iget-boolean v5, v2, Lnt0/e;->c:Z

    .line 68
    .line 69
    sget-object v3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 70
    .line 71
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 72
    .line 73
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Lj91/e;

    .line 78
    .line 79
    invoke-virtual {v4}, Lj91/e;->b()J

    .line 80
    .line 81
    .line 82
    move-result-wide v6

    .line 83
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 84
    .line 85
    invoke-static {v3, v6, v7, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v13

    .line 89
    invoke-interface {v1}, Lk1/z0;->d()F

    .line 90
    .line 91
    .line 92
    move-result v15

    .line 93
    invoke-interface {v1}, Lk1/z0;->c()F

    .line 94
    .line 95
    .line 96
    move-result v17

    .line 97
    const/16 v18, 0x5

    .line 98
    .line 99
    const/4 v14, 0x0

    .line 100
    const/16 v16, 0x0

    .line 101
    .line 102
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    new-instance v1, Li50/j;

    .line 107
    .line 108
    const/16 v3, 0x1a

    .line 109
    .line 110
    invoke-direct {v1, v3, v8, v2}, Li50/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    const v3, -0x64ccd6e

    .line 114
    .line 115
    .line 116
    invoke-static {v3, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 117
    .line 118
    .line 119
    move-result-object v10

    .line 120
    new-instance v1, Lh70/l;

    .line 121
    .line 122
    iget-boolean v3, v0, Lot0/d;->f:Z

    .line 123
    .line 124
    iget-object v4, v0, Lot0/d;->g:Lay0/n;

    .line 125
    .line 126
    iget-object v6, v0, Lot0/d;->h:Lay0/a;

    .line 127
    .line 128
    invoke-direct {v1, v2, v3, v4, v6}, Lh70/l;-><init>(Lnt0/e;ZLay0/n;Lay0/a;)V

    .line 129
    .line 130
    .line 131
    const v2, -0x7ae53c4f

    .line 132
    .line 133
    .line 134
    invoke-static {v2, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 135
    .line 136
    .line 137
    move-result-object v11

    .line 138
    const/high16 v13, 0x1b0000

    .line 139
    .line 140
    const/16 v14, 0x10

    .line 141
    .line 142
    iget-object v6, v0, Lot0/d;->e:Lay0/a;

    .line 143
    .line 144
    const/4 v9, 0x0

    .line 145
    invoke-static/range {v5 .. v14}, Lj2/i;->b(ZLay0/a;Lx2/s;Lj2/p;Lx2/e;Lay0/o;Lt2/b;Ll2/o;II)V

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_3
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 150
    .line 151
    .line 152
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 153
    .line 154
    return-object v0
.end method
