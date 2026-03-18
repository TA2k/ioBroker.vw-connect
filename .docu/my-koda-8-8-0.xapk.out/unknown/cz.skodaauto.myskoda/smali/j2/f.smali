.class public final Lj2/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Lj2/p;


# direct methods
.method public constructor <init>(JLj2/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lj2/f;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Lj2/f;->e:Lj2/p;

    .line 7
    .line 8
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
    check-cast v1, Ljava/lang/Boolean;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    move-object/from16 v2, p2

    .line 12
    .line 13
    check-cast v2, Ll2/o;

    .line 14
    .line 15
    move-object/from16 v3, p3

    .line 16
    .line 17
    check-cast v3, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    and-int/lit8 v4, v3, 0x6

    .line 24
    .line 25
    if-nez v4, :cond_1

    .line 26
    .line 27
    move-object v4, v2

    .line 28
    check-cast v4, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {v4, v1}, Ll2/t;->h(Z)Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-eqz v4, :cond_0

    .line 35
    .line 36
    const/4 v4, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v4, 0x2

    .line 39
    :goto_0
    or-int/2addr v3, v4

    .line 40
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 41
    .line 42
    const/16 v5, 0x12

    .line 43
    .line 44
    const/4 v6, 0x1

    .line 45
    const/4 v7, 0x0

    .line 46
    if-eq v4, v5, :cond_2

    .line 47
    .line 48
    move v4, v6

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    move v4, v7

    .line 51
    :goto_1
    and-int/2addr v3, v6

    .line 52
    check-cast v2, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    if-eqz v3, :cond_6

    .line 59
    .line 60
    if-eqz v1, :cond_3

    .line 61
    .line 62
    const v1, -0x1dca1a97

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 66
    .line 67
    .line 68
    sget v11, Lj2/i;->a:F

    .line 69
    .line 70
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 71
    .line 72
    sget v3, Lj2/i;->c:F

    .line 73
    .line 74
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    const/16 v17, 0x186

    .line 79
    .line 80
    const/16 v18, 0x38

    .line 81
    .line 82
    iget-wide v9, v0, Lj2/f;->d:J

    .line 83
    .line 84
    const-wide/16 v12, 0x0

    .line 85
    .line 86
    const/4 v14, 0x0

    .line 87
    const/4 v15, 0x0

    .line 88
    move-object/from16 v16, v2

    .line 89
    .line 90
    invoke-static/range {v8 .. v18}, Lh2/n7;->a(Lx2/s;JFJIFLl2/o;II)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_3
    const v1, -0x1dc66309

    .line 98
    .line 99
    .line 100
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    iget-object v1, v0, Lj2/f;->e:Lj2/p;

    .line 104
    .line 105
    invoke-virtual {v2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    if-nez v3, :cond_4

    .line 114
    .line 115
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-ne v4, v3, :cond_5

    .line 118
    .line 119
    :cond_4
    new-instance v4, Lh2/k4;

    .line 120
    .line 121
    const/4 v3, 0x1

    .line 122
    invoke-direct {v4, v1, v3}, Lh2/k4;-><init>(Ljava/lang/Object;I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_5
    check-cast v4, Li2/l0;

    .line 129
    .line 130
    iget-wide v0, v0, Lj2/f;->d:J

    .line 131
    .line 132
    invoke-static {v4, v0, v1, v2, v7}, Lj2/i;->a(Li2/l0;JLl2/o;I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 136
    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_6
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 140
    .line 141
    .line 142
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    return-object v0
.end method
