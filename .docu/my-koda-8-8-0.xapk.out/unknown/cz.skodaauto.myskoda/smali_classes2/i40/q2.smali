.class public final synthetic Li40/q2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lh40/u;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z


# direct methods
.method public synthetic constructor <init>(Lh40/u;Lay0/a;ZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li40/q2;->d:Lh40/u;

    .line 5
    .line 6
    iput-object p2, p0, Li40/q2;->e:Lay0/a;

    .line 7
    .line 8
    iput-boolean p3, p0, Li40/q2;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Li40/q2;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Li40/q2;->h:Z

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Landroidx/compose/foundation/lazy/a;

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
    const-string v4, "$this$item"

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
    const/4 v7, 0x0

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v6

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v4, v7

    .line 52
    :goto_1
    and-int/2addr v3, v6

    .line 53
    move-object v13, v2

    .line 54
    check-cast v13, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v13, v3, v4}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_5

    .line 61
    .line 62
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 63
    .line 64
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    check-cast v3, Lj91/c;

    .line 69
    .line 70
    iget v3, v3, Lj91/c;->c:F

    .line 71
    .line 72
    const/high16 v4, 0x3f800000    # 1.0f

    .line 73
    .line 74
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 75
    .line 76
    invoke-static {v5, v3, v13, v5, v4}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v14

    .line 80
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    check-cast v3, Lj91/c;

    .line 85
    .line 86
    iget v15, v3, Lj91/c;->k:F

    .line 87
    .line 88
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    check-cast v3, Lj91/c;

    .line 93
    .line 94
    iget v3, v3, Lj91/c;->k:F

    .line 95
    .line 96
    const/16 v18, 0x0

    .line 97
    .line 98
    const/16 v19, 0xa

    .line 99
    .line 100
    const/16 v16, 0x0

    .line 101
    .line 102
    move/from16 v17, v3

    .line 103
    .line 104
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-static {v1, v3}, Landroidx/compose/foundation/lazy/a;->a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;

    .line 109
    .line 110
    .line 111
    move-result-object v8

    .line 112
    iget-boolean v12, v0, Li40/q2;->f:Z

    .line 113
    .line 114
    if-nez v12, :cond_3

    .line 115
    .line 116
    iget-boolean v1, v0, Li40/q2;->g:Z

    .line 117
    .line 118
    if-nez v1, :cond_3

    .line 119
    .line 120
    move v11, v6

    .line 121
    goto :goto_2

    .line 122
    :cond_3
    move v11, v7

    .line 123
    :goto_2
    const/4 v14, 0x0

    .line 124
    iget-object v9, v0, Li40/q2;->d:Lh40/u;

    .line 125
    .line 126
    iget-object v10, v0, Li40/q2;->e:Lay0/a;

    .line 127
    .line 128
    invoke-static/range {v8 .. v14}, Li40/q;->i(Lx2/s;Lh40/u;Lay0/a;ZZLl2/o;I)V

    .line 129
    .line 130
    .line 131
    iget-boolean v0, v0, Li40/q2;->h:Z

    .line 132
    .line 133
    if-eqz v0, :cond_4

    .line 134
    .line 135
    const v0, -0x5999434e

    .line 136
    .line 137
    .line 138
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    check-cast v0, Lj91/c;

    .line 146
    .line 147
    iget v0, v0, Lj91/c;->c:F

    .line 148
    .line 149
    :goto_3
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 150
    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_4
    const v0, -0x59993f0f

    .line 154
    .line 155
    .line 156
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v13, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    check-cast v0, Lj91/c;

    .line 164
    .line 165
    iget v0, v0, Lj91/c;->e:F

    .line 166
    .line 167
    goto :goto_3

    .line 168
    :goto_4
    invoke-static {v5, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-static {v13, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 173
    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_5
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 177
    .line 178
    .line 179
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    return-object v0
.end method
