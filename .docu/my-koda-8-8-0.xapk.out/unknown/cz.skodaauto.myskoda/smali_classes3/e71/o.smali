.class public final synthetic Le71/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Z

.field public final synthetic f:Lh71/x;

.field public final synthetic g:Ljava/lang/Float;

.field public final synthetic h:Le71/g;


# direct methods
.method public synthetic constructor <init>(FZLh71/x;Ljava/lang/Float;Le71/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Le71/o;->d:F

    .line 5
    .line 6
    iput-boolean p2, p0, Le71/o;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Le71/o;->f:Lh71/x;

    .line 9
    .line 10
    iput-object p4, p0, Le71/o;->g:Ljava/lang/Float;

    .line 11
    .line 12
    iput-object p5, p0, Le71/o;->h:Le71/g;

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
    check-cast v1, Landroidx/compose/foundation/layout/c;

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
    const-string v4, "$this$BoxWithConstraints"

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
    move-object v12, v2

    .line 54
    check-cast v12, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v12, v3, v4}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_5

    .line 61
    .line 62
    invoke-virtual {v1}, Landroidx/compose/foundation/layout/c;->c()F

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    const v3, 0x3d23d70a    # 0.04f

    .line 67
    .line 68
    .line 69
    mul-float v9, v2, v3

    .line 70
    .line 71
    invoke-virtual {v1}, Landroidx/compose/foundation/layout/c;->c()F

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    const/high16 v2, 0x3f000000    # 0.5f

    .line 76
    .line 77
    mul-float/2addr v1, v2

    .line 78
    iget v2, v0, Le71/o;->d:F

    .line 79
    .line 80
    mul-float/2addr v1, v2

    .line 81
    iget-boolean v2, v0, Le71/o;->e:Z

    .line 82
    .line 83
    const/high16 v3, 0x3f800000    # 1.0f

    .line 84
    .line 85
    if-eqz v2, :cond_3

    .line 86
    .line 87
    const v2, 0x45503fa9

    .line 88
    .line 89
    .line 90
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 91
    .line 92
    .line 93
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 94
    .line 95
    invoke-static {v2, v3, v7}, Landroidx/compose/foundation/layout/a;->d(Lx2/s;FZ)Lx2/s;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    const/4 v13, 0x6

    .line 100
    const/4 v14, 0x0

    .line 101
    iget-object v10, v0, Le71/o;->f:Lh71/x;

    .line 102
    .line 103
    iget-object v11, v0, Le71/o;->g:Ljava/lang/Float;

    .line 104
    .line 105
    invoke-static/range {v8 .. v14}, Lkp/w5;->d(Lx2/s;FLh71/x;Ljava/lang/Float;Ll2/o;II)V

    .line 106
    .line 107
    .line 108
    :goto_2
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    const v2, 0x4535880b

    .line 113
    .line 114
    .line 115
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 116
    .line 117
    .line 118
    goto :goto_2

    .line 119
    :goto_3
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 120
    .line 121
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v13

    .line 125
    iget-object v0, v0, Le71/o;->h:Le71/g;

    .line 126
    .line 127
    iget-object v14, v0, Le71/g;->a:Li3/c;

    .line 128
    .line 129
    if-eqz v14, :cond_4

    .line 130
    .line 131
    const/16 v18, 0x0

    .line 132
    .line 133
    const/16 v19, 0x3e

    .line 134
    .line 135
    const/4 v15, 0x0

    .line 136
    const/16 v16, 0x0

    .line 137
    .line 138
    const/16 v17, 0x0

    .line 139
    .line 140
    invoke-static/range {v13 .. v19}, Landroidx/compose/ui/draw/a;->d(Lx2/s;Li3/c;Lx2/e;Lt3/k;FLe3/m;I)Lx2/s;

    .line 141
    .line 142
    .line 143
    move-result-object v13

    .line 144
    :cond_4
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 145
    .line 146
    invoke-interface {v13, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    sget-object v2, Lx2/c;->e:Lx2/j;

    .line 151
    .line 152
    sget-object v4, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 153
    .line 154
    invoke-virtual {v4, v1, v2}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-static {v1, v3, v7}, Landroidx/compose/foundation/layout/a;->d(Lx2/s;FZ)Lx2/s;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    iget-object v9, v0, Le71/g;->b:Li3/c;

    .line 163
    .line 164
    iget-wide v10, v0, Le71/g;->c:J

    .line 165
    .line 166
    const/4 v13, 0x0

    .line 167
    invoke-static/range {v8 .. v13}, Lkp/i0;->b(Lx2/s;Li3/c;JLl2/o;I)V

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_5
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 172
    .line 173
    .line 174
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 175
    .line 176
    return-object v0
.end method
