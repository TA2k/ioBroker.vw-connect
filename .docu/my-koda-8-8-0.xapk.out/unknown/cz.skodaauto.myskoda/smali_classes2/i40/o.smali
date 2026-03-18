.class public final Li40/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:Lh40/q;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lay0/a;


# direct methods
.method public constructor <init>(Ljava/util/List;Lh40/q;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li40/o;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Li40/o;->e:Lh40/q;

    .line 7
    .line 8
    iput-object p3, p0, Li40/o;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p4, p0, Li40/o;->g:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Li40/o;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Li40/o;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Li40/o;->j:Lay0/a;

    .line 17
    .line 18
    iput-object p8, p0, Li40/o;->k:Lay0/a;

    .line 19
    .line 20
    iput-object p9, p0, Li40/o;->l:Lay0/a;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

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
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    move-object/from16 v2, p3

    .line 16
    .line 17
    check-cast v2, Ll2/o;

    .line 18
    .line 19
    move-object/from16 v3, p4

    .line 20
    .line 21
    check-cast v3, Ljava/lang/Number;

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    and-int/lit8 v4, v3, 0x6

    .line 28
    .line 29
    if-nez v4, :cond_1

    .line 30
    .line 31
    move-object v4, v2

    .line 32
    check-cast v4, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_0

    .line 39
    .line 40
    const/4 v1, 0x4

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v1, 0x2

    .line 43
    :goto_0
    or-int/2addr v1, v3

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    move v1, v3

    .line 46
    :goto_1
    and-int/lit8 v3, v3, 0x30

    .line 47
    .line 48
    if-nez v3, :cond_3

    .line 49
    .line 50
    move-object v3, v2

    .line 51
    check-cast v3, Ll2/t;

    .line 52
    .line 53
    invoke-virtual {v3, v5}, Ll2/t;->e(I)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_2

    .line 58
    .line 59
    const/16 v3, 0x20

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    const/16 v3, 0x10

    .line 63
    .line 64
    :goto_2
    or-int/2addr v1, v3

    .line 65
    :cond_3
    and-int/lit16 v3, v1, 0x93

    .line 66
    .line 67
    const/16 v4, 0x92

    .line 68
    .line 69
    const/4 v14, 0x0

    .line 70
    const/4 v6, 0x1

    .line 71
    if-eq v3, v4, :cond_4

    .line 72
    .line 73
    move v3, v6

    .line 74
    goto :goto_3

    .line 75
    :cond_4
    move v3, v14

    .line 76
    :goto_3
    and-int/2addr v1, v6

    .line 77
    check-cast v2, Ll2/t;

    .line 78
    .line 79
    invoke-virtual {v2, v1, v3}, Ll2/t;->O(IZ)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-eqz v1, :cond_5

    .line 84
    .line 85
    iget-object v1, v0, Li40/o;->d:Ljava/util/List;

    .line 86
    .line 87
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    move-object v4, v1

    .line 92
    check-cast v4, Lh40/m;

    .line 93
    .line 94
    const v1, -0xc414c8

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 98
    .line 99
    .line 100
    iget-object v1, v0, Li40/o;->e:Lh40/q;

    .line 101
    .line 102
    iget-boolean v15, v1, Lh40/q;->e:Z

    .line 103
    .line 104
    invoke-static {v5}, Li40/q;->K(I)Lb1/t0;

    .line 105
    .line 106
    .line 107
    move-result-object v17

    .line 108
    invoke-static {v5}, Li40/q;->L(I)Lb1/u0;

    .line 109
    .line 110
    .line 111
    move-result-object v18

    .line 112
    new-instance v3, Li40/p;

    .line 113
    .line 114
    iget-object v12, v0, Li40/o;->k:Lay0/a;

    .line 115
    .line 116
    iget-object v13, v0, Li40/o;->l:Lay0/a;

    .line 117
    .line 118
    iget-object v6, v0, Li40/o;->e:Lh40/q;

    .line 119
    .line 120
    iget-object v7, v0, Li40/o;->f:Lay0/k;

    .line 121
    .line 122
    iget-object v8, v0, Li40/o;->g:Lay0/k;

    .line 123
    .line 124
    iget-object v9, v0, Li40/o;->h:Lay0/a;

    .line 125
    .line 126
    iget-object v10, v0, Li40/o;->i:Lay0/a;

    .line 127
    .line 128
    iget-object v11, v0, Li40/o;->j:Lay0/a;

    .line 129
    .line 130
    invoke-direct/range {v3 .. v13}, Li40/p;-><init>(Lh40/m;ILh40/q;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V

    .line 131
    .line 132
    .line 133
    const v0, -0x1097eae4

    .line 134
    .line 135
    .line 136
    invoke-static {v0, v2, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 137
    .line 138
    .line 139
    move-result-object v20

    .line 140
    const/high16 v22, 0x30000

    .line 141
    .line 142
    const/16 v23, 0x12

    .line 143
    .line 144
    const/16 v16, 0x0

    .line 145
    .line 146
    const/16 v19, 0x0

    .line 147
    .line 148
    move-object/from16 v21, v2

    .line 149
    .line 150
    invoke-static/range {v15 .. v23}, Landroidx/compose/animation/b;->d(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 154
    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_5
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 158
    .line 159
    .line 160
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    return-object v0
.end method
