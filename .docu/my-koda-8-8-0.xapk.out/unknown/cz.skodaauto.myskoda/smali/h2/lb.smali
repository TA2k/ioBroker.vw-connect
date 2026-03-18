.class public final Lh2/lb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Z

.field public final synthetic f:Lh2/eb;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Z

.field public final synthetic j:Z

.field public final synthetic k:Lg4/p0;

.field public final synthetic l:Lt1/o0;

.field public final synthetic m:Lt1/n0;

.field public final synthetic n:Z

.field public final synthetic o:I

.field public final synthetic p:I

.field public final synthetic q:Ll4/d0;

.field public final synthetic r:Li1/l;

.field public final synthetic s:Lay0/n;

.field public final synthetic t:Lay0/n;

.field public final synthetic u:Le3/n0;


# direct methods
.method public constructor <init>(Lx2/s;ZLh2/eb;Ljava/lang/String;Lay0/k;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Li1/l;Lay0/n;Lay0/n;Le3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/lb;->d:Lx2/s;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/lb;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh2/lb;->f:Lh2/eb;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/lb;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/lb;->h:Lay0/k;

    .line 13
    .line 14
    iput-boolean p6, p0, Lh2/lb;->i:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Lh2/lb;->j:Z

    .line 17
    .line 18
    iput-object p8, p0, Lh2/lb;->k:Lg4/p0;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/lb;->l:Lt1/o0;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/lb;->m:Lt1/n0;

    .line 23
    .line 24
    iput-boolean p11, p0, Lh2/lb;->n:Z

    .line 25
    .line 26
    iput p12, p0, Lh2/lb;->o:I

    .line 27
    .line 28
    iput p13, p0, Lh2/lb;->p:I

    .line 29
    .line 30
    iput-object p14, p0, Lh2/lb;->q:Ll4/d0;

    .line 31
    .line 32
    iput-object p15, p0, Lh2/lb;->r:Li1/l;

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lh2/lb;->s:Lay0/n;

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Lh2/lb;->t:Lay0/n;

    .line 41
    .line 42
    move-object/from16 p1, p18

    .line 43
    .line 44
    iput-object p1, p0, Lh2/lb;->u:Le3/n0;

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

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
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v6

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v6

    .line 26
    check-cast v1, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_3

    .line 33
    .line 34
    const v2, 0x7f1201ef

    .line 35
    .line 36
    .line 37
    invoke-static {v1, v2}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    sget v3, Li2/h1;->a:F

    .line 42
    .line 43
    iget-boolean v3, v0, Lh2/lb;->e:Z

    .line 44
    .line 45
    iget-object v4, v0, Lh2/lb;->d:Lx2/s;

    .line 46
    .line 47
    if-eqz v3, :cond_1

    .line 48
    .line 49
    new-instance v6, Lac0/r;

    .line 50
    .line 51
    const/16 v7, 0x18

    .line 52
    .line 53
    invoke-direct {v6, v2, v7}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v4, v5, v6}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    :cond_1
    sget v2, Lh2/hb;->c:F

    .line 61
    .line 62
    sget v5, Lh2/hb;->b:F

    .line 63
    .line 64
    invoke-static {v4, v2, v5}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    new-instance v2, Le3/p0;

    .line 69
    .line 70
    iget-object v4, v0, Lh2/lb;->f:Lh2/eb;

    .line 71
    .line 72
    if-eqz v3, :cond_2

    .line 73
    .line 74
    iget-wide v5, v4, Lh2/eb;->j:J

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_2
    iget-wide v5, v4, Lh2/eb;->i:J

    .line 78
    .line 79
    :goto_1
    invoke-direct {v2, v5, v6}, Le3/p0;-><init>(J)V

    .line 80
    .line 81
    .line 82
    new-instance v9, Lh2/kb;

    .line 83
    .line 84
    iget-object v3, v0, Lh2/lb;->t:Lay0/n;

    .line 85
    .line 86
    iget-object v5, v0, Lh2/lb;->u:Le3/n0;

    .line 87
    .line 88
    iget-object v6, v0, Lh2/lb;->g:Ljava/lang/String;

    .line 89
    .line 90
    iget-boolean v11, v0, Lh2/lb;->i:Z

    .line 91
    .line 92
    iget-boolean v14, v0, Lh2/lb;->n:Z

    .line 93
    .line 94
    iget-object v13, v0, Lh2/lb;->q:Ll4/d0;

    .line 95
    .line 96
    move v12, v14

    .line 97
    iget-object v14, v0, Lh2/lb;->r:Li1/l;

    .line 98
    .line 99
    iget-boolean v15, v0, Lh2/lb;->e:Z

    .line 100
    .line 101
    iget-object v7, v0, Lh2/lb;->s:Lay0/n;

    .line 102
    .line 103
    move-object/from16 v17, v3

    .line 104
    .line 105
    move-object/from16 v19, v4

    .line 106
    .line 107
    move-object/from16 v18, v5

    .line 108
    .line 109
    move-object v10, v6

    .line 110
    move-object/from16 v16, v7

    .line 111
    .line 112
    invoke-direct/range {v9 .. v19}, Lh2/kb;-><init>(Ljava/lang/String;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Le3/n0;Lh2/eb;)V

    .line 113
    .line 114
    .line 115
    const v3, 0x568400e5

    .line 116
    .line 117
    .line 118
    invoke-static {v3, v1, v9}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 119
    .line 120
    .line 121
    move-result-object v21

    .line 122
    const/high16 v24, 0x30000

    .line 123
    .line 124
    const/16 v25, 0x1000

    .line 125
    .line 126
    iget-object v7, v0, Lh2/lb;->h:Lay0/k;

    .line 127
    .line 128
    iget-boolean v10, v0, Lh2/lb;->j:Z

    .line 129
    .line 130
    move v9, v11

    .line 131
    iget-object v11, v0, Lh2/lb;->k:Lg4/p0;

    .line 132
    .line 133
    move-object/from16 v19, v14

    .line 134
    .line 135
    move v14, v12

    .line 136
    iget-object v12, v0, Lh2/lb;->l:Lt1/o0;

    .line 137
    .line 138
    move-object/from16 v17, v13

    .line 139
    .line 140
    iget-object v13, v0, Lh2/lb;->m:Lt1/n0;

    .line 141
    .line 142
    iget v15, v0, Lh2/lb;->o:I

    .line 143
    .line 144
    iget v0, v0, Lh2/lb;->p:I

    .line 145
    .line 146
    const/16 v18, 0x0

    .line 147
    .line 148
    const/16 v23, 0x0

    .line 149
    .line 150
    move/from16 v16, v0

    .line 151
    .line 152
    move-object/from16 v22, v1

    .line 153
    .line 154
    move-object/from16 v20, v2

    .line 155
    .line 156
    invoke-static/range {v6 .. v25}, Lt1/h;->a(Ljava/lang/String;Lay0/k;Lx2/s;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Lay0/k;Li1/l;Le3/p0;Lt2/b;Ll2/o;III)V

    .line 157
    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_3
    move-object/from16 v22, v1

    .line 161
    .line 162
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 163
    .line 164
    .line 165
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object v0
.end method
