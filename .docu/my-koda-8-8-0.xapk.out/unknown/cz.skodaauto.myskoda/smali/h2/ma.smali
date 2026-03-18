.class public final Lh2/ma;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Le3/n0;

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:Le1/t;

.field public final synthetic i:Li1/l;

.field public final synthetic j:Z

.field public final synthetic k:Lay0/a;

.field public final synthetic l:F

.field public final synthetic m:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/s;Le3/n0;JFLe1/t;Li1/l;ZLay0/a;FLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/ma;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/ma;->e:Le3/n0;

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/ma;->f:J

    .line 9
    .line 10
    iput p5, p0, Lh2/ma;->g:F

    .line 11
    .line 12
    iput-object p6, p0, Lh2/ma;->h:Le1/t;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/ma;->i:Li1/l;

    .line 15
    .line 16
    iput-boolean p8, p0, Lh2/ma;->j:Z

    .line 17
    .line 18
    iput-object p9, p0, Lh2/ma;->k:Lay0/a;

    .line 19
    .line 20
    iput p10, p0, Lh2/ma;->l:F

    .line 21
    .line 22
    iput-object p11, p0, Lh2/ma;->m:Lt2/b;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

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
    if-eqz v2, :cond_4

    .line 33
    .line 34
    sget-object v2, Lh2/k5;->a:Lt3/o;

    .line 35
    .line 36
    sget-object v2, Landroidx/compose/material3/MinimumInteractiveModifier;->b:Landroidx/compose/material3/MinimumInteractiveModifier;

    .line 37
    .line 38
    iget-object v3, v0, Lh2/ma;->d:Lx2/s;

    .line 39
    .line 40
    invoke-interface {v3, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    iget-wide v2, v0, Lh2/ma;->f:J

    .line 45
    .line 46
    iget v4, v0, Lh2/ma;->g:F

    .line 47
    .line 48
    invoke-static {v2, v3, v4, v1}, Lh2/oa;->e(JFLl2/t;)J

    .line 49
    .line 50
    .line 51
    move-result-wide v9

    .line 52
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 53
    .line 54
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    iget v3, v0, Lh2/ma;->l:F

    .line 59
    .line 60
    check-cast v2, Lt4/c;

    .line 61
    .line 62
    invoke-interface {v2, v3}, Lt4/c;->w0(F)F

    .line 63
    .line 64
    .line 65
    move-result v12

    .line 66
    iget-object v8, v0, Lh2/ma;->e:Le3/n0;

    .line 67
    .line 68
    iget-object v11, v0, Lh2/ma;->h:Le1/t;

    .line 69
    .line 70
    invoke-static/range {v7 .. v12}, Lh2/oa;->d(Lx2/s;Le3/n0;JLe1/t;F)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v13

    .line 74
    const-wide/16 v2, 0x0

    .line 75
    .line 76
    const/4 v4, 0x7

    .line 77
    const/4 v7, 0x0

    .line 78
    invoke-static {v2, v3, v7, v4, v5}, Lh2/w7;->a(JFIZ)Lh2/x7;

    .line 79
    .line 80
    .line 81
    move-result-object v15

    .line 82
    iget-object v2, v0, Lh2/ma;->k:Lay0/a;

    .line 83
    .line 84
    const/16 v19, 0x18

    .line 85
    .line 86
    iget-object v14, v0, Lh2/ma;->i:Li1/l;

    .line 87
    .line 88
    iget-boolean v3, v0, Lh2/ma;->j:Z

    .line 89
    .line 90
    const/16 v17, 0x0

    .line 91
    .line 92
    move-object/from16 v18, v2

    .line 93
    .line 94
    move/from16 v16, v3

    .line 95
    .line 96
    invoke-static/range {v13 .. v19}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    invoke-static {v2}, Li2/a1;->g(Lx2/s;)Lx2/s;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 105
    .line 106
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    iget-wide v7, v1, Ll2/t;->T:J

    .line 111
    .line 112
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 125
    .line 126
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 130
    .line 131
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 132
    .line 133
    .line 134
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 135
    .line 136
    if-eqz v9, :cond_1

    .line 137
    .line 138
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 139
    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 143
    .line 144
    .line 145
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 146
    .line 147
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 148
    .line 149
    .line 150
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 151
    .line 152
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 153
    .line 154
    .line 155
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 156
    .line 157
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 158
    .line 159
    if-nez v7, :cond_2

    .line 160
    .line 161
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 166
    .line 167
    .line 168
    move-result-object v8

    .line 169
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v7

    .line 173
    if-nez v7, :cond_3

    .line 174
    .line 175
    :cond_2
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 176
    .line 177
    .line 178
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 179
    .line 180
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 181
    .line 182
    .line 183
    iget-object v0, v0, Lh2/ma;->m:Lt2/b;

    .line 184
    .line 185
    invoke-static {v5, v0, v1, v6}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 186
    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 190
    .line 191
    .line 192
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    return-object v0
.end method
