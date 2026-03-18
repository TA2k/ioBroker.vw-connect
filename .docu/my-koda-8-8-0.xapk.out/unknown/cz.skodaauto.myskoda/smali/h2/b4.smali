.class public final Lh2/b4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Ljava/lang/Long;

.field public final synthetic e:Ljava/lang/Long;

.field public final synthetic f:J

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Li2/z;

.field public final synthetic j:Lgy0/j;

.field public final synthetic k:Lh2/g2;

.field public final synthetic l:Lh2/e8;

.field public final synthetic m:Lh2/z1;

.field public final synthetic n:Lc3/q;


# direct methods
.method public constructor <init>(Ljava/lang/Long;Ljava/lang/Long;JLay0/n;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/b4;->d:Ljava/lang/Long;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/b4;->e:Ljava/lang/Long;

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/b4;->f:J

    .line 9
    .line 10
    iput-object p5, p0, Lh2/b4;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/b4;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/b4;->i:Li2/z;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/b4;->j:Lgy0/j;

    .line 17
    .line 18
    iput-object p9, p0, Lh2/b4;->k:Lh2/g2;

    .line 19
    .line 20
    iput-object p10, p0, Lh2/b4;->l:Lh2/e8;

    .line 21
    .line 22
    iput-object p11, p0, Lh2/b4;->m:Lh2/z1;

    .line 23
    .line 24
    iput-object p12, p0, Lh2/b4;->n:Lc3/q;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lh2/o4;

    .line 6
    .line 7
    iget v1, v1, Lh2/o4;->a:I

    .line 8
    .line 9
    move-object/from16 v2, p2

    .line 10
    .line 11
    check-cast v2, Ll2/o;

    .line 12
    .line 13
    move-object/from16 v3, p3

    .line 14
    .line 15
    check-cast v3, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    and-int/lit8 v4, v3, 0x6

    .line 22
    .line 23
    if-nez v4, :cond_1

    .line 24
    .line 25
    move-object v4, v2

    .line 26
    check-cast v4, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v4, v1}, Ll2/t;->e(I)Z

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    if-eqz v4, :cond_0

    .line 33
    .line 34
    const/4 v4, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v4, 0x2

    .line 37
    :goto_0
    or-int/2addr v3, v4

    .line 38
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 39
    .line 40
    const/16 v5, 0x12

    .line 41
    .line 42
    const/4 v6, 0x1

    .line 43
    const/4 v7, 0x0

    .line 44
    if-eq v4, v5, :cond_2

    .line 45
    .line 46
    move v4, v6

    .line 47
    goto :goto_1

    .line 48
    :cond_2
    move v4, v7

    .line 49
    :goto_1
    and-int/2addr v3, v6

    .line 50
    check-cast v2, Ll2/t;

    .line 51
    .line 52
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-eqz v3, :cond_5

    .line 57
    .line 58
    if-nez v1, :cond_3

    .line 59
    .line 60
    const v1, -0x24ed1556

    .line 61
    .line 62
    .line 63
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 64
    .line 65
    .line 66
    iget-object v1, v0, Lh2/b4;->m:Lh2/z1;

    .line 67
    .line 68
    const/16 v20, 0x0

    .line 69
    .line 70
    iget-object v8, v0, Lh2/b4;->d:Ljava/lang/Long;

    .line 71
    .line 72
    iget-object v9, v0, Lh2/b4;->e:Ljava/lang/Long;

    .line 73
    .line 74
    iget-wide v10, v0, Lh2/b4;->f:J

    .line 75
    .line 76
    iget-object v12, v0, Lh2/b4;->g:Lay0/n;

    .line 77
    .line 78
    iget-object v13, v0, Lh2/b4;->h:Lay0/k;

    .line 79
    .line 80
    iget-object v14, v0, Lh2/b4;->i:Li2/z;

    .line 81
    .line 82
    iget-object v15, v0, Lh2/b4;->j:Lgy0/j;

    .line 83
    .line 84
    iget-object v3, v0, Lh2/b4;->k:Lh2/g2;

    .line 85
    .line 86
    iget-object v0, v0, Lh2/b4;->l:Lh2/e8;

    .line 87
    .line 88
    move-object/from16 v17, v0

    .line 89
    .line 90
    move-object/from16 v18, v1

    .line 91
    .line 92
    move-object/from16 v19, v2

    .line 93
    .line 94
    move-object/from16 v16, v3

    .line 95
    .line 96
    invoke-static/range {v8 .. v20}, Lh2/f4;->b(Ljava/lang/Long;Ljava/lang/Long;JLay0/n;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_3
    if-ne v1, v6, :cond_4

    .line 104
    .line 105
    const v1, -0x24ecc208

    .line 106
    .line 107
    .line 108
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 109
    .line 110
    .line 111
    iget-object v1, v0, Lh2/b4;->n:Lc3/q;

    .line 112
    .line 113
    const/16 v18, 0x0

    .line 114
    .line 115
    iget-object v8, v0, Lh2/b4;->d:Ljava/lang/Long;

    .line 116
    .line 117
    iget-object v9, v0, Lh2/b4;->e:Ljava/lang/Long;

    .line 118
    .line 119
    iget-object v10, v0, Lh2/b4;->g:Lay0/n;

    .line 120
    .line 121
    iget-object v11, v0, Lh2/b4;->i:Li2/z;

    .line 122
    .line 123
    iget-object v12, v0, Lh2/b4;->j:Lgy0/j;

    .line 124
    .line 125
    iget-object v13, v0, Lh2/b4;->k:Lh2/g2;

    .line 126
    .line 127
    iget-object v14, v0, Lh2/b4;->l:Lh2/e8;

    .line 128
    .line 129
    iget-object v15, v0, Lh2/b4;->m:Lh2/z1;

    .line 130
    .line 131
    move-object/from16 v16, v1

    .line 132
    .line 133
    move-object/from16 v17, v2

    .line 134
    .line 135
    invoke-static/range {v8 .. v18}, Lh2/q3;->a(Ljava/lang/Long;Ljava/lang/Long;Lay0/n;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;Ll2/o;I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_4
    const v0, -0x78a3785d

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_5
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 153
    .line 154
    .line 155
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object v0
.end method
