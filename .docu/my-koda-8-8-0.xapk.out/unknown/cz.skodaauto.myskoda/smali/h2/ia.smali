.class public final Lh2/ia;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/t9;


# direct methods
.method public synthetic constructor <init>(Lh2/t9;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/ia;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/ia;->e:Lh2/t9;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/ia;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    move-object v10, v1

    .line 31
    check-cast v10, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v10, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    iget-object v0, v0, Lh2/ia;->e:Lh2/t9;

    .line 40
    .line 41
    invoke-virtual {v10, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    if-nez v1, :cond_1

    .line 50
    .line 51
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 52
    .line 53
    if-ne v2, v1, :cond_2

    .line 54
    .line 55
    :cond_1
    new-instance v2, Lh2/v9;

    .line 56
    .line 57
    const/4 v1, 0x2

    .line 58
    invoke-direct {v2, v0, v1}, Lh2/v9;-><init>(Lh2/t9;I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v10, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    :cond_2
    move-object v4, v2

    .line 65
    check-cast v4, Lay0/a;

    .line 66
    .line 67
    sget-object v9, Lh2/n1;->a:Lt2/b;

    .line 68
    .line 69
    const/high16 v11, 0x180000

    .line 70
    .line 71
    const/16 v12, 0x3e

    .line 72
    .line 73
    const/4 v5, 0x0

    .line 74
    const/4 v6, 0x0

    .line 75
    const/4 v7, 0x0

    .line 76
    const/4 v8, 0x0

    .line 77
    invoke-static/range {v4 .. v12}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object v0

    .line 87
    :pswitch_0
    move-object/from16 v1, p1

    .line 88
    .line 89
    check-cast v1, Ll2/o;

    .line 90
    .line 91
    move-object/from16 v2, p2

    .line 92
    .line 93
    check-cast v2, Ljava/lang/Number;

    .line 94
    .line 95
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    and-int/lit8 v3, v2, 0x3

    .line 100
    .line 101
    const/4 v4, 0x2

    .line 102
    const/4 v5, 0x1

    .line 103
    if-eq v3, v4, :cond_4

    .line 104
    .line 105
    move v3, v5

    .line 106
    goto :goto_2

    .line 107
    :cond_4
    const/4 v3, 0x0

    .line 108
    :goto_2
    and-int/2addr v2, v5

    .line 109
    check-cast v1, Ll2/t;

    .line 110
    .line 111
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    if-eqz v2, :cond_5

    .line 116
    .line 117
    iget-object v0, v0, Lh2/ia;->e:Lh2/t9;

    .line 118
    .line 119
    invoke-interface {v0}, Lh2/t9;->a()Lh2/y9;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    invoke-virtual {v0}, Lh2/y9;->b()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    const/16 v25, 0x0

    .line 128
    .line 129
    const v26, 0x3fffe

    .line 130
    .line 131
    .line 132
    const/4 v5, 0x0

    .line 133
    const-wide/16 v6, 0x0

    .line 134
    .line 135
    const-wide/16 v8, 0x0

    .line 136
    .line 137
    const/4 v10, 0x0

    .line 138
    const-wide/16 v11, 0x0

    .line 139
    .line 140
    const/4 v13, 0x0

    .line 141
    const/4 v14, 0x0

    .line 142
    const-wide/16 v15, 0x0

    .line 143
    .line 144
    const/16 v17, 0x0

    .line 145
    .line 146
    const/16 v18, 0x0

    .line 147
    .line 148
    const/16 v19, 0x0

    .line 149
    .line 150
    const/16 v20, 0x0

    .line 151
    .line 152
    const/16 v21, 0x0

    .line 153
    .line 154
    const/16 v22, 0x0

    .line 155
    .line 156
    const/16 v24, 0x0

    .line 157
    .line 158
    move-object/from16 v23, v1

    .line 159
    .line 160
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 161
    .line 162
    .line 163
    goto :goto_3

    .line 164
    :cond_5
    move-object/from16 v23, v1

    .line 165
    .line 166
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 167
    .line 168
    .line 169
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    return-object v0

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
