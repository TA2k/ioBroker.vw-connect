.class public final synthetic Lc1/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ll2/t2;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroidx/media3/exoplayer/ExoPlayer;Lio0/c;Ljava/lang/String;Landroid/media/AudioManager;Ll2/f1;FLl2/b1;Ll2/b1;)V
    .locals 0

    .line 1
    const/4 p2, 0x1

    iput p2, p0, Lc1/i1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc1/i1;->f:Ljava/lang/Object;

    iput-object p3, p0, Lc1/i1;->g:Ljava/lang/Object;

    iput-object p4, p0, Lc1/i1;->h:Ljava/lang/Object;

    iput-object p5, p0, Lc1/i1;->i:Ljava/lang/Object;

    iput p6, p0, Lc1/i1;->e:F

    iput-object p7, p0, Lc1/i1;->j:Ll2/t2;

    iput-object p8, p0, Lc1/i1;->k:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/f0;Ljava/lang/Object;Lc1/f;Lc1/p;Lc1/k;FLay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lc1/i1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc1/i1;->f:Ljava/lang/Object;

    iput-object p2, p0, Lc1/i1;->g:Ljava/lang/Object;

    iput-object p3, p0, Lc1/i1;->h:Ljava/lang/Object;

    iput-object p4, p0, Lc1/i1;->i:Ljava/lang/Object;

    iput-object p5, p0, Lc1/i1;->j:Ll2/t2;

    iput p6, p0, Lc1/i1;->e:F

    iput-object p7, p0, Lc1/i1;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc1/i1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lc1/i1;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Landroidx/media3/exoplayer/ExoPlayer;

    .line 11
    .line 12
    iget-object v2, v0, Lc1/i1;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, v0, Lc1/i1;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v3, Landroid/media/AudioManager;

    .line 19
    .line 20
    iget-object v4, v0, Lc1/i1;->i:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v4, Ll2/f1;

    .line 23
    .line 24
    iget-object v5, v0, Lc1/i1;->j:Ll2/t2;

    .line 25
    .line 26
    check-cast v5, Ll2/b1;

    .line 27
    .line 28
    iget-object v6, v0, Lc1/i1;->k:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v6, Ll2/b1;

    .line 31
    .line 32
    move-object/from16 v7, p1

    .line 33
    .line 34
    check-cast v7, Landroidx/compose/runtime/DisposableEffectScope;

    .line 35
    .line 36
    const-string v8, "$this$DisposableEffect"

    .line 37
    .line 38
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance v8, Lac0/a;

    .line 42
    .line 43
    const/16 v9, 0x17

    .line 44
    .line 45
    invoke-direct {v8, v2, v9}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 46
    .line 47
    .line 48
    const/4 v9, 0x0

    .line 49
    invoke-static {v9, v1, v8}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 50
    .line 51
    .line 52
    move-object v8, v1

    .line 53
    check-cast v8, La8/i0;

    .line 54
    .line 55
    invoke-virtual {v8}, La8/i0;->w0()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v8}, La8/i0;->L0()V

    .line 59
    .line 60
    .line 61
    const/4 v10, 0x1

    .line 62
    const/4 v11, 0x0

    .line 63
    invoke-virtual {v8, v10, v11}, La8/i0;->I0(IZ)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v8, v11}, La8/i0;->C0(I)V

    .line 67
    .line 68
    .line 69
    new-instance v10, Lio0/h;

    .line 70
    .line 71
    iget v0, v0, Lc1/i1;->e:F

    .line 72
    .line 73
    invoke-direct {v10, v4, v0, v5, v6}, Lio0/h;-><init>(Ll2/f1;FLl2/b1;Ll2/b1;)V

    .line 74
    .line 75
    .line 76
    iget-object v0, v8, La8/i0;->q:Le30/v;

    .line 77
    .line 78
    invoke-virtual {v0, v10}, Le30/v;->a(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    invoke-static {v2}, Lt7/x;->a(Ljava/lang/String;)Lt7/x;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    move-object v2, v1

    .line 86
    check-cast v2, Lap0/o;

    .line 87
    .line 88
    invoke-virtual {v2, v0}, Lap0/o;->U(Lt7/x;)V

    .line 89
    .line 90
    .line 91
    new-instance v0, Lio0/d;

    .line 92
    .line 93
    const/4 v2, 0x0

    .line 94
    invoke-direct {v0, v1, v2}, Lio0/d;-><init>(Landroidx/media3/exoplayer/ExoPlayer;I)V

    .line 95
    .line 96
    .line 97
    invoke-static {v9, v1, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 98
    .line 99
    .line 100
    const/4 v0, 0x3

    .line 101
    if-eqz v3, :cond_0

    .line 102
    .line 103
    invoke-virtual {v3, v0}, Landroid/media/AudioManager;->getStreamVolume(I)I

    .line 104
    .line 105
    .line 106
    :cond_0
    if-eqz v3, :cond_1

    .line 107
    .line 108
    invoke-virtual {v3, v0}, Landroid/media/AudioManager;->getStreamMaxVolume(I)I

    .line 109
    .line 110
    .line 111
    :cond_1
    const/4 v0, 0x0

    .line 112
    invoke-virtual {v8, v0}, La8/i0;->F0(F)V

    .line 113
    .line 114
    .line 115
    new-instance v0, Laa/t;

    .line 116
    .line 117
    const/4 v2, 0x6

    .line 118
    invoke-direct {v0, v2, v7, v1}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    return-object v0

    .line 122
    :pswitch_0
    iget-object v1, v0, Lc1/i1;->f:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v1, Lkotlin/jvm/internal/f0;

    .line 125
    .line 126
    iget-object v2, v0, Lc1/i1;->h:Ljava/lang/Object;

    .line 127
    .line 128
    move-object v7, v2

    .line 129
    check-cast v7, Lc1/f;

    .line 130
    .line 131
    iget-object v2, v0, Lc1/i1;->i:Ljava/lang/Object;

    .line 132
    .line 133
    move-object v11, v2

    .line 134
    check-cast v11, Lc1/p;

    .line 135
    .line 136
    iget-object v2, v0, Lc1/i1;->j:Ll2/t2;

    .line 137
    .line 138
    check-cast v2, Lc1/k;

    .line 139
    .line 140
    iget-object v3, v0, Lc1/i1;->k:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v3, Lay0/k;

    .line 143
    .line 144
    move-object/from16 v4, p1

    .line 145
    .line 146
    check-cast v4, Ljava/lang/Long;

    .line 147
    .line 148
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 149
    .line 150
    .line 151
    move-result-wide v4

    .line 152
    new-instance v8, Lc1/i;

    .line 153
    .line 154
    invoke-interface {v7}, Lc1/f;->e()Lc1/b2;

    .line 155
    .line 156
    .line 157
    move-result-object v10

    .line 158
    invoke-interface {v7}, Lc1/f;->g()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v14

    .line 162
    new-instance v6, Lc1/j1;

    .line 163
    .line 164
    const/4 v9, 0x1

    .line 165
    invoke-direct {v6, v9, v2}, Lc1/j1;-><init>(ILc1/k;)V

    .line 166
    .line 167
    .line 168
    iget-object v9, v0, Lc1/i1;->g:Ljava/lang/Object;

    .line 169
    .line 170
    move-wide v15, v4

    .line 171
    move-wide v12, v4

    .line 172
    move-object/from16 v17, v6

    .line 173
    .line 174
    invoke-direct/range {v8 .. v17}, Lc1/i;-><init>(Ljava/lang/Object;Lc1/b2;Lc1/p;JLjava/lang/Object;JLay0/a;)V

    .line 175
    .line 176
    .line 177
    iget v6, v0, Lc1/i1;->e:F

    .line 178
    .line 179
    move-object v9, v3

    .line 180
    move-object v3, v8

    .line 181
    move-object v8, v2

    .line 182
    invoke-static/range {v3 .. v9}, Lc1/d;->n(Lc1/i;JFLc1/f;Lc1/k;Lay0/k;)V

    .line 183
    .line 184
    .line 185
    move-object v8, v3

    .line 186
    iput-object v8, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 187
    .line 188
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object v0

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
