.class public final Lkn/a;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lkn/c0;

.field public final synthetic h:Lx2/s;

.field public final synthetic i:Z

.field public final synthetic j:Lkn/l0;

.field public final synthetic k:Ls1/e;

.field public final synthetic l:J

.field public final synthetic m:J

.field public final synthetic n:F

.field public final synthetic o:Lkn/j0;

.field public final synthetic p:Lx2/d;

.field public final synthetic q:Lt2/b;

.field public final synthetic r:Lt2/b;

.field public final synthetic s:I

.field public final synthetic t:I


# direct methods
.method public synthetic constructor <init>(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;III)V
    .locals 1

    .line 1
    move/from16 v0, p17

    .line 2
    .line 3
    iput v0, p0, Lkn/a;->f:I

    .line 4
    .line 5
    iput-object p1, p0, Lkn/a;->g:Lkn/c0;

    .line 6
    .line 7
    iput-object p2, p0, Lkn/a;->h:Lx2/s;

    .line 8
    .line 9
    iput-boolean p3, p0, Lkn/a;->i:Z

    .line 10
    .line 11
    iput-object p4, p0, Lkn/a;->j:Lkn/l0;

    .line 12
    .line 13
    iput-object p5, p0, Lkn/a;->k:Ls1/e;

    .line 14
    .line 15
    iput-wide p6, p0, Lkn/a;->l:J

    .line 16
    .line 17
    iput-wide p8, p0, Lkn/a;->m:J

    .line 18
    .line 19
    iput p10, p0, Lkn/a;->n:F

    .line 20
    .line 21
    iput-object p11, p0, Lkn/a;->o:Lkn/j0;

    .line 22
    .line 23
    iput-object p12, p0, Lkn/a;->p:Lx2/d;

    .line 24
    .line 25
    iput-object p13, p0, Lkn/a;->q:Lt2/b;

    .line 26
    .line 27
    iput-object p14, p0, Lkn/a;->r:Lt2/b;

    .line 28
    .line 29
    move/from16 p1, p15

    .line 30
    .line 31
    iput p1, p0, Lkn/a;->s:I

    .line 32
    .line 33
    move/from16 p1, p16

    .line 34
    .line 35
    iput p1, p0, Lkn/a;->t:I

    .line 36
    .line 37
    const/4 p1, 0x2

    .line 38
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 39
    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lkn/a;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v16, p1

    .line 9
    .line 10
    check-cast v16, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    iget v1, v0, Lkn/a;->s:I

    .line 20
    .line 21
    or-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 24
    .line 25
    .line 26
    move-result v17

    .line 27
    iget v1, v0, Lkn/a;->t:I

    .line 28
    .line 29
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result v18

    .line 33
    iget-object v2, v0, Lkn/a;->g:Lkn/c0;

    .line 34
    .line 35
    iget-object v3, v0, Lkn/a;->h:Lx2/s;

    .line 36
    .line 37
    iget-boolean v4, v0, Lkn/a;->i:Z

    .line 38
    .line 39
    iget-object v5, v0, Lkn/a;->j:Lkn/l0;

    .line 40
    .line 41
    iget-object v6, v0, Lkn/a;->k:Ls1/e;

    .line 42
    .line 43
    iget-wide v7, v0, Lkn/a;->l:J

    .line 44
    .line 45
    iget-wide v9, v0, Lkn/a;->m:J

    .line 46
    .line 47
    iget v11, v0, Lkn/a;->n:F

    .line 48
    .line 49
    iget-object v12, v0, Lkn/a;->o:Lkn/j0;

    .line 50
    .line 51
    iget-object v13, v0, Lkn/a;->p:Lx2/d;

    .line 52
    .line 53
    iget-object v14, v0, Lkn/a;->q:Lt2/b;

    .line 54
    .line 55
    iget-object v15, v0, Lkn/a;->r:Lt2/b;

    .line 56
    .line 57
    invoke-static/range {v2 .. v18}, Llp/ud;->a(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 58
    .line 59
    .line 60
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object v0

    .line 63
    :pswitch_0
    move-object/from16 v15, p1

    .line 64
    .line 65
    check-cast v15, Ll2/o;

    .line 66
    .line 67
    move-object/from16 v1, p2

    .line 68
    .line 69
    check-cast v1, Ljava/lang/Number;

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 72
    .line 73
    .line 74
    iget v1, v0, Lkn/a;->s:I

    .line 75
    .line 76
    or-int/lit8 v1, v1, 0x1

    .line 77
    .line 78
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 79
    .line 80
    .line 81
    move-result v16

    .line 82
    iget v1, v0, Lkn/a;->t:I

    .line 83
    .line 84
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 85
    .line 86
    .line 87
    move-result v17

    .line 88
    iget-object v1, v0, Lkn/a;->g:Lkn/c0;

    .line 89
    .line 90
    iget-object v2, v0, Lkn/a;->h:Lx2/s;

    .line 91
    .line 92
    iget-boolean v3, v0, Lkn/a;->i:Z

    .line 93
    .line 94
    iget-object v4, v0, Lkn/a;->j:Lkn/l0;

    .line 95
    .line 96
    iget-object v5, v0, Lkn/a;->k:Ls1/e;

    .line 97
    .line 98
    iget-wide v6, v0, Lkn/a;->l:J

    .line 99
    .line 100
    iget-wide v8, v0, Lkn/a;->m:J

    .line 101
    .line 102
    iget v10, v0, Lkn/a;->n:F

    .line 103
    .line 104
    iget-object v11, v0, Lkn/a;->o:Lkn/j0;

    .line 105
    .line 106
    iget-object v12, v0, Lkn/a;->p:Lx2/d;

    .line 107
    .line 108
    iget-object v13, v0, Lkn/a;->q:Lt2/b;

    .line 109
    .line 110
    iget-object v14, v0, Lkn/a;->r:Lt2/b;

    .line 111
    .line 112
    invoke-static/range {v1 .. v17}, Llp/sd;->a(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 113
    .line 114
    .line 115
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    return-object v0

    .line 118
    :pswitch_1
    move-object/from16 v15, p1

    .line 119
    .line 120
    check-cast v15, Ll2/o;

    .line 121
    .line 122
    move-object/from16 v1, p2

    .line 123
    .line 124
    check-cast v1, Ljava/lang/Number;

    .line 125
    .line 126
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 127
    .line 128
    .line 129
    iget v1, v0, Lkn/a;->s:I

    .line 130
    .line 131
    or-int/lit8 v1, v1, 0x1

    .line 132
    .line 133
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 134
    .line 135
    .line 136
    move-result v16

    .line 137
    iget v1, v0, Lkn/a;->t:I

    .line 138
    .line 139
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 140
    .line 141
    .line 142
    move-result v17

    .line 143
    iget-object v1, v0, Lkn/a;->g:Lkn/c0;

    .line 144
    .line 145
    iget-object v2, v0, Lkn/a;->h:Lx2/s;

    .line 146
    .line 147
    iget-boolean v3, v0, Lkn/a;->i:Z

    .line 148
    .line 149
    iget-object v4, v0, Lkn/a;->j:Lkn/l0;

    .line 150
    .line 151
    iget-object v5, v0, Lkn/a;->k:Ls1/e;

    .line 152
    .line 153
    iget-wide v6, v0, Lkn/a;->l:J

    .line 154
    .line 155
    iget-wide v8, v0, Lkn/a;->m:J

    .line 156
    .line 157
    iget v10, v0, Lkn/a;->n:F

    .line 158
    .line 159
    iget-object v11, v0, Lkn/a;->o:Lkn/j0;

    .line 160
    .line 161
    iget-object v12, v0, Lkn/a;->p:Lx2/d;

    .line 162
    .line 163
    iget-object v13, v0, Lkn/a;->q:Lt2/b;

    .line 164
    .line 165
    iget-object v14, v0, Lkn/a;->r:Lt2/b;

    .line 166
    .line 167
    invoke-static/range {v1 .. v17}, Llp/sd;->a(Lkn/c0;Lx2/s;ZLkn/l0;Ls1/e;JJFLkn/j0;Lx2/d;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 168
    .line 169
    .line 170
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    return-object v0

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
