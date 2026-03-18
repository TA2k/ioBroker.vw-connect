.class public final Lh2/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/m0;

.field public final synthetic e:Lt2/b;

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Z

.field public final synthetic i:Le3/n0;

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:F

.field public final synthetic m:F

.field public final synthetic n:Lay0/n;

.field public final synthetic o:Lt2/b;

.field public final synthetic p:Lay0/o;


# direct methods
.method public constructor <init>(Lh2/m0;Lt2/b;FFZLe3/n0;JJFFLay0/n;Lt2/b;Lay0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/d0;->d:Lh2/m0;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/d0;->e:Lt2/b;

    .line 7
    .line 8
    iput p3, p0, Lh2/d0;->f:F

    .line 9
    .line 10
    iput p4, p0, Lh2/d0;->g:F

    .line 11
    .line 12
    iput-boolean p5, p0, Lh2/d0;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Lh2/d0;->i:Le3/n0;

    .line 15
    .line 16
    iput-wide p7, p0, Lh2/d0;->j:J

    .line 17
    .line 18
    iput-wide p9, p0, Lh2/d0;->k:J

    .line 19
    .line 20
    iput p11, p0, Lh2/d0;->l:F

    .line 21
    .line 22
    iput p12, p0, Lh2/d0;->m:F

    .line 23
    .line 24
    iput-object p13, p0, Lh2/d0;->n:Lay0/n;

    .line 25
    .line 26
    iput-object p14, p0, Lh2/d0;->o:Lt2/b;

    .line 27
    .line 28
    iput-object p15, p0, Lh2/d0;->p:Lay0/o;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

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
    const/4 v5, 0x1

    .line 19
    if-eq v3, v4, :cond_0

    .line 20
    .line 21
    move v3, v5

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v3, 0x0

    .line 24
    :goto_0
    and-int/2addr v2, v5

    .line 25
    move-object v9, v1

    .line 26
    check-cast v9, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v9, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    iget-object v1, v0, Lh2/d0;->d:Lh2/m0;

    .line 35
    .line 36
    iget-object v8, v1, Lh2/m0;->a:Lh2/r8;

    .line 37
    .line 38
    new-instance v2, Lh2/b0;

    .line 39
    .line 40
    iget-object v3, v0, Lh2/d0;->e:Lt2/b;

    .line 41
    .line 42
    iget v4, v0, Lh2/d0;->f:F

    .line 43
    .line 44
    invoke-direct {v2, v3, v4}, Lh2/b0;-><init>(Lt2/b;F)V

    .line 45
    .line 46
    .line 47
    const v3, -0x1ef8305a

    .line 48
    .line 49
    .line 50
    invoke-static {v3, v9, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    new-instance v10, Lh2/c0;

    .line 55
    .line 56
    iget-object v2, v0, Lh2/d0;->n:Lay0/n;

    .line 57
    .line 58
    iget-object v3, v0, Lh2/d0;->o:Lt2/b;

    .line 59
    .line 60
    iget-object v11, v0, Lh2/d0;->d:Lh2/m0;

    .line 61
    .line 62
    iget v12, v0, Lh2/d0;->f:F

    .line 63
    .line 64
    iget v13, v0, Lh2/d0;->g:F

    .line 65
    .line 66
    iget-boolean v14, v0, Lh2/d0;->h:Z

    .line 67
    .line 68
    iget-object v15, v0, Lh2/d0;->i:Le3/n0;

    .line 69
    .line 70
    iget-wide v5, v0, Lh2/d0;->j:J

    .line 71
    .line 72
    move-object/from16 v22, v2

    .line 73
    .line 74
    move-object/from16 v23, v3

    .line 75
    .line 76
    iget-wide v2, v0, Lh2/d0;->k:J

    .line 77
    .line 78
    iget v7, v0, Lh2/d0;->l:F

    .line 79
    .line 80
    move-wide/from16 v18, v2

    .line 81
    .line 82
    iget v2, v0, Lh2/d0;->m:F

    .line 83
    .line 84
    move/from16 v21, v2

    .line 85
    .line 86
    move-wide/from16 v16, v5

    .line 87
    .line 88
    move/from16 v20, v7

    .line 89
    .line 90
    invoke-direct/range {v10 .. v23}, Lh2/c0;-><init>(Lh2/m0;FFZLe3/n0;JJFFLay0/n;Lt2/b;)V

    .line 91
    .line 92
    .line 93
    const v2, -0x309d717b

    .line 94
    .line 95
    .line 96
    invoke-static {v2, v9, v10}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 97
    .line 98
    .line 99
    move-result-object v5

    .line 100
    new-instance v2, Laa/p;

    .line 101
    .line 102
    iget-object v0, v0, Lh2/d0;->p:Lay0/o;

    .line 103
    .line 104
    const/4 v3, 0x3

    .line 105
    invoke-direct {v2, v3, v0, v1}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    const v0, -0x4242b29c

    .line 109
    .line 110
    .line 111
    invoke-static {v0, v9, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    if-nez v0, :cond_1

    .line 124
    .line 125
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 126
    .line 127
    if-ne v2, v0, :cond_2

    .line 128
    .line 129
    :cond_1
    new-instance v2, Ld2/g;

    .line 130
    .line 131
    const/16 v0, 0x16

    .line 132
    .line 133
    invoke-direct {v2, v1, v0}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v9, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    :cond_2
    move-object v7, v2

    .line 140
    check-cast v7, Lay0/a;

    .line 141
    .line 142
    const/16 v10, 0xdb0

    .line 143
    .line 144
    invoke-static/range {v4 .. v10}, Lh2/r;->c(Lt2/b;Lt2/b;Lt2/b;Lay0/a;Lh2/r8;Ll2/o;I)V

    .line 145
    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_3
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 149
    .line 150
    .line 151
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 152
    .line 153
    return-object v0
.end method
