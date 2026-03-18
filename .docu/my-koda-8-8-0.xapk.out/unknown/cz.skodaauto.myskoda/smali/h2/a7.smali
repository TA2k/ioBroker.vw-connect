.class public final Lh2/a7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Ll4/v;

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ll4/d0;

.field public final synthetic h:Li1/l;

.field public final synthetic i:Z

.field public final synthetic j:Lay0/n;

.field public final synthetic k:Lay0/n;

.field public final synthetic l:Lay0/n;

.field public final synthetic m:Lh2/eb;

.field public final synthetic n:Le3/n0;


# direct methods
.method public constructor <init>(Ll4/v;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Lay0/n;Lh2/eb;Le3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/a7;->d:Ll4/v;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/a7;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/a7;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lh2/a7;->g:Ll4/d0;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/a7;->h:Li1/l;

    .line 13
    .line 14
    iput-boolean p6, p0, Lh2/a7;->i:Z

    .line 15
    .line 16
    iput-object p7, p0, Lh2/a7;->j:Lay0/n;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/a7;->k:Lay0/n;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/a7;->l:Lay0/n;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/a7;->m:Lh2/eb;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/a7;->n:Le3/n0;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    check-cast v2, Lay0/n;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    and-int/lit8 v4, v3, 0x6

    .line 20
    .line 21
    if-nez v4, :cond_1

    .line 22
    .line 23
    move-object v4, v1

    .line 24
    check-cast v4, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_0

    .line 31
    .line 32
    const/4 v4, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v4, 0x2

    .line 35
    :goto_0
    or-int/2addr v3, v4

    .line 36
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 37
    .line 38
    const/16 v5, 0x12

    .line 39
    .line 40
    if-eq v4, v5, :cond_2

    .line 41
    .line 42
    const/4 v4, 0x1

    .line 43
    goto :goto_1

    .line 44
    :cond_2
    const/4 v4, 0x0

    .line 45
    :goto_1
    and-int/lit8 v5, v3, 0x1

    .line 46
    .line 47
    move-object v14, v1

    .line 48
    check-cast v14, Ll2/t;

    .line 49
    .line 50
    invoke-virtual {v14, v5, v4}, Ll2/t;->O(IZ)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_3

    .line 55
    .line 56
    sget-object v1, Lh2/v6;->a:Lh2/v6;

    .line 57
    .line 58
    iget-object v4, v0, Lh2/a7;->d:Ll4/v;

    .line 59
    .line 60
    iget-object v4, v4, Ll4/v;->a:Lg4/g;

    .line 61
    .line 62
    iget-object v4, v4, Lg4/g;->e:Ljava/lang/String;

    .line 63
    .line 64
    new-instance v5, Lh2/z6;

    .line 65
    .line 66
    iget-object v10, v0, Lh2/a7;->n:Le3/n0;

    .line 67
    .line 68
    const/4 v11, 0x0

    .line 69
    iget-boolean v6, v0, Lh2/a7;->e:Z

    .line 70
    .line 71
    iget-boolean v7, v0, Lh2/a7;->i:Z

    .line 72
    .line 73
    iget-object v8, v0, Lh2/a7;->h:Li1/l;

    .line 74
    .line 75
    iget-object v9, v0, Lh2/a7;->m:Lh2/eb;

    .line 76
    .line 77
    invoke-direct/range {v5 .. v11}, Lh2/z6;-><init>(ZZLi1/l;Lh2/eb;Le3/n0;I)V

    .line 78
    .line 79
    .line 80
    const v10, 0x53ffaf45

    .line 81
    .line 82
    .line 83
    invoke-static {v10, v14, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 84
    .line 85
    .line 86
    move-result-object v13

    .line 87
    shl-int/lit8 v3, v3, 0x3

    .line 88
    .line 89
    and-int/lit8 v15, v3, 0x70

    .line 90
    .line 91
    move-object v3, v1

    .line 92
    move-object v1, v4

    .line 93
    iget-boolean v4, v0, Lh2/a7;->f:Z

    .line 94
    .line 95
    iget-object v5, v0, Lh2/a7;->g:Ll4/d0;

    .line 96
    .line 97
    move-object v10, v3

    .line 98
    move v3, v6

    .line 99
    move-object v6, v8

    .line 100
    iget-object v8, v0, Lh2/a7;->j:Lay0/n;

    .line 101
    .line 102
    move-object v11, v9

    .line 103
    iget-object v9, v0, Lh2/a7;->k:Lay0/n;

    .line 104
    .line 105
    iget-object v0, v0, Lh2/a7;->l:Lay0/n;

    .line 106
    .line 107
    const/4 v12, 0x0

    .line 108
    move-object/from16 v16, v10

    .line 109
    .line 110
    move-object v10, v0

    .line 111
    move-object/from16 v0, v16

    .line 112
    .line 113
    invoke-virtual/range {v0 .. v15}, Lh2/v6;->b(Ljava/lang/String;Lay0/n;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Lay0/n;Lh2/eb;Lk1/z0;Lt2/b;Ll2/o;I)V

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 118
    .line 119
    .line 120
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object v0
.end method
