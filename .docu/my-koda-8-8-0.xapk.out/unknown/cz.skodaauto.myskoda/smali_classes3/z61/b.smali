.class public final synthetic Lz61/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field public final synthetic j:J

.field public final synthetic k:Z


# direct methods
.method public synthetic constructor <init>(ZZZLay0/a;Lay0/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;JZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lz61/b;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lz61/b;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lz61/b;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lz61/b;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lz61/b;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lz61/b;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 15
    .line 16
    iput-wide p7, p0, Lz61/b;->j:J

    .line 17
    .line 18
    iput-boolean p9, p0, Lz61/b;->k:Z

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/t;

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
    const-string v4, "$this$RpaScaffold"

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
    if-eq v4, v5, :cond_2

    .line 47
    .line 48
    move v4, v6

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    const/4 v4, 0x0

    .line 51
    :goto_1
    and-int/2addr v3, v6

    .line 52
    move-object v8, v2

    .line 53
    check-cast v8, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v8, v3, v4}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_3

    .line 60
    .line 61
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 62
    .line 63
    const/high16 v3, 0x3f800000    # 1.0f

    .line 64
    .line 65
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-static {v1, v2}, Lk1/t;->c(Lk1/t;Lx2/s;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    new-instance v9, Lz61/d;

    .line 74
    .line 75
    iget-boolean v10, v0, Lz61/b;->d:Z

    .line 76
    .line 77
    iget-boolean v11, v0, Lz61/b;->e:Z

    .line 78
    .line 79
    iget-boolean v12, v0, Lz61/b;->f:Z

    .line 80
    .line 81
    iget-object v13, v0, Lz61/b;->g:Lay0/a;

    .line 82
    .line 83
    iget-object v14, v0, Lz61/b;->h:Lay0/a;

    .line 84
    .line 85
    iget-object v15, v0, Lz61/b;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 86
    .line 87
    iget-wide v1, v0, Lz61/b;->j:J

    .line 88
    .line 89
    move-wide/from16 v16, v1

    .line 90
    .line 91
    invoke-direct/range {v9 .. v17}, Lz61/d;-><init>(ZZZLay0/a;Lay0/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;J)V

    .line 92
    .line 93
    .line 94
    const v1, -0x57d57223

    .line 95
    .line 96
    .line 97
    invoke-static {v1, v8, v9}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    new-instance v1, Lz61/e;

    .line 102
    .line 103
    iget-boolean v0, v0, Lz61/b;->k:Z

    .line 104
    .line 105
    invoke-direct {v1, v10, v0}, Lz61/e;-><init>(ZZ)V

    .line 106
    .line 107
    .line 108
    const v0, 0x405253fc    # 3.286376f

    .line 109
    .line 110
    .line 111
    invoke-static {v0, v8, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    const/16 v9, 0x1b0

    .line 116
    .line 117
    const/4 v10, 0x0

    .line 118
    invoke-static/range {v5 .. v10}, Lc71/a;->a(Lx2/s;Lay0/o;Lt2/b;Ll2/o;II)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_3
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    return-object v0
.end method
