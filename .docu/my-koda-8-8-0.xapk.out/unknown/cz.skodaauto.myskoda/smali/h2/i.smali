.class public final Lh2/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/n;

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Le3/n0;

.field public final synthetic g:J

.field public final synthetic h:F

.field public final synthetic i:J

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:Lt2/b;


# direct methods
.method public constructor <init>(Lay0/n;Lay0/n;Le3/n0;JFJJJLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/i;->d:Lay0/n;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/i;->e:Lay0/n;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/i;->f:Le3/n0;

    .line 9
    .line 10
    iput-wide p4, p0, Lh2/i;->g:J

    .line 11
    .line 12
    iput p6, p0, Lh2/i;->h:F

    .line 13
    .line 14
    iput-wide p7, p0, Lh2/i;->i:J

    .line 15
    .line 16
    iput-wide p9, p0, Lh2/i;->j:J

    .line 17
    .line 18
    iput-wide p11, p0, Lh2/i;->k:J

    .line 19
    .line 20
    iput-object p13, p0, Lh2/i;->l:Lt2/b;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

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
    check-cast v1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    new-instance v2, Lf2/c0;

    .line 34
    .line 35
    iget-object v3, v0, Lh2/i;->l:Lt2/b;

    .line 36
    .line 37
    const/4 v4, 0x3

    .line 38
    invoke-direct {v2, v3, v4}, Lf2/c0;-><init>(Lt2/b;I)V

    .line 39
    .line 40
    .line 41
    const v3, 0x51830875

    .line 42
    .line 43
    .line 44
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    sget-object v2, Lk2/n;->a:Lk2/l;

    .line 49
    .line 50
    invoke-static {v2, v1}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 51
    .line 52
    .line 53
    move-result-wide v12

    .line 54
    iget-wide v2, v0, Lh2/i;->k:J

    .line 55
    .line 56
    const/16 v21, 0x6

    .line 57
    .line 58
    iget-object v6, v0, Lh2/i;->d:Lay0/n;

    .line 59
    .line 60
    iget-object v7, v0, Lh2/i;->e:Lay0/n;

    .line 61
    .line 62
    iget-object v8, v0, Lh2/i;->f:Le3/n0;

    .line 63
    .line 64
    iget-wide v9, v0, Lh2/i;->g:J

    .line 65
    .line 66
    iget v11, v0, Lh2/i;->h:F

    .line 67
    .line 68
    iget-wide v14, v0, Lh2/i;->i:J

    .line 69
    .line 70
    move-object/from16 v16, v6

    .line 71
    .line 72
    iget-wide v5, v0, Lh2/i;->j:J

    .line 73
    .line 74
    move-wide/from16 v18, v5

    .line 75
    .line 76
    move-object/from16 v6, v16

    .line 77
    .line 78
    move-wide/from16 v16, v18

    .line 79
    .line 80
    move-object/from16 v20, v1

    .line 81
    .line 82
    move-wide/from16 v18, v2

    .line 83
    .line 84
    const/4 v5, 0x0

    .line 85
    invoke-static/range {v4 .. v21}, Lh2/j;->a(Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JFJJJJLl2/o;I)V

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    move-object/from16 v20, v1

    .line 90
    .line 91
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 92
    .line 93
    .line 94
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object v0
.end method
