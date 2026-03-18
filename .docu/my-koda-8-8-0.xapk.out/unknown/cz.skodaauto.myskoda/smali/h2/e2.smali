.class public final Lh2/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Le3/n0;

.field public final synthetic e:Lh2/z1;

.field public final synthetic f:F

.field public final synthetic g:Lt2/b;

.field public final synthetic h:Lt2/b;


# direct methods
.method public constructor <init>(Le3/n0;Lh2/z1;FLt2/b;Lt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/e2;->d:Le3/n0;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/e2;->e:Lh2/z1;

    .line 7
    .line 8
    iput p3, p0, Lh2/e2;->f:F

    .line 9
    .line 10
    iput-object p4, p0, Lh2/e2;->g:Lt2/b;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/e2;->h:Lt2/b;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

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
    sget v2, Lk2/m;->d:F

    .line 34
    .line 35
    invoke-static {v2}, Landroidx/compose/foundation/layout/d;->m(F)Lx2/s;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    const/4 v3, 0x0

    .line 40
    sget v4, Lk2/m;->b:F

    .line 41
    .line 42
    invoke-static {v2, v3, v4, v5}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    .line 43
    .line 44
    .line 45
    move-result-object v6

    .line 46
    iget-object v2, v0, Lh2/e2;->e:Lh2/z1;

    .line 47
    .line 48
    iget-wide v8, v2, Lh2/z1;->a:J

    .line 49
    .line 50
    new-instance v2, Laa/p;

    .line 51
    .line 52
    iget-object v3, v0, Lh2/e2;->h:Lt2/b;

    .line 53
    .line 54
    const/4 v4, 0x4

    .line 55
    iget-object v5, v0, Lh2/e2;->g:Lt2/b;

    .line 56
    .line 57
    invoke-direct {v2, v4, v5, v3}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const v3, 0x6a376592

    .line 61
    .line 62
    .line 63
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 64
    .line 65
    .line 66
    move-result-object v15

    .line 67
    const v17, 0xc00006

    .line 68
    .line 69
    .line 70
    const/16 v18, 0x68

    .line 71
    .line 72
    iget-object v7, v0, Lh2/e2;->d:Le3/n0;

    .line 73
    .line 74
    const-wide/16 v10, 0x0

    .line 75
    .line 76
    iget v12, v0, Lh2/e2;->f:F

    .line 77
    .line 78
    const/4 v13, 0x0

    .line 79
    const/4 v14, 0x0

    .line 80
    move-object/from16 v16, v1

    .line 81
    .line 82
    invoke-static/range {v6 .. v18}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_1
    move-object/from16 v16, v1

    .line 87
    .line 88
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object v0
.end method
