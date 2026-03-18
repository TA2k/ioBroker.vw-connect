.class public final Lh2/i4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/i4;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh2/i4;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/i4;->a:Lh2/i4;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lh2/r6;Ll2/o;I)V
    .locals 15

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v12, p2

    .line 6
    .line 7
    check-cast v12, Ll2/t;

    .line 8
    .line 9
    const v2, 0x34946814

    .line 10
    .line 11
    .line 12
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/4 v3, 0x2

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    const/4 v2, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v2, v3

    .line 25
    :goto_0
    or-int/2addr v2, v1

    .line 26
    and-int/lit8 v4, v2, 0x3

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    if-eq v4, v3, :cond_1

    .line 30
    .line 31
    move v3, v5

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/4 v3, 0x0

    .line 34
    :goto_1
    and-int/2addr v2, v5

    .line 35
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    iget-wide v4, v0, Lh2/r6;->b:J

    .line 42
    .line 43
    iget-wide v6, v0, Lh2/r6;->c:J

    .line 44
    .line 45
    iget v8, v0, Lh2/r6;->d:F

    .line 46
    .line 47
    iget-object v2, v0, Lh2/r6;->a:Lx2/s;

    .line 48
    .line 49
    new-instance v3, Lal/q;

    .line 50
    .line 51
    const/4 v9, 0x3

    .line 52
    invoke-direct {v3, v0, v9}, Lal/q;-><init>(Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    const v9, 0x76b04459

    .line 56
    .line 57
    .line 58
    invoke-static {v9, v12, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 59
    .line 60
    .line 61
    move-result-object v11

    .line 62
    const/high16 v13, 0xc00000

    .line 63
    .line 64
    const/16 v14, 0x62

    .line 65
    .line 66
    const/4 v3, 0x0

    .line 67
    const/4 v9, 0x0

    .line 68
    const/4 v10, 0x0

    .line 69
    invoke-static/range {v2 .. v14}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 74
    .line 75
    .line 76
    :goto_2
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    if-eqz v2, :cond_3

    .line 81
    .line 82
    new-instance v3, Ld90/m;

    .line 83
    .line 84
    const/16 v4, 0x15

    .line 85
    .line 86
    invoke-direct {v3, v1, v4, p0, v0}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 90
    .line 91
    :cond_3
    return-void
.end method
