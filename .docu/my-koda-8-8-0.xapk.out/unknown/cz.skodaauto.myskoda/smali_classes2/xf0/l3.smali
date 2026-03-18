.class public final synthetic Lxf0/l3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Le3/s;

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:F


# direct methods
.method public synthetic constructor <init>(ZLe3/s;FFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lxf0/l3;->d:Z

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/l3;->e:Le3/s;

    .line 7
    .line 8
    iput p3, p0, Lxf0/l3;->f:F

    .line 9
    .line 10
    iput p4, p0, Lxf0/l3;->g:F

    .line 11
    .line 12
    iput p5, p0, Lxf0/l3;->h:F

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    const-string v2, "$this$drawBaseGauge"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-boolean v2, v0, Lxf0/l3;->d:Z

    .line 13
    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    iget-object v2, v0, Lxf0/l3;->e:Le3/s;

    .line 17
    .line 18
    iget-wide v2, v2, Le3/s;->a:J

    .line 19
    .line 20
    const/4 v4, 0x2

    .line 21
    int-to-float v4, v4

    .line 22
    iget v6, v0, Lxf0/l3;->f:F

    .line 23
    .line 24
    div-float v5, v6, v4

    .line 25
    .line 26
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    int-to-long v7, v7

    .line 31
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    int-to-long v9, v5

    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    shl-long/2addr v7, v5

    .line 39
    const-wide v11, 0xffffffffL

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    and-long/2addr v9, v11

    .line 45
    or-long v13, v7, v9

    .line 46
    .line 47
    iget v7, v0, Lxf0/l3;->g:F

    .line 48
    .line 49
    mul-float/2addr v7, v4

    .line 50
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    int-to-long v8, v4

    .line 55
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    move/from16 p1, v5

    .line 60
    .line 61
    move v7, v6

    .line 62
    int-to-long v5, v4

    .line 63
    shl-long v8, v8, p1

    .line 64
    .line 65
    and-long v4, v5, v11

    .line 66
    .line 67
    or-long v15, v8, v4

    .line 68
    .line 69
    new-instance v5, Lg3/h;

    .line 70
    .line 71
    const/4 v10, 0x0

    .line 72
    const/16 v11, 0x1a

    .line 73
    .line 74
    move v6, v7

    .line 75
    const/4 v7, 0x0

    .line 76
    const/4 v8, 0x0

    .line 77
    const/4 v9, 0x0

    .line 78
    invoke-direct/range {v5 .. v11}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 79
    .line 80
    .line 81
    const/4 v9, 0x0

    .line 82
    const/16 v11, 0x340

    .line 83
    .line 84
    move-object v4, v1

    .line 85
    move-wide v1, v2

    .line 86
    const/high16 v3, -0x3d4c0000    # -90.0f

    .line 87
    .line 88
    iget v0, v0, Lxf0/l3;->h:F

    .line 89
    .line 90
    move-object v6, v4

    .line 91
    move v4, v0

    .line 92
    move-object v0, v6

    .line 93
    move-object v10, v5

    .line 94
    move-wide v5, v13

    .line 95
    move-wide v7, v15

    .line 96
    invoke-static/range {v0 .. v11}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 97
    .line 98
    .line 99
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object v0
.end method
