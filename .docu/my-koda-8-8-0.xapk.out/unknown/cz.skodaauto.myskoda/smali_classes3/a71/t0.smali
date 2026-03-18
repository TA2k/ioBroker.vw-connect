.class public final synthetic La71/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, La71/t0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/t0;->e:Lx2/s;

    iput-object p2, p0, La71/t0;->f:Lay0/a;

    iput-object p3, p0, La71/t0;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, La71/t0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/t0;->e:Lx2/s;

    iput-object p2, p0, La71/t0;->f:Lay0/a;

    iput-object p3, p0, La71/t0;->g:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La71/t0;->d:I

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
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

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
    move-object v14, v1

    .line 31
    check-cast v14, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    const/high16 v1, 0x3f800000    # 1.0f

    .line 40
    .line 41
    iget-object v2, v0, La71/t0;->e:Lx2/s;

    .line 42
    .line 43
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    const/4 v1, 0x4

    .line 48
    int-to-float v1, v1

    .line 49
    invoke-static {v1}, Ls1/f;->b(F)Ls1/e;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 54
    .line 55
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    check-cast v2, Lj91/e;

    .line 60
    .line 61
    invoke-virtual {v2}, Lj91/e;->i()J

    .line 62
    .line 63
    .line 64
    move-result-wide v6

    .line 65
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    check-cast v1, Lj91/e;

    .line 70
    .line 71
    invoke-virtual {v1}, Lj91/e;->q()J

    .line 72
    .line 73
    .line 74
    move-result-wide v8

    .line 75
    new-instance v1, Lbf/b;

    .line 76
    .line 77
    const/16 v2, 0xc

    .line 78
    .line 79
    iget-object v3, v0, La71/t0;->f:Lay0/a;

    .line 80
    .line 81
    iget-object v0, v0, La71/t0;->g:Lay0/a;

    .line 82
    .line 83
    invoke-direct {v1, v3, v0, v2}, Lbf/b;-><init>(Lay0/a;Lay0/a;I)V

    .line 84
    .line 85
    .line 86
    const v0, 0x27384416

    .line 87
    .line 88
    .line 89
    invoke-static {v0, v14, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 90
    .line 91
    .line 92
    move-result-object v13

    .line 93
    const/high16 v15, 0xc00000

    .line 94
    .line 95
    const/16 v16, 0x70

    .line 96
    .line 97
    const/4 v10, 0x0

    .line 98
    const/4 v11, 0x0

    .line 99
    const/4 v12, 0x0

    .line 100
    invoke-static/range {v4 .. v16}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_1
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 105
    .line 106
    .line 107
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object v0

    .line 110
    :pswitch_0
    move-object/from16 v1, p1

    .line 111
    .line 112
    check-cast v1, Ll2/o;

    .line 113
    .line 114
    move-object/from16 v2, p2

    .line 115
    .line 116
    check-cast v2, Ljava/lang/Integer;

    .line 117
    .line 118
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    const/4 v2, 0x1

    .line 122
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    iget-object v3, v0, La71/t0;->e:Lx2/s;

    .line 127
    .line 128
    iget-object v4, v0, La71/t0;->f:Lay0/a;

    .line 129
    .line 130
    iget-object v0, v0, La71/t0;->g:Lay0/a;

    .line 131
    .line 132
    invoke-static {v3, v4, v0, v1, v2}, La71/b;->o(Lx2/s;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 133
    .line 134
    .line 135
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    return-object v0

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
