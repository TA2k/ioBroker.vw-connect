.class public final synthetic Li40/c3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 1
    iput p3, p0, Li40/c3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/c3;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, Li40/c3;->e:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/c3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li40/c3;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ltz/x0;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Landroidx/compose/foundation/lazy/a;

    .line 15
    .line 16
    move-object/from16 v3, p2

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-object/from16 v3, p3

    .line 24
    .line 25
    check-cast v3, Ll2/o;

    .line 26
    .line 27
    move-object/from16 v4, p4

    .line 28
    .line 29
    check-cast v4, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    const-string v5, "$this$stickyHeader"

    .line 36
    .line 37
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    and-int/lit16 v2, v4, 0x81

    .line 41
    .line 42
    const/16 v5, 0x80

    .line 43
    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v7, 0x1

    .line 46
    if-eq v2, v5, :cond_0

    .line 47
    .line 48
    move v2, v7

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    move v2, v6

    .line 51
    :goto_0
    and-int/2addr v4, v7

    .line 52
    check-cast v3, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {v3, v4, v2}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_1

    .line 59
    .line 60
    iget v0, v0, Li40/c3;->e:I

    .line 61
    .line 62
    invoke-static {v1, v0, v3, v6}, Luz/t;->r(Ltz/x0;ILl2/o;I)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 67
    .line 68
    .line 69
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object v0

    .line 72
    :pswitch_0
    iget-object v1, v0, Li40/c3;->f:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Ljava/util/List;

    .line 75
    .line 76
    move-object/from16 v2, p1

    .line 77
    .line 78
    check-cast v2, Lp1/p;

    .line 79
    .line 80
    move-object/from16 v3, p2

    .line 81
    .line 82
    check-cast v3, Ljava/lang/Integer;

    .line 83
    .line 84
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    move-object/from16 v15, p3

    .line 89
    .line 90
    check-cast v15, Ll2/o;

    .line 91
    .line 92
    move-object/from16 v4, p4

    .line 93
    .line 94
    check-cast v4, Ljava/lang/Integer;

    .line 95
    .line 96
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    const-string v4, "$this$HorizontalPager"

    .line 100
    .line 101
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 105
    .line 106
    const/high16 v4, 0x3f800000    # 1.0f

    .line 107
    .line 108
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    move-object v4, v1

    .line 117
    check-cast v4, Landroid/net/Uri;

    .line 118
    .line 119
    new-instance v1, Ldl0/f;

    .line 120
    .line 121
    const/4 v2, 0x1

    .line 122
    const/4 v3, 0x0

    .line 123
    iget v0, v0, Li40/c3;->e:I

    .line 124
    .line 125
    invoke-direct {v1, v0, v2, v3}, Ldl0/f;-><init>(IIB)V

    .line 126
    .line 127
    .line 128
    const v2, 0x1a44a330

    .line 129
    .line 130
    .line 131
    invoke-static {v2, v15, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 132
    .line 133
    .line 134
    move-result-object v13

    .line 135
    new-instance v1, Ldl0/f;

    .line 136
    .line 137
    const/4 v2, 0x2

    .line 138
    invoke-direct {v1, v0, v2, v3}, Ldl0/f;-><init>(IIB)V

    .line 139
    .line 140
    .line 141
    const v0, 0x7e39fb8f

    .line 142
    .line 143
    .line 144
    invoke-static {v0, v15, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 145
    .line 146
    .line 147
    move-result-object v14

    .line 148
    const/16 v17, 0x6c06

    .line 149
    .line 150
    const/16 v18, 0x1bfc

    .line 151
    .line 152
    const/4 v6, 0x0

    .line 153
    const/4 v7, 0x0

    .line 154
    const/4 v8, 0x0

    .line 155
    const/4 v9, 0x0

    .line 156
    const/4 v10, 0x0

    .line 157
    sget-object v11, Lt3/j;->b:Lt3/x0;

    .line 158
    .line 159
    const/4 v12, 0x0

    .line 160
    const/16 v16, 0x30

    .line 161
    .line 162
    invoke-static/range {v4 .. v18}, Lxf0/i0;->F(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;Ll2/o;III)V

    .line 163
    .line 164
    .line 165
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object v0

    .line 168
    nop

    .line 169
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
