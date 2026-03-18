.class public final Lw3/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/graphics/Matrix;

.field public final b:[I


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Matrix;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lw3/a1;->a:Landroid/graphics/Matrix;

    .line 10
    .line 11
    const/4 v0, 0x2

    .line 12
    new-array v0, v0, [I

    .line 13
    .line 14
    iput-object v0, p0, Lw3/a1;->b:[I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public a(Landroid/view/View;[F)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v0, Lw3/a1;->a:Landroid/graphics/Matrix;

    .line 6
    .line 7
    invoke-virtual {v2}, Landroid/graphics/Matrix;->reset()V

    .line 8
    .line 9
    .line 10
    move-object/from16 v3, p1

    .line 11
    .line 12
    invoke-virtual {v3, v2}, Landroid/view/View;->transformMatrixToGlobal(Landroid/graphics/Matrix;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v3}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    :goto_0
    instance-of v5, v4, Landroid/view/View;

    .line 20
    .line 21
    if-eqz v5, :cond_0

    .line 22
    .line 23
    move-object v3, v4

    .line 24
    check-cast v3, Landroid/view/View;

    .line 25
    .line 26
    invoke-virtual {v3}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object v0, v0, Lw3/a1;->b:[I

    .line 32
    .line 33
    invoke-virtual {v3, v0}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 34
    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    aget v5, v0, v4

    .line 38
    .line 39
    const/4 v6, 0x1

    .line 40
    aget v7, v0, v6

    .line 41
    .line 42
    invoke-virtual {v3, v0}, Landroid/view/View;->getLocationInWindow([I)V

    .line 43
    .line 44
    .line 45
    aget v3, v0, v4

    .line 46
    .line 47
    aget v0, v0, v6

    .line 48
    .line 49
    sub-int/2addr v3, v5

    .line 50
    int-to-float v3, v3

    .line 51
    sub-int/2addr v0, v7

    .line 52
    int-to-float v0, v0

    .line 53
    invoke-virtual {v2, v3, v0}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2, v1}, Landroid/graphics/Matrix;->getValues([F)V

    .line 57
    .line 58
    .line 59
    const/4 v0, 0x0

    .line 60
    aget v2, v1, v0

    .line 61
    .line 62
    const/4 v3, 0x1

    .line 63
    aget v4, v1, v3

    .line 64
    .line 65
    const/4 v5, 0x2

    .line 66
    aget v6, v1, v5

    .line 67
    .line 68
    const/4 v7, 0x3

    .line 69
    aget v8, v1, v7

    .line 70
    .line 71
    const/4 v9, 0x4

    .line 72
    aget v10, v1, v9

    .line 73
    .line 74
    const/4 v11, 0x5

    .line 75
    aget v12, v1, v11

    .line 76
    .line 77
    const/4 v13, 0x6

    .line 78
    aget v14, v1, v13

    .line 79
    .line 80
    const/4 v15, 0x7

    .line 81
    aget v16, v1, v15

    .line 82
    .line 83
    const/16 v17, 0x8

    .line 84
    .line 85
    aget v18, v1, v17

    .line 86
    .line 87
    aput v2, v1, v0

    .line 88
    .line 89
    aput v8, v1, v3

    .line 90
    .line 91
    const/4 v0, 0x0

    .line 92
    aput v0, v1, v5

    .line 93
    .line 94
    aput v14, v1, v7

    .line 95
    .line 96
    aput v4, v1, v9

    .line 97
    .line 98
    aput v10, v1, v11

    .line 99
    .line 100
    aput v0, v1, v13

    .line 101
    .line 102
    aput v16, v1, v15

    .line 103
    .line 104
    aput v0, v1, v17

    .line 105
    .line 106
    const/16 v2, 0x9

    .line 107
    .line 108
    aput v0, v1, v2

    .line 109
    .line 110
    const/16 v2, 0xa

    .line 111
    .line 112
    const/high16 v3, 0x3f800000    # 1.0f

    .line 113
    .line 114
    aput v3, v1, v2

    .line 115
    .line 116
    const/16 v2, 0xb

    .line 117
    .line 118
    aput v0, v1, v2

    .line 119
    .line 120
    const/16 v2, 0xc

    .line 121
    .line 122
    aput v6, v1, v2

    .line 123
    .line 124
    const/16 v2, 0xd

    .line 125
    .line 126
    aput v12, v1, v2

    .line 127
    .line 128
    const/16 v2, 0xe

    .line 129
    .line 130
    aput v0, v1, v2

    .line 131
    .line 132
    const/16 v0, 0xf

    .line 133
    .line 134
    aput v18, v1, v0

    .line 135
    .line 136
    return-void
.end method
