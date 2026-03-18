.class public final Landroidx/constraintlayout/widget/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Landroid/util/SparseIntArray;


# instance fields
.field public a:F

.field public b:F

.field public c:F

.field public d:F

.field public e:F

.field public f:F

.field public g:F

.field public h:I

.field public i:F

.field public j:F

.field public k:F

.field public l:Z

.field public m:F


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Landroid/util/SparseIntArray;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/constraintlayout/widget/n;->n:Landroid/util/SparseIntArray;

    .line 7
    .line 8
    const/4 v1, 0x6

    .line 9
    const/4 v2, 0x1

    .line 10
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->append(II)V

    .line 11
    .line 12
    .line 13
    const/4 v3, 0x7

    .line 14
    const/4 v4, 0x2

    .line 15
    invoke-virtual {v0, v3, v4}, Landroid/util/SparseIntArray;->append(II)V

    .line 16
    .line 17
    .line 18
    const/16 v5, 0x8

    .line 19
    .line 20
    const/4 v6, 0x3

    .line 21
    invoke-virtual {v0, v5, v6}, Landroid/util/SparseIntArray;->append(II)V

    .line 22
    .line 23
    .line 24
    const/4 v7, 0x4

    .line 25
    invoke-virtual {v0, v7, v7}, Landroid/util/SparseIntArray;->append(II)V

    .line 26
    .line 27
    .line 28
    const/4 v7, 0x5

    .line 29
    invoke-virtual {v0, v7, v7}, Landroid/util/SparseIntArray;->append(II)V

    .line 30
    .line 31
    .line 32
    const/4 v7, 0x0

    .line 33
    invoke-virtual {v0, v7, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->append(II)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, v4, v5}, Landroid/util/SparseIntArray;->append(II)V

    .line 40
    .line 41
    .line 42
    const/16 v1, 0x9

    .line 43
    .line 44
    invoke-virtual {v0, v6, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 45
    .line 46
    .line 47
    const/16 v2, 0xa

    .line 48
    .line 49
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->append(II)V

    .line 50
    .line 51
    .line 52
    const/16 v1, 0xb

    .line 53
    .line 54
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 55
    .line 56
    .line 57
    const/16 v2, 0xc

    .line 58
    .line 59
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->append(II)V

    .line 60
    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 3

    .line 1
    sget-object v0, Landroidx/constraintlayout/widget/s;->i:[I

    .line 2
    .line 3
    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->getIndexCount()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    const/4 v0, 0x0

    .line 12
    :goto_0
    if-ge v0, p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/content/res/TypedArray;->getIndex(I)I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    sget-object v2, Landroidx/constraintlayout/widget/n;->n:Landroid/util/SparseIntArray;

    .line 19
    .line 20
    invoke-virtual {v2, v1}, Landroid/util/SparseIntArray;->get(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    packed-switch v2, :pswitch_data_0

    .line 25
    .line 26
    .line 27
    goto/16 :goto_1

    .line 28
    .line 29
    :pswitch_0
    iget v2, p0, Landroidx/constraintlayout/widget/n;->h:I

    .line 30
    .line 31
    invoke-static {p1, v1, v2}, Landroidx/constraintlayout/widget/o;->f(Landroid/content/res/TypedArray;II)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    iput v1, p0, Landroidx/constraintlayout/widget/n;->h:I

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :pswitch_1
    const/4 v2, 0x1

    .line 39
    iput-boolean v2, p0, Landroidx/constraintlayout/widget/n;->l:Z

    .line 40
    .line 41
    iget v2, p0, Landroidx/constraintlayout/widget/n;->m:F

    .line 42
    .line 43
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    iput v1, p0, Landroidx/constraintlayout/widget/n;->m:F

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :pswitch_2
    iget v2, p0, Landroidx/constraintlayout/widget/n;->k:F

    .line 51
    .line 52
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    iput v1, p0, Landroidx/constraintlayout/widget/n;->k:F

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :pswitch_3
    iget v2, p0, Landroidx/constraintlayout/widget/n;->j:F

    .line 60
    .line 61
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    iput v1, p0, Landroidx/constraintlayout/widget/n;->j:F

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :pswitch_4
    iget v2, p0, Landroidx/constraintlayout/widget/n;->i:F

    .line 69
    .line 70
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    iput v1, p0, Landroidx/constraintlayout/widget/n;->i:F

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :pswitch_5
    iget v2, p0, Landroidx/constraintlayout/widget/n;->g:F

    .line 78
    .line 79
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    iput v1, p0, Landroidx/constraintlayout/widget/n;->g:F

    .line 84
    .line 85
    goto :goto_1

    .line 86
    :pswitch_6
    iget v2, p0, Landroidx/constraintlayout/widget/n;->f:F

    .line 87
    .line 88
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    iput v1, p0, Landroidx/constraintlayout/widget/n;->f:F

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :pswitch_7
    iget v2, p0, Landroidx/constraintlayout/widget/n;->e:F

    .line 96
    .line 97
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    iput v1, p0, Landroidx/constraintlayout/widget/n;->e:F

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :pswitch_8
    iget v2, p0, Landroidx/constraintlayout/widget/n;->d:F

    .line 105
    .line 106
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    iput v1, p0, Landroidx/constraintlayout/widget/n;->d:F

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :pswitch_9
    iget v2, p0, Landroidx/constraintlayout/widget/n;->c:F

    .line 114
    .line 115
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    iput v1, p0, Landroidx/constraintlayout/widget/n;->c:F

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :pswitch_a
    iget v2, p0, Landroidx/constraintlayout/widget/n;->b:F

    .line 123
    .line 124
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    iput v1, p0, Landroidx/constraintlayout/widget/n;->b:F

    .line 129
    .line 130
    goto :goto_1

    .line 131
    :pswitch_b
    iget v2, p0, Landroidx/constraintlayout/widget/n;->a:F

    .line 132
    .line 133
    invoke-virtual {p1, v1, v2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    iput v1, p0, Landroidx/constraintlayout/widget/n;->a:F

    .line 138
    .line 139
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 140
    .line 141
    goto/16 :goto_0

    .line 142
    .line 143
    :cond_0
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 144
    .line 145
    .line 146
    return-void

    .line 147
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
