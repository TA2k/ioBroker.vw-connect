.class public final Landroidx/constraintlayout/widget/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:Landroid/util/SparseIntArray;


# instance fields
.field public a:I

.field public b:I

.field public c:I

.field public d:F

.field public e:F

.field public f:F

.field public g:I

.field public h:Ljava/lang/String;

.field public i:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Landroid/util/SparseIntArray;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/util/SparseIntArray;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/constraintlayout/widget/l;->j:Landroid/util/SparseIntArray;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    const/4 v2, 0x1

    .line 10
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->append(II)V

    .line 11
    .line 12
    .line 13
    const/4 v3, 0x5

    .line 14
    const/4 v4, 0x2

    .line 15
    invoke-virtual {v0, v3, v4}, Landroid/util/SparseIntArray;->append(II)V

    .line 16
    .line 17
    .line 18
    const/16 v5, 0x9

    .line 19
    .line 20
    invoke-virtual {v0, v5, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 21
    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    invoke-virtual {v0, v4, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->append(II)V

    .line 28
    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    const/4 v3, 0x6

    .line 32
    invoke-virtual {v0, v2, v3}, Landroid/util/SparseIntArray;->append(II)V

    .line 33
    .line 34
    .line 35
    const/4 v2, 0x7

    .line 36
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseIntArray;->append(II)V

    .line 37
    .line 38
    .line 39
    const/16 v1, 0x8

    .line 40
    .line 41
    invoke-virtual {v0, v1, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, v2, v5}, Landroid/util/SparseIntArray;->append(II)V

    .line 45
    .line 46
    .line 47
    const/16 v1, 0xa

    .line 48
    .line 49
    invoke-virtual {v0, v3, v1}, Landroid/util/SparseIntArray;->append(II)V

    .line 50
    .line 51
    .line 52
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 7

    .line 1
    sget-object v0, Landroidx/constraintlayout/widget/s;->f:[I

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
    move v1, v0

    .line 13
    :goto_0
    if-ge v1, p2, :cond_4

    .line 14
    .line 15
    invoke-virtual {p1, v1}, Landroid/content/res/TypedArray;->getIndex(I)I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    sget-object v3, Landroidx/constraintlayout/widget/l;->j:Landroid/util/SparseIntArray;

    .line 20
    .line 21
    invoke-virtual {v3, v2}, Landroid/util/SparseIntArray;->get(I)I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    const/4 v4, 0x3

    .line 26
    packed-switch v3, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    goto/16 :goto_1

    .line 30
    .line 31
    :pswitch_0
    invoke-virtual {p1, v2}, Landroid/content/res/TypedArray;->peekValue(I)Landroid/util/TypedValue;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    iget v3, v3, Landroid/util/TypedValue;->type:I

    .line 36
    .line 37
    const/4 v5, -0x1

    .line 38
    const/4 v6, 0x1

    .line 39
    if-ne v3, v6, :cond_0

    .line 40
    .line 41
    invoke-virtual {p1, v2, v5}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    iput v2, p0, Landroidx/constraintlayout/widget/l;->i:I

    .line 46
    .line 47
    goto/16 :goto_1

    .line 48
    .line 49
    :cond_0
    if-ne v3, v4, :cond_1

    .line 50
    .line 51
    invoke-virtual {p1, v2}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    iput-object v3, p0, Landroidx/constraintlayout/widget/l;->h:Ljava/lang/String;

    .line 56
    .line 57
    const-string v4, "/"

    .line 58
    .line 59
    invoke-virtual {v3, v4}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-lez v3, :cond_3

    .line 64
    .line 65
    invoke-virtual {p1, v2, v5}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    iput v2, p0, Landroidx/constraintlayout/widget/l;->i:I

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_1
    iget v3, p0, Landroidx/constraintlayout/widget/l;->i:I

    .line 73
    .line 74
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :pswitch_1
    iget v3, p0, Landroidx/constraintlayout/widget/l;->f:F

    .line 79
    .line 80
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    iput v2, p0, Landroidx/constraintlayout/widget/l;->f:F

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :pswitch_2
    iget v3, p0, Landroidx/constraintlayout/widget/l;->g:I

    .line 88
    .line 89
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    iput v2, p0, Landroidx/constraintlayout/widget/l;->g:I

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :pswitch_3
    iget v3, p0, Landroidx/constraintlayout/widget/l;->d:F

    .line 97
    .line 98
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    iput v2, p0, Landroidx/constraintlayout/widget/l;->d:F

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :pswitch_4
    iget v3, p0, Landroidx/constraintlayout/widget/l;->b:I

    .line 106
    .line 107
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    iput v2, p0, Landroidx/constraintlayout/widget/l;->b:I

    .line 112
    .line 113
    goto :goto_1

    .line 114
    :pswitch_5
    iget v3, p0, Landroidx/constraintlayout/widget/l;->a:I

    .line 115
    .line 116
    invoke-static {p1, v2, v3}, Landroidx/constraintlayout/widget/o;->f(Landroid/content/res/TypedArray;II)I

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    iput v2, p0, Landroidx/constraintlayout/widget/l;->a:I

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :pswitch_6
    invoke-virtual {p1, v2, v0}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 124
    .line 125
    .line 126
    goto :goto_1

    .line 127
    :pswitch_7
    invoke-virtual {p1, v2}, Landroid/content/res/TypedArray;->peekValue(I)Landroid/util/TypedValue;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    iget v3, v3, Landroid/util/TypedValue;->type:I

    .line 132
    .line 133
    if-ne v3, v4, :cond_2

    .line 134
    .line 135
    invoke-virtual {p1, v2}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_2
    sget-object v3, Lc5/a;->a:[Ljava/lang/String;

    .line 140
    .line 141
    invoke-virtual {p1, v2, v0}, Landroid/content/res/TypedArray;->getInteger(II)I

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    aget-object v2, v3, v2

    .line 146
    .line 147
    goto :goto_1

    .line 148
    :pswitch_8
    iget v3, p0, Landroidx/constraintlayout/widget/l;->c:I

    .line 149
    .line 150
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    iput v2, p0, Landroidx/constraintlayout/widget/l;->c:I

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :pswitch_9
    iget v3, p0, Landroidx/constraintlayout/widget/l;->e:F

    .line 158
    .line 159
    invoke-virtual {p1, v2, v3}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    iput v2, p0, Landroidx/constraintlayout/widget/l;->e:F

    .line 164
    .line 165
    :cond_3
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 166
    .line 167
    goto/16 :goto_0

    .line 168
    .line 169
    :cond_4
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 170
    .line 171
    .line 172
    return-void

    .line 173
    :pswitch_data_0
    .packed-switch 0x1
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
