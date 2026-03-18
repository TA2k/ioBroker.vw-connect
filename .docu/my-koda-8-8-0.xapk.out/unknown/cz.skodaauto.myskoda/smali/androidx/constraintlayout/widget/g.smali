.class public final Landroidx/constraintlayout/widget/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public final b:F

.field public final c:F

.field public final d:F

.field public final e:I

.field public final f:Landroidx/constraintlayout/widget/o;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/content/res/XmlResourceParser;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x7fc00000    # Float.NaN

    .line 5
    .line 6
    iput v0, p0, Landroidx/constraintlayout/widget/g;->a:F

    .line 7
    .line 8
    iput v0, p0, Landroidx/constraintlayout/widget/g;->b:F

    .line 9
    .line 10
    iput v0, p0, Landroidx/constraintlayout/widget/g;->c:F

    .line 11
    .line 12
    iput v0, p0, Landroidx/constraintlayout/widget/g;->d:F

    .line 13
    .line 14
    const/4 v0, -0x1

    .line 15
    iput v0, p0, Landroidx/constraintlayout/widget/g;->e:I

    .line 16
    .line 17
    invoke-static {p2}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    sget-object v0, Landroidx/constraintlayout/widget/s;->j:[I

    .line 22
    .line 23
    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->getIndexCount()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    const/4 v1, 0x0

    .line 32
    :goto_0
    if-ge v1, v0, :cond_6

    .line 33
    .line 34
    invoke-virtual {p2, v1}, Landroid/content/res/TypedArray;->getIndex(I)I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-nez v2, :cond_0

    .line 39
    .line 40
    iget v3, p0, Landroidx/constraintlayout/widget/g;->e:I

    .line 41
    .line 42
    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    iput v2, p0, Landroidx/constraintlayout/widget/g;->e:I

    .line 47
    .line 48
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-virtual {v3, v2}, Landroid/content/res/Resources;->getResourceTypeName(I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    invoke-virtual {v4, v2}, Landroid/content/res/Resources;->getResourceName(I)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    const-string v4, "layout"

    .line 64
    .line 65
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eqz v3, :cond_5

    .line 70
    .line 71
    new-instance v3, Landroidx/constraintlayout/widget/o;

    .line 72
    .line 73
    invoke-direct {v3}, Landroidx/constraintlayout/widget/o;-><init>()V

    .line 74
    .line 75
    .line 76
    iput-object v3, p0, Landroidx/constraintlayout/widget/g;->f:Landroidx/constraintlayout/widget/o;

    .line 77
    .line 78
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    const/4 v5, 0x0

    .line 83
    invoke-virtual {v4, v2, v5}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    check-cast v2, Landroidx/constraintlayout/widget/ConstraintLayout;

    .line 88
    .line 89
    invoke-virtual {v3, v2}, Landroidx/constraintlayout/widget/o;->b(Landroidx/constraintlayout/widget/ConstraintLayout;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_0
    const/4 v3, 0x1

    .line 94
    if-ne v2, v3, :cond_1

    .line 95
    .line 96
    iget v3, p0, Landroidx/constraintlayout/widget/g;->d:F

    .line 97
    .line 98
    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    iput v2, p0, Landroidx/constraintlayout/widget/g;->d:F

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_1
    const/4 v3, 0x2

    .line 106
    if-ne v2, v3, :cond_2

    .line 107
    .line 108
    iget v3, p0, Landroidx/constraintlayout/widget/g;->b:F

    .line 109
    .line 110
    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    iput v2, p0, Landroidx/constraintlayout/widget/g;->b:F

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_2
    const/4 v3, 0x3

    .line 118
    if-ne v2, v3, :cond_3

    .line 119
    .line 120
    iget v3, p0, Landroidx/constraintlayout/widget/g;->c:F

    .line 121
    .line 122
    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    iput v2, p0, Landroidx/constraintlayout/widget/g;->c:F

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_3
    const/4 v3, 0x4

    .line 130
    if-ne v2, v3, :cond_4

    .line 131
    .line 132
    iget v3, p0, Landroidx/constraintlayout/widget/g;->a:F

    .line 133
    .line 134
    invoke-virtual {p2, v2, v3}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    iput v2, p0, Landroidx/constraintlayout/widget/g;->a:F

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_4
    const-string v2, "ConstraintLayoutStates"

    .line 142
    .line 143
    const-string v3, "Unknown tag"

    .line 144
    .line 145
    invoke-static {v2, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 146
    .line 147
    .line 148
    :cond_5
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 149
    .line 150
    goto :goto_0

    .line 151
    :cond_6
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 152
    .line 153
    .line 154
    return-void
.end method


# virtual methods
.method public final a(FF)Z
    .locals 3

    .line 1
    iget v0, p0, Landroidx/constraintlayout/widget/g;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    cmpg-float v0, p1, v0

    .line 11
    .line 12
    if-gez v0, :cond_0

    .line 13
    .line 14
    return v2

    .line 15
    :cond_0
    iget v0, p0, Landroidx/constraintlayout/widget/g;->b:F

    .line 16
    .line 17
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_1

    .line 22
    .line 23
    cmpg-float v0, p2, v0

    .line 24
    .line 25
    if-gez v0, :cond_1

    .line 26
    .line 27
    return v2

    .line 28
    :cond_1
    iget v0, p0, Landroidx/constraintlayout/widget/g;->c:F

    .line 29
    .line 30
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-nez v1, :cond_2

    .line 35
    .line 36
    cmpl-float p1, p1, v0

    .line 37
    .line 38
    if-lez p1, :cond_2

    .line 39
    .line 40
    return v2

    .line 41
    :cond_2
    iget p0, p0, Landroidx/constraintlayout/widget/g;->d:F

    .line 42
    .line 43
    invoke-static {p0}, Ljava/lang/Float;->isNaN(F)Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-nez p1, :cond_3

    .line 48
    .line 49
    cmpl-float p0, p2, p0

    .line 50
    .line 51
    if-lez p0, :cond_3

    .line 52
    .line 53
    return v2

    .line 54
    :cond_3
    const/4 p0, 0x1

    .line 55
    return p0
.end method
