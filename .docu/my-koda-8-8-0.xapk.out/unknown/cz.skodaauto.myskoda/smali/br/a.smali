.class public abstract Lbr/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[I

.field public static final b:[I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/high16 v0, 0x1010000

    .line 2
    .line 3
    const v1, 0x7f040594

    .line 4
    .line 5
    .line 6
    filled-new-array {v0, v1}, [I

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lbr/a;->a:[I

    .line 11
    .line 12
    const v0, 0x7f04039f

    .line 13
    .line 14
    .line 15
    filled-new-array {v0}, [I

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lbr/a;->b:[I

    .line 20
    .line 21
    return-void
.end method

.method public static a(Landroid/content/Context;Landroid/util/AttributeSet;II)Landroid/content/Context;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    invoke-static {p0, p1, p2, p3, v0}, Lbr/a;->b(Landroid/content/Context;Landroid/util/AttributeSet;II[I)Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public static b(Landroid/content/Context;Landroid/util/AttributeSet;II[I)Landroid/content/Context;
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v1, v0, [I

    .line 3
    .line 4
    sget-object v2, Lbr/a;->b:[I

    .line 5
    .line 6
    invoke-virtual {p0, p1, v2, p2, p3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    const/4 v3, 0x0

    .line 11
    invoke-virtual {v2, v3, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    aput v4, v1, v3

    .line 16
    .line 17
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 18
    .line 19
    .line 20
    aget v1, v1, v3

    .line 21
    .line 22
    instance-of v2, p0, Lk/c;

    .line 23
    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    move-object v2, p0

    .line 27
    check-cast v2, Lk/c;

    .line 28
    .line 29
    iget v2, v2, Lk/c;->a:I

    .line 30
    .line 31
    if-ne v2, v1, :cond_0

    .line 32
    .line 33
    move v2, v0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move v2, v3

    .line 36
    :goto_0
    if-eqz v1, :cond_8

    .line 37
    .line 38
    if-eqz v2, :cond_1

    .line 39
    .line 40
    goto :goto_4

    .line 41
    :cond_1
    new-instance v2, Lk/c;

    .line 42
    .line 43
    invoke-direct {v2, p0, v1}, Lk/c;-><init>(Landroid/content/Context;I)V

    .line 44
    .line 45
    .line 46
    array-length v1, p4

    .line 47
    new-array v4, v1, [I

    .line 48
    .line 49
    array-length v5, p4

    .line 50
    if-lez v5, :cond_3

    .line 51
    .line 52
    invoke-virtual {p0, p1, p4, p2, p3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    move p3, v3

    .line 57
    :goto_1
    array-length v5, p4

    .line 58
    if-ge p3, v5, :cond_2

    .line 59
    .line 60
    invoke-virtual {p2, p3, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    aput v5, v4, p3

    .line 65
    .line 66
    add-int/lit8 p3, p3, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 70
    .line 71
    .line 72
    :cond_3
    move p2, v3

    .line 73
    :goto_2
    if-ge p2, v1, :cond_5

    .line 74
    .line 75
    aget p3, v4, p2

    .line 76
    .line 77
    if-eqz p3, :cond_4

    .line 78
    .line 79
    invoke-virtual {v2}, Lk/c;->getTheme()Landroid/content/res/Resources$Theme;

    .line 80
    .line 81
    .line 82
    move-result-object p4

    .line 83
    invoke-virtual {p4, p3, v0}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 84
    .line 85
    .line 86
    :cond_4
    add-int/lit8 p2, p2, 0x1

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_5
    sget-object p2, Lbr/a;->a:[I

    .line 90
    .line 91
    invoke-virtual {p0, p1, p2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-virtual {p0, v3, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    invoke-virtual {p0, v0, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 100
    .line 101
    .line 102
    move-result p2

    .line 103
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    .line 104
    .line 105
    .line 106
    if-eqz p1, :cond_6

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_6
    move p1, p2

    .line 110
    :goto_3
    if-eqz p1, :cond_7

    .line 111
    .line 112
    invoke-virtual {v2}, Lk/c;->getTheme()Landroid/content/res/Resources$Theme;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-virtual {p0, p1, v0}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 117
    .line 118
    .line 119
    :cond_7
    return-object v2

    .line 120
    :cond_8
    :goto_4
    return-object p0
.end method
