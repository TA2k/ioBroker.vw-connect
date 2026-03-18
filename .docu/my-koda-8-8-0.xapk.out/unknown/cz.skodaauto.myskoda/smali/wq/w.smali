.class public final Lwq/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:Lwq/d;

.field public c:[[I

.field public d:[Lwq/d;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0xa

    .line 5
    .line 6
    new-array v1, v0, [[I

    .line 7
    .line 8
    iput-object v1, p0, Lwq/w;->c:[[I

    .line 9
    .line 10
    new-array v0, v0, [Lwq/d;

    .line 11
    .line 12
    iput-object v0, p0, Lwq/w;->d:[Lwq/d;

    .line 13
    .line 14
    return-void
.end method

.method public static b(Lwq/d;)Lwq/w;
    .locals 2

    .line 1
    new-instance v0, Lwq/w;

    .line 2
    .line 3
    invoke-direct {v0}, Lwq/w;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Landroid/util/StateSet;->WILD_CARD:[I

    .line 7
    .line 8
    invoke-virtual {v0, v1, p0}, Lwq/w;->a([ILwq/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method


# virtual methods
.method public final a([ILwq/d;)V
    .locals 5

    .line 1
    iget v0, p0, Lwq/w;->a:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    array-length v1, p1

    .line 6
    if-nez v1, :cond_1

    .line 7
    .line 8
    :cond_0
    iput-object p2, p0, Lwq/w;->b:Lwq/d;

    .line 9
    .line 10
    :cond_1
    iget-object v1, p0, Lwq/w;->c:[[I

    .line 11
    .line 12
    array-length v2, v1

    .line 13
    if-lt v0, v2, :cond_2

    .line 14
    .line 15
    add-int/lit8 v2, v0, 0xa

    .line 16
    .line 17
    new-array v3, v2, [[I

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    invoke-static {v1, v4, v3, v4, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 21
    .line 22
    .line 23
    iput-object v3, p0, Lwq/w;->c:[[I

    .line 24
    .line 25
    new-array v1, v2, [Lwq/d;

    .line 26
    .line 27
    iget-object v2, p0, Lwq/w;->d:[Lwq/d;

    .line 28
    .line 29
    invoke-static {v2, v4, v1, v4, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 30
    .line 31
    .line 32
    iput-object v1, p0, Lwq/w;->d:[Lwq/d;

    .line 33
    .line 34
    :cond_2
    iget-object v0, p0, Lwq/w;->c:[[I

    .line 35
    .line 36
    iget v1, p0, Lwq/w;->a:I

    .line 37
    .line 38
    aput-object p1, v0, v1

    .line 39
    .line 40
    iget-object p1, p0, Lwq/w;->d:[Lwq/d;

    .line 41
    .line 42
    aput-object p2, p1, v1

    .line 43
    .line 44
    add-int/lit8 v1, v1, 0x1

    .line 45
    .line 46
    iput v1, p0, Lwq/w;->a:I

    .line 47
    .line 48
    return-void
.end method

.method public final c([I)Lwq/d;
    .locals 5

    .line 1
    iget-object v0, p0, Lwq/w;->c:[[I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move v2, v1

    .line 5
    :goto_0
    iget v3, p0, Lwq/w;->a:I

    .line 6
    .line 7
    const/4 v4, -0x1

    .line 8
    if-ge v2, v3, :cond_1

    .line 9
    .line 10
    aget-object v3, v0, v2

    .line 11
    .line 12
    invoke-static {v3, p1}, Landroid/util/StateSet;->stateSetMatches([I[I)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-eqz v3, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move v2, v4

    .line 23
    :goto_1
    if-gez v2, :cond_4

    .line 24
    .line 25
    sget-object p1, Landroid/util/StateSet;->WILD_CARD:[I

    .line 26
    .line 27
    iget-object v0, p0, Lwq/w;->c:[[I

    .line 28
    .line 29
    :goto_2
    iget v2, p0, Lwq/w;->a:I

    .line 30
    .line 31
    if-ge v1, v2, :cond_3

    .line 32
    .line 33
    aget-object v2, v0, v1

    .line 34
    .line 35
    invoke-static {v2, p1}, Landroid/util/StateSet;->stateSetMatches([I[I)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    move v4, v1

    .line 42
    goto :goto_3

    .line 43
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_3
    :goto_3
    move v2, v4

    .line 47
    :cond_4
    if-gez v2, :cond_5

    .line 48
    .line 49
    iget-object p0, p0, Lwq/w;->b:Lwq/d;

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_5
    iget-object p0, p0, Lwq/w;->d:[Lwq/d;

    .line 53
    .line 54
    aget-object p0, p0, v2

    .line 55
    .line 56
    return-object p0
.end method

.method public final d(Landroid/content/Context;Landroid/content/res/XmlResourceParser;Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)V
    .locals 11

    .line 1
    invoke-interface {p2}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    add-int/2addr v0, v1

    .line 7
    :cond_0
    :goto_0
    invoke-interface {p2}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eq v2, v1, :cond_7

    .line 12
    .line 13
    invoke-interface {p2}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-ge v3, v0, :cond_1

    .line 18
    .line 19
    const/4 v4, 0x3

    .line 20
    if-eq v2, v4, :cond_7

    .line 21
    .line 22
    :cond_1
    const/4 v4, 0x2

    .line 23
    if-ne v2, v4, :cond_0

    .line 24
    .line 25
    if-gt v3, v0, :cond_0

    .line 26
    .line 27
    invoke-interface {p2}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    const-string v3, "item"

    .line 32
    .line 33
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-nez v2, :cond_2

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    sget-object v3, Ldq/a;->z:[I

    .line 45
    .line 46
    const/4 v4, 0x0

    .line 47
    if-nez p4, :cond_3

    .line 48
    .line 49
    invoke-virtual {v2, p3, v3}, Landroid/content/res/Resources;->obtainAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    goto :goto_1

    .line 54
    :cond_3
    invoke-virtual {p4, p3, v3, v4, v4}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    :goto_1
    new-instance v3, Lwq/a;

    .line 59
    .line 60
    const/4 v5, 0x0

    .line 61
    invoke-direct {v3, v5}, Lwq/a;-><init>(F)V

    .line 62
    .line 63
    .line 64
    const/4 v5, 0x5

    .line 65
    invoke-static {v2, v5, v3}, Lwq/m;->c(Landroid/content/res/TypedArray;ILwq/d;)Lwq/d;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 70
    .line 71
    .line 72
    invoke-interface {p3}, Landroid/util/AttributeSet;->getAttributeCount()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    new-array v5, v2, [I

    .line 77
    .line 78
    move v6, v4

    .line 79
    move v7, v6

    .line 80
    :goto_2
    if-ge v6, v2, :cond_6

    .line 81
    .line 82
    invoke-interface {p3, v6}, Landroid/util/AttributeSet;->getAttributeNameResource(I)I

    .line 83
    .line 84
    .line 85
    move-result v8

    .line 86
    const v9, 0x7f04018d

    .line 87
    .line 88
    .line 89
    if-eq v8, v9, :cond_5

    .line 90
    .line 91
    add-int/lit8 v9, v7, 0x1

    .line 92
    .line 93
    invoke-interface {p3, v6, v4}, Landroid/util/AttributeSet;->getAttributeBooleanValue(IZ)Z

    .line 94
    .line 95
    .line 96
    move-result v10

    .line 97
    if-eqz v10, :cond_4

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_4
    neg-int v8, v8

    .line 101
    :goto_3
    aput v8, v5, v7

    .line 102
    .line 103
    move v7, v9

    .line 104
    :cond_5
    add-int/lit8 v6, v6, 0x1

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_6
    invoke-static {v5, v7}, Landroid/util/StateSet;->trimStateSet([II)[I

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-virtual {p0, v2, v3}, Lwq/w;->a([ILwq/d;)V

    .line 112
    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_7
    return-void
.end method
