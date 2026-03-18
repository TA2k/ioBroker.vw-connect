.class public final Lzq/q;
.super Landroid/widget/ArrayAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Landroid/content/res/ColorStateList;

.field public b:Landroid/content/res/ColorStateList;

.field public final synthetic c:Lzq/r;


# direct methods
.method public constructor <init>(Lzq/r;Landroid/content/Context;I[Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lzq/q;->c:Lzq/r;

    .line 2
    .line 3
    invoke-direct {p0, p2, p3, p4}, Landroid/widget/ArrayAdapter;-><init>(Landroid/content/Context;I[Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lzq/q;->a()V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 7

    .line 1
    iget-object v0, p0, Lzq/q;->c:Lzq/r;

    .line 2
    .line 3
    iget-object v1, v0, Lzq/r;->o:Landroid/content/res/ColorStateList;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    const v4, 0x10100a7

    .line 10
    .line 11
    .line 12
    filled-new-array {v4}, [I

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    invoke-virtual {v1, v4, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    filled-new-array {v1, v3}, [I

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    new-array v5, v3, [I

    .line 25
    .line 26
    filled-new-array {v4, v5}, [[I

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    new-instance v5, Landroid/content/res/ColorStateList;

    .line 31
    .line 32
    invoke-direct {v5, v4, v1}, Landroid/content/res/ColorStateList;-><init>([[I[I)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object v5, v2

    .line 37
    :goto_0
    iput-object v5, p0, Lzq/q;->b:Landroid/content/res/ColorStateList;

    .line 38
    .line 39
    iget v1, v0, Lzq/r;->n:I

    .line 40
    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    iget-object v1, v0, Lzq/r;->o:Landroid/content/res/ColorStateList;

    .line 44
    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    const v1, 0x1010367

    .line 48
    .line 49
    .line 50
    const v2, -0x10100a7

    .line 51
    .line 52
    .line 53
    filled-new-array {v1, v2}, [I

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    const v4, 0x10100a1

    .line 58
    .line 59
    .line 60
    filled-new-array {v4, v2}, [I

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    iget-object v4, v0, Lzq/r;->o:Landroid/content/res/ColorStateList;

    .line 65
    .line 66
    invoke-virtual {v4, v2, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    iget-object v5, v0, Lzq/r;->o:Landroid/content/res/ColorStateList;

    .line 71
    .line 72
    invoke-virtual {v5, v1, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 73
    .line 74
    .line 75
    move-result v5

    .line 76
    iget v6, v0, Lzq/r;->n:I

    .line 77
    .line 78
    invoke-static {v4, v6}, Ls5/a;->c(II)I

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    iget v6, v0, Lzq/r;->n:I

    .line 83
    .line 84
    invoke-static {v5, v6}, Ls5/a;->c(II)I

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    iget v0, v0, Lzq/r;->n:I

    .line 89
    .line 90
    filled-new-array {v4, v5, v0}, [I

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    new-array v3, v3, [I

    .line 95
    .line 96
    filled-new-array {v2, v1, v3}, [[I

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    new-instance v2, Landroid/content/res/ColorStateList;

    .line 101
    .line 102
    invoke-direct {v2, v1, v0}, Landroid/content/res/ColorStateList;-><init>([[I[I)V

    .line 103
    .line 104
    .line 105
    :cond_1
    iput-object v2, p0, Lzq/q;->a:Landroid/content/res/ColorStateList;

    .line 106
    .line 107
    return-void
.end method

.method public final getView(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;
    .locals 2

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroid/widget/ArrayAdapter;->getView(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    instance-of p2, p1, Landroid/widget/TextView;

    .line 6
    .line 7
    if-eqz p2, :cond_2

    .line 8
    .line 9
    move-object p2, p1

    .line 10
    check-cast p2, Landroid/widget/TextView;

    .line 11
    .line 12
    iget-object p3, p0, Lzq/q;->c:Lzq/r;

    .line 13
    .line 14
    invoke-virtual {p3}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {p2}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/String;->contentEquals(Ljava/lang/CharSequence;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v1, 0x0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    iget v0, p3, Lzq/r;->n:I

    .line 34
    .line 35
    if-eqz v0, :cond_1

    .line 36
    .line 37
    new-instance v0, Landroid/graphics/drawable/ColorDrawable;

    .line 38
    .line 39
    iget p3, p3, Lzq/r;->n:I

    .line 40
    .line 41
    invoke-direct {v0, p3}, Landroid/graphics/drawable/ColorDrawable;-><init>(I)V

    .line 42
    .line 43
    .line 44
    iget-object p3, p0, Lzq/q;->b:Landroid/content/res/ColorStateList;

    .line 45
    .line 46
    if-eqz p3, :cond_0

    .line 47
    .line 48
    iget-object p3, p0, Lzq/q;->a:Landroid/content/res/ColorStateList;

    .line 49
    .line 50
    invoke-virtual {v0, p3}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 51
    .line 52
    .line 53
    new-instance p3, Landroid/graphics/drawable/RippleDrawable;

    .line 54
    .line 55
    iget-object p0, p0, Lzq/q;->b:Landroid/content/res/ColorStateList;

    .line 56
    .line 57
    invoke-direct {p3, p0, v0, v1}, Landroid/graphics/drawable/RippleDrawable;-><init>(Landroid/content/res/ColorStateList;Landroid/graphics/drawable/Drawable;Landroid/graphics/drawable/Drawable;)V

    .line 58
    .line 59
    .line 60
    move-object v1, p3

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    move-object v1, v0

    .line 63
    :cond_1
    :goto_0
    invoke-virtual {p2, v1}, Landroid/view/View;->setBackground(Landroid/graphics/drawable/Drawable;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    return-object p1
.end method
