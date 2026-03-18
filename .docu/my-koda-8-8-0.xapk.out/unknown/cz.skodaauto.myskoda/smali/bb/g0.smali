.class public final Lbb/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/d0;
.implements Lo8/i;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(BI)V
    .locals 0

    iput p2, p0, Lbb/g0;->d:I

    sparse-switch p2, :sswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 p1, 0x8

    new-array p1, p1, [Ljava/lang/Object;

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    const/4 p1, 0x0

    iput p1, p0, Lbb/g0;->e:I

    return-void

    .line 2
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance p1, Ln2/b;

    const/16 p2, 0x10

    new-array p2, p2, [Lo1/h;

    invoke-direct {p1, p2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 4
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    return-void

    .line 5
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Landroidx/collection/f;

    const/4 p2, 0x0

    .line 6
    invoke-direct {p1, p2}, Landroidx/collection/a1;-><init>(I)V

    .line 7
    invoke-static {p1}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object p1

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    iput p2, p0, Lbb/g0;->e:I

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x9 -> :sswitch_1
        0xd -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(CI)V
    .locals 0

    .line 8
    iput p2, p0, Lbb/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lbb/g0;->d:I

    .line 99
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    mul-int/lit8 p1, p1, 0x2

    .line 100
    new-array p1, p1, [Ljava/lang/Object;

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 101
    iput p1, p0, Lbb/g0;->e:I

    return-void
.end method

.method public constructor <init>(ILjava/lang/String;ILjava/util/ArrayList;[B)V
    .locals 0

    const/16 p1, 0x12

    iput p1, p0, Lbb/g0;->d:I

    .line 93
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 94
    iput p3, p0, Lbb/g0;->e:I

    if-nez p4, :cond_0

    .line 95
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    goto :goto_0

    .line 96
    :cond_0
    invoke-static {p4}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    :goto_0
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 97
    iput-object p5, p0, Lbb/g0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(ILw7/u;)V
    .locals 1

    const/16 v0, 0x11

    iput v0, p0, Lbb/g0;->d:I

    .line 85
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 86
    iput p1, p0, Lbb/g0;->e:I

    .line 87
    iput-object p2, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 88
    new-instance p1, Lw7/p;

    invoke-direct {p1}, Lw7/p;-><init>()V

    iput-object p1, p0, Lbb/g0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/graphics/Shader;Landroid/content/res/ColorStateList;I)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Lbb/g0;->d:I

    .line 81
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 82
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 83
    iput-object p2, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 84
    iput p3, p0, Lbb/g0;->e:I

    return-void
.end method

.method public constructor <init>(Landroid/widget/ImageView;)V
    .locals 1

    const/16 v0, 0xb

    iput v0, p0, Lbb/g0;->d:I

    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 23
    iput v0, p0, Lbb/g0;->e:I

    .line 24
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lay0/k;Lay0/k;)V
    .locals 1

    const/16 v0, 0xc

    iput v0, p0, Lbb/g0;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 17
    iput-object p2, p0, Lbb/g0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ld01/i0;ILjava/lang/String;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lbb/g0;->d:I

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 20
    iput p2, p0, Lbb/g0;->e:I

    .line 21
    iput-object p3, p0, Lbb/g0;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lf3/d;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lbb/g0;->d:I

    .line 77
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 78
    new-instance v0, Landroid/util/SparseArray;

    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    iput-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 79
    iput-object p1, p0, Lbb/g0;->g:Ljava/lang/Object;

    const/4 p1, -0x1

    .line 80
    iput p1, p0, Lbb/g0;->e:I

    return-void
.end method

.method public constructor <init>(Lgr/k;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lbb/g0;->d:I

    .line 89
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 90
    iput-object p1, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 91
    sget-object p1, Lgr/d;->d:Lgr/d;

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    const p1, 0x7fffffff

    .line 92
    iput p1, p0, Lbb/g0;->e:I

    return-void
.end method

.method public constructor <init>(Lgy0/j;Lo1/y;)V
    .locals 12

    const/16 v0, 0xe

    iput v0, p0, Lbb/g0;->d:I

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    invoke-virtual {p2}, Lo1/y;->k()Lbb/g0;

    move-result-object p2

    .line 27
    iget v0, p1, Lgy0/h;->d:I

    if-ltz v0, :cond_0

    goto :goto_0

    .line 28
    :cond_0
    const-string v1, "negative nearestRange.first"

    .line 29
    invoke-static {v1}, Lj1/b;->c(Ljava/lang/String;)V

    .line 30
    :goto_0
    iget p1, p1, Lgy0/h;->e:I

    .line 31
    iget v1, p2, Lbb/g0;->e:I

    add-int/lit8 v1, v1, -0x1

    .line 32
    invoke-static {p1, v1}, Ljava/lang/Math;->min(II)I

    move-result p1

    if-ge p1, v0, :cond_1

    .line 33
    sget-object p1, Landroidx/collection/v0;->a:Landroidx/collection/h0;

    const-string p2, "null cannot be cast to non-null type androidx.collection.ObjectIntMap<K of androidx.collection.ObjectIntMapKt.emptyObjectIntMap>"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 35
    new-array p2, p1, [Ljava/lang/Object;

    iput-object p2, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 36
    iput p1, p0, Lbb/g0;->e:I

    goto/16 :goto_6

    :cond_1
    sub-int v1, p1, v0

    add-int/lit8 v1, v1, 0x1

    .line 37
    new-array v2, v1, [Ljava/lang/Object;

    iput-object v2, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 38
    iput v0, p0, Lbb/g0;->e:I

    .line 39
    new-instance v2, Landroidx/collection/h0;

    invoke-direct {v2, v1}, Landroidx/collection/h0;-><init>(I)V

    .line 40
    iget-object v1, p2, Lbb/g0;->f:Ljava/lang/Object;

    check-cast v1, Ln2/b;

    .line 41
    const-string v3, ", size "

    const-string v4, "Index "

    if-ltz v0, :cond_2

    .line 42
    iget v5, p2, Lbb/g0;->e:I

    if-ge v0, v5, :cond_2

    goto :goto_1

    .line 43
    :cond_2
    invoke-static {v4, v0, v3}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    .line 44
    iget v6, p2, Lbb/g0;->e:I

    .line 45
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5}, Lj1/b;->e(Ljava/lang/String;)V

    :goto_1
    if-ltz p1, :cond_3

    .line 46
    iget v5, p2, Lbb/g0;->e:I

    if-ge p1, v5, :cond_3

    goto :goto_2

    .line 47
    :cond_3
    invoke-static {v4, p1, v3}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    .line 48
    iget p2, p2, Lbb/g0;->e:I

    .line 49
    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Lj1/b;->e(Ljava/lang/String;)V

    :goto_2
    if-lt p1, v0, :cond_4

    goto :goto_3

    .line 50
    :cond_4
    new-instance p2, Ljava/lang/StringBuilder;

    const-string v3, "toIndex ("

    invoke-direct {p2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, ") should be not smaller than fromIndex ("

    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v3, 0x29

    invoke-virtual {p2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    .line 51
    invoke-static {p2}, Lj1/b;->a(Ljava/lang/String;)V

    .line 52
    :goto_3
    invoke-static {v0, v1}, Lo1/y;->e(ILn2/b;)I

    move-result p2

    .line 53
    iget-object v3, v1, Ln2/b;->d:[Ljava/lang/Object;

    aget-object v3, v3, p2

    check-cast v3, Lo1/h;

    .line 54
    iget v3, v3, Lo1/h;->a:I

    :goto_4
    if-gt v3, p1, :cond_8

    .line 55
    iget-object v4, v1, Ln2/b;->d:[Ljava/lang/Object;

    aget-object v4, v4, p2

    .line 56
    check-cast v4, Lo1/h;

    .line 57
    iget-object v5, v4, Lo1/h;->c:Lo1/q;

    .line 58
    invoke-interface {v5}, Lo1/q;->getKey()Lay0/k;

    move-result-object v5

    .line 59
    iget v6, v4, Lo1/h;->a:I

    .line 60
    invoke-static {v0, v6}, Ljava/lang/Math;->max(II)I

    move-result v7

    .line 61
    iget v8, v4, Lo1/h;->b:I

    add-int/2addr v8, v6

    add-int/lit8 v8, v8, -0x1

    .line 62
    invoke-static {p1, v8}, Ljava/lang/Math;->min(II)I

    move-result v8

    if-gt v7, v8, :cond_7

    :goto_5
    if-eqz v5, :cond_5

    sub-int v9, v7, v6

    .line 63
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-interface {v5, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_6

    .line 64
    :cond_5
    new-instance v9, Lo1/f;

    invoke-direct {v9, v7}, Lo1/f;-><init>(I)V

    .line 65
    :cond_6
    invoke-virtual {v2, v7, v9}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 66
    iget-object v10, p0, Lbb/g0;->g:Ljava/lang/Object;

    check-cast v10, [Ljava/lang/Object;

    iget v11, p0, Lbb/g0;->e:I

    sub-int v11, v7, v11

    aput-object v9, v10, v11

    if-eq v7, v8, :cond_7

    add-int/lit8 v7, v7, 0x1

    goto :goto_5

    .line 67
    :cond_7
    iget v4, v4, Lo1/h;->b:I

    add-int/2addr v3, v4

    add-int/lit8 p2, p2, 0x1

    goto :goto_4

    .line 68
    :cond_8
    iput-object v2, p0, Lbb/g0;->f:Ljava/lang/Object;

    :goto_6
    return-void
.end method

.method public constructor <init>(Lin/z1;I)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Lbb/g0;->d:I

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljp/uf;

    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    invoke-static {}, Ljp/zg;->b()V

    iput p2, p0, Lbb/g0;->e:I

    return-void
.end method

.method public constructor <init>(Lin/z1;IB)V
    .locals 0

    const/16 p3, 0xa

    iput p3, p0, Lbb/g0;->d:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p3, Ljp/uf;

    .line 13
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 14
    iput-object p3, p0, Lbb/g0;->g:Ljava/lang/Object;

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    invoke-static {}, Llp/og;->b()V

    iput p2, p0, Lbb/g0;->e:I

    return-void
.end method

.method public constructor <init>(Lw3/h2;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lbb/g0;->d:I

    .line 98
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbb/g0;->f:Ljava/lang/Object;

    return-void
.end method

.method public static f(Landroid/content/res/Resources;ILandroid/content/res/Resources$Theme;)Lbb/g0;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    invoke-virtual/range {p0 .. p1}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-static {v2}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    :goto_0
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    const/4 v5, 0x1

    .line 18
    const/4 v6, 0x2

    .line 19
    if-eq v4, v6, :cond_0

    .line 20
    .line 21
    if-eq v4, v5, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    if-ne v4, v6, :cond_22

    .line 25
    .line 26
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    const-string v7, "gradient"

    .line 34
    .line 35
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    const/4 v9, 0x0

    .line 40
    if-nez v8, :cond_2

    .line 41
    .line 42
    const-string v5, "selector"

    .line 43
    .line 44
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    if-eqz v5, :cond_1

    .line 49
    .line 50
    invoke-static {v0, v2, v3, v1}, Lp5/c;->b(Landroid/content/res/Resources;Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    new-instance v1, Lbb/g0;

    .line 55
    .line 56
    invoke-virtual {v0}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    invoke-direct {v1, v9, v0, v2}, Lbb/g0;-><init>(Landroid/graphics/Shader;Landroid/content/res/ColorStateList;I)V

    .line 61
    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_1
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 65
    .line 66
    new-instance v1, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 69
    .line 70
    .line 71
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getPositionDescription()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v2, ": unsupported complex color tag "

    .line 79
    .line 80
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw v0

    .line 94
    :cond_2
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v7

    .line 102
    if-eqz v7, :cond_21

    .line 103
    .line 104
    sget-object v4, Lm5/a;->e:[I

    .line 105
    .line 106
    invoke-static {v0, v1, v3, v4}, Lp5/b;->g(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    const-string v7, "http://schemas.android.com/apk/res/android"

    .line 111
    .line 112
    const-string v8, "startX"

    .line 113
    .line 114
    invoke-interface {v2, v7, v8}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    const/4 v10, 0x0

    .line 119
    if-eqz v8, :cond_3

    .line 120
    .line 121
    const/16 v8, 0x8

    .line 122
    .line 123
    invoke-virtual {v4, v8, v10}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 124
    .line 125
    .line 126
    move-result v8

    .line 127
    move v12, v8

    .line 128
    goto :goto_1

    .line 129
    :cond_3
    move v12, v10

    .line 130
    :goto_1
    const-string v8, "startY"

    .line 131
    .line 132
    invoke-interface {v2, v7, v8}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v8

    .line 136
    if-eqz v8, :cond_4

    .line 137
    .line 138
    const/16 v8, 0x9

    .line 139
    .line 140
    invoke-virtual {v4, v8, v10}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 141
    .line 142
    .line 143
    move-result v8

    .line 144
    move v13, v8

    .line 145
    goto :goto_2

    .line 146
    :cond_4
    move v13, v10

    .line 147
    :goto_2
    const-string v8, "endX"

    .line 148
    .line 149
    invoke-interface {v2, v7, v8}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v8

    .line 153
    if-eqz v8, :cond_5

    .line 154
    .line 155
    const/16 v8, 0xa

    .line 156
    .line 157
    invoke-virtual {v4, v8, v10}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 158
    .line 159
    .line 160
    move-result v8

    .line 161
    move v14, v8

    .line 162
    goto :goto_3

    .line 163
    :cond_5
    move v14, v10

    .line 164
    :goto_3
    const-string v8, "endY"

    .line 165
    .line 166
    invoke-interface {v2, v7, v8}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v8

    .line 170
    if-eqz v8, :cond_6

    .line 171
    .line 172
    const/16 v8, 0xb

    .line 173
    .line 174
    invoke-virtual {v4, v8, v10}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 175
    .line 176
    .line 177
    move-result v8

    .line 178
    move v15, v8

    .line 179
    goto :goto_4

    .line 180
    :cond_6
    move v15, v10

    .line 181
    :goto_4
    const-string v8, "centerX"

    .line 182
    .line 183
    invoke-interface {v2, v7, v8}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    const/4 v11, 0x3

    .line 188
    if-eqz v8, :cond_7

    .line 189
    .line 190
    invoke-virtual {v4, v11, v10}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 191
    .line 192
    .line 193
    move-result v8

    .line 194
    goto :goto_5

    .line 195
    :cond_7
    move v8, v10

    .line 196
    :goto_5
    const-string v9, "centerY"

    .line 197
    .line 198
    invoke-interface {v2, v7, v9}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v9

    .line 202
    if-eqz v9, :cond_8

    .line 203
    .line 204
    const/4 v9, 0x4

    .line 205
    invoke-virtual {v4, v9, v10}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 206
    .line 207
    .line 208
    move-result v9

    .line 209
    goto :goto_6

    .line 210
    :cond_8
    move v9, v10

    .line 211
    :goto_6
    const-string v11, "type"

    .line 212
    .line 213
    invoke-interface {v2, v7, v11}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v11

    .line 217
    const/4 v10, 0x0

    .line 218
    if-eqz v11, :cond_9

    .line 219
    .line 220
    invoke-virtual {v4, v6, v10}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 221
    .line 222
    .line 223
    move-result v11

    .line 224
    goto :goto_7

    .line 225
    :cond_9
    move v11, v10

    .line 226
    :goto_7
    const-string v6, "startColor"

    .line 227
    .line 228
    invoke-interface {v2, v7, v6}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v6

    .line 232
    if-eqz v6, :cond_a

    .line 233
    .line 234
    invoke-virtual {v4, v10, v10}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 235
    .line 236
    .line 237
    move-result v6

    .line 238
    goto :goto_8

    .line 239
    :cond_a
    move v6, v10

    .line 240
    :goto_8
    const-string v5, "centerColor"

    .line 241
    .line 242
    invoke-interface {v2, v7, v5}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v20

    .line 246
    if-eqz v20, :cond_b

    .line 247
    .line 248
    const/16 v20, 0x1

    .line 249
    .line 250
    goto :goto_9

    .line 251
    :cond_b
    move/from16 v20, v10

    .line 252
    .line 253
    :goto_9
    invoke-interface {v2, v7, v5}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v5

    .line 257
    if-eqz v5, :cond_c

    .line 258
    .line 259
    const/4 v5, 0x7

    .line 260
    invoke-virtual {v4, v5, v10}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 261
    .line 262
    .line 263
    move-result v5

    .line 264
    goto :goto_a

    .line 265
    :cond_c
    move v5, v10

    .line 266
    :goto_a
    const-string v10, "endColor"

    .line 267
    .line 268
    invoke-interface {v2, v7, v10}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v10

    .line 272
    if-eqz v10, :cond_d

    .line 273
    .line 274
    move/from16 v21, v12

    .line 275
    .line 276
    const/4 v10, 0x0

    .line 277
    const/4 v12, 0x1

    .line 278
    invoke-virtual {v4, v12, v10}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 279
    .line 280
    .line 281
    move-result v23

    .line 282
    move/from16 v12, v23

    .line 283
    .line 284
    goto :goto_b

    .line 285
    :cond_d
    move/from16 v21, v12

    .line 286
    .line 287
    const/4 v10, 0x0

    .line 288
    move v12, v10

    .line 289
    :goto_b
    const-string v10, "tileMode"

    .line 290
    .line 291
    invoke-interface {v2, v7, v10}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v10

    .line 295
    if-eqz v10, :cond_e

    .line 296
    .line 297
    const/4 v10, 0x6

    .line 298
    move/from16 v22, v13

    .line 299
    .line 300
    const/4 v13, 0x0

    .line 301
    invoke-virtual {v4, v10, v13}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 302
    .line 303
    .line 304
    move-result v10

    .line 305
    goto :goto_c

    .line 306
    :cond_e
    move/from16 v22, v13

    .line 307
    .line 308
    const/4 v10, 0x0

    .line 309
    :goto_c
    const-string v13, "gradientRadius"

    .line 310
    .line 311
    invoke-interface {v2, v7, v13}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v7

    .line 315
    if-eqz v7, :cond_f

    .line 316
    .line 317
    const/4 v7, 0x5

    .line 318
    const/4 v13, 0x0

    .line 319
    invoke-virtual {v4, v7, v13}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 320
    .line 321
    .line 322
    move-result v7

    .line 323
    move v13, v7

    .line 324
    goto :goto_d

    .line 325
    :cond_f
    const/4 v13, 0x0

    .line 326
    :goto_d
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    .line 327
    .line 328
    .line 329
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 330
    .line 331
    .line 332
    move-result v4

    .line 333
    const/4 v7, 0x1

    .line 334
    add-int/2addr v4, v7

    .line 335
    new-instance v7, Ljava/util/ArrayList;

    .line 336
    .line 337
    move-object/from16 v24, v2

    .line 338
    .line 339
    const/16 v2, 0x14

    .line 340
    .line 341
    invoke-direct {v7, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 342
    .line 343
    .line 344
    move/from16 v25, v13

    .line 345
    .line 346
    new-instance v13, Ljava/util/ArrayList;

    .line 347
    .line 348
    invoke-direct {v13, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 349
    .line 350
    .line 351
    :goto_e
    invoke-interface/range {v24 .. v24}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 352
    .line 353
    .line 354
    move-result v2

    .line 355
    move/from16 v26, v14

    .line 356
    .line 357
    const/4 v14, 0x1

    .line 358
    if-eq v2, v14, :cond_15

    .line 359
    .line 360
    invoke-interface/range {v24 .. v24}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 361
    .line 362
    .line 363
    move-result v14

    .line 364
    move/from16 v27, v15

    .line 365
    .line 366
    if-ge v14, v4, :cond_10

    .line 367
    .line 368
    const/4 v15, 0x3

    .line 369
    if-eq v2, v15, :cond_16

    .line 370
    .line 371
    :cond_10
    const/4 v15, 0x2

    .line 372
    if-eq v2, v15, :cond_12

    .line 373
    .line 374
    :cond_11
    :goto_f
    move/from16 v14, v26

    .line 375
    .line 376
    move/from16 v15, v27

    .line 377
    .line 378
    goto :goto_e

    .line 379
    :cond_12
    if-gt v14, v4, :cond_11

    .line 380
    .line 381
    invoke-interface/range {v24 .. v24}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 382
    .line 383
    .line 384
    move-result-object v2

    .line 385
    const-string v14, "item"

    .line 386
    .line 387
    invoke-virtual {v2, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 388
    .line 389
    .line 390
    move-result v2

    .line 391
    if-nez v2, :cond_13

    .line 392
    .line 393
    goto :goto_f

    .line 394
    :cond_13
    sget-object v2, Lm5/a;->f:[I

    .line 395
    .line 396
    invoke-static {v0, v1, v3, v2}, Lp5/b;->g(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 397
    .line 398
    .line 399
    move-result-object v2

    .line 400
    const/4 v14, 0x0

    .line 401
    invoke-virtual {v2, v14}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 402
    .line 403
    .line 404
    move-result v15

    .line 405
    const/4 v14, 0x1

    .line 406
    invoke-virtual {v2, v14}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 407
    .line 408
    .line 409
    move-result v19

    .line 410
    if-eqz v15, :cond_14

    .line 411
    .line 412
    if-eqz v19, :cond_14

    .line 413
    .line 414
    const/4 v15, 0x0

    .line 415
    invoke-virtual {v2, v15, v15}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 416
    .line 417
    .line 418
    move-result v28

    .line 419
    const/4 v15, 0x0

    .line 420
    invoke-virtual {v2, v14, v15}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 421
    .line 422
    .line 423
    move-result v29

    .line 424
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 425
    .line 426
    .line 427
    invoke-static/range {v28 .. v28}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 428
    .line 429
    .line 430
    move-result-object v2

    .line 431
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    invoke-static/range {v29 .. v29}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 435
    .line 436
    .line 437
    move-result-object v2

    .line 438
    invoke-virtual {v7, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    goto :goto_f

    .line 442
    :cond_14
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 443
    .line 444
    new-instance v1, Ljava/lang/StringBuilder;

    .line 445
    .line 446
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 447
    .line 448
    .line 449
    invoke-interface/range {v24 .. v24}, Lorg/xmlpull/v1/XmlPullParser;->getPositionDescription()Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object v2

    .line 453
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 454
    .line 455
    .line 456
    const-string v2, ": <item> tag requires a \'color\' attribute and a \'offset\' attribute!"

    .line 457
    .line 458
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 459
    .line 460
    .line 461
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v1

    .line 465
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    throw v0

    .line 469
    :cond_15
    move/from16 v27, v15

    .line 470
    .line 471
    :cond_16
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 472
    .line 473
    .line 474
    move-result v0

    .line 475
    if-lez v0, :cond_17

    .line 476
    .line 477
    new-instance v0, Lvp/y1;

    .line 478
    .line 479
    invoke-direct {v0, v13, v7}, Lvp/y1;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 480
    .line 481
    .line 482
    goto :goto_10

    .line 483
    :cond_17
    const/4 v0, 0x0

    .line 484
    :goto_10
    if-eqz v0, :cond_18

    .line 485
    .line 486
    :goto_11
    const/4 v14, 0x1

    .line 487
    goto :goto_12

    .line 488
    :cond_18
    if-eqz v20, :cond_19

    .line 489
    .line 490
    new-instance v0, Lvp/y1;

    .line 491
    .line 492
    invoke-direct {v0, v6, v5, v12}, Lvp/y1;-><init>(III)V

    .line 493
    .line 494
    .line 495
    goto :goto_11

    .line 496
    :cond_19
    new-instance v0, Lvp/y1;

    .line 497
    .line 498
    invoke-direct {v0, v6, v12}, Lvp/y1;-><init>(II)V

    .line 499
    .line 500
    .line 501
    goto :goto_11

    .line 502
    :goto_12
    if-eq v11, v14, :cond_1d

    .line 503
    .line 504
    const/4 v15, 0x2

    .line 505
    if-eq v11, v15, :cond_1c

    .line 506
    .line 507
    new-instance v11, Landroid/graphics/LinearGradient;

    .line 508
    .line 509
    iget-object v1, v0, Lvp/y1;->e:Ljava/lang/Object;

    .line 510
    .line 511
    move-object/from16 v16, v1

    .line 512
    .line 513
    check-cast v16, [I

    .line 514
    .line 515
    iget-object v0, v0, Lvp/y1;->f:Ljava/lang/Object;

    .line 516
    .line 517
    move-object/from16 v17, v0

    .line 518
    .line 519
    check-cast v17, [F

    .line 520
    .line 521
    if-eq v10, v14, :cond_1b

    .line 522
    .line 523
    if-eq v10, v15, :cond_1a

    .line 524
    .line 525
    sget-object v0, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 526
    .line 527
    :goto_13
    move-object/from16 v18, v0

    .line 528
    .line 529
    move/from16 v12, v21

    .line 530
    .line 531
    move/from16 v13, v22

    .line 532
    .line 533
    move/from16 v14, v26

    .line 534
    .line 535
    move/from16 v15, v27

    .line 536
    .line 537
    goto :goto_14

    .line 538
    :cond_1a
    sget-object v0, Landroid/graphics/Shader$TileMode;->MIRROR:Landroid/graphics/Shader$TileMode;

    .line 539
    .line 540
    goto :goto_13

    .line 541
    :cond_1b
    sget-object v0, Landroid/graphics/Shader$TileMode;->REPEAT:Landroid/graphics/Shader$TileMode;

    .line 542
    .line 543
    goto :goto_13

    .line 544
    :goto_14
    invoke-direct/range {v11 .. v18}, Landroid/graphics/LinearGradient;-><init>(FFFF[I[FLandroid/graphics/Shader$TileMode;)V

    .line 545
    .line 546
    .line 547
    goto :goto_17

    .line 548
    :cond_1c
    new-instance v11, Landroid/graphics/SweepGradient;

    .line 549
    .line 550
    iget-object v1, v0, Lvp/y1;->e:Ljava/lang/Object;

    .line 551
    .line 552
    check-cast v1, [I

    .line 553
    .line 554
    iget-object v0, v0, Lvp/y1;->f:Ljava/lang/Object;

    .line 555
    .line 556
    check-cast v0, [F

    .line 557
    .line 558
    invoke-direct {v11, v8, v9, v1, v0}, Landroid/graphics/SweepGradient;-><init>(FF[I[F)V

    .line 559
    .line 560
    .line 561
    goto :goto_17

    .line 562
    :cond_1d
    const/16 v17, 0x0

    .line 563
    .line 564
    cmpg-float v1, v25, v17

    .line 565
    .line 566
    if-lez v1, :cond_20

    .line 567
    .line 568
    new-instance v16, Landroid/graphics/RadialGradient;

    .line 569
    .line 570
    iget-object v1, v0, Lvp/y1;->e:Ljava/lang/Object;

    .line 571
    .line 572
    move-object/from16 v20, v1

    .line 573
    .line 574
    check-cast v20, [I

    .line 575
    .line 576
    iget-object v0, v0, Lvp/y1;->f:Ljava/lang/Object;

    .line 577
    .line 578
    move-object/from16 v21, v0

    .line 579
    .line 580
    check-cast v21, [F

    .line 581
    .line 582
    const/4 v14, 0x1

    .line 583
    if-eq v10, v14, :cond_1f

    .line 584
    .line 585
    const/4 v15, 0x2

    .line 586
    if-eq v10, v15, :cond_1e

    .line 587
    .line 588
    sget-object v0, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 589
    .line 590
    :goto_15
    move-object/from16 v22, v0

    .line 591
    .line 592
    move/from16 v17, v8

    .line 593
    .line 594
    move/from16 v18, v9

    .line 595
    .line 596
    move/from16 v19, v25

    .line 597
    .line 598
    goto :goto_16

    .line 599
    :cond_1e
    sget-object v0, Landroid/graphics/Shader$TileMode;->MIRROR:Landroid/graphics/Shader$TileMode;

    .line 600
    .line 601
    goto :goto_15

    .line 602
    :cond_1f
    sget-object v0, Landroid/graphics/Shader$TileMode;->REPEAT:Landroid/graphics/Shader$TileMode;

    .line 603
    .line 604
    goto :goto_15

    .line 605
    :goto_16
    invoke-direct/range {v16 .. v22}, Landroid/graphics/RadialGradient;-><init>(FFF[I[FLandroid/graphics/Shader$TileMode;)V

    .line 606
    .line 607
    .line 608
    move-object/from16 v11, v16

    .line 609
    .line 610
    :goto_17
    new-instance v0, Lbb/g0;

    .line 611
    .line 612
    const/4 v1, 0x0

    .line 613
    const/4 v13, 0x0

    .line 614
    invoke-direct {v0, v11, v1, v13}, Lbb/g0;-><init>(Landroid/graphics/Shader;Landroid/content/res/ColorStateList;I)V

    .line 615
    .line 616
    .line 617
    return-object v0

    .line 618
    :cond_20
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 619
    .line 620
    const-string v1, "<gradient> tag requires \'gradientRadius\' attribute with radial type"

    .line 621
    .line 622
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 623
    .line 624
    .line 625
    throw v0

    .line 626
    :cond_21
    move-object/from16 v24, v2

    .line 627
    .line 628
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 629
    .line 630
    new-instance v1, Ljava/lang/StringBuilder;

    .line 631
    .line 632
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 633
    .line 634
    .line 635
    invoke-interface/range {v24 .. v24}, Lorg/xmlpull/v1/XmlPullParser;->getPositionDescription()Ljava/lang/String;

    .line 636
    .line 637
    .line 638
    move-result-object v2

    .line 639
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 640
    .line 641
    .line 642
    const-string v2, ": invalid gradient color tag "

    .line 643
    .line 644
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 645
    .line 646
    .line 647
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 648
    .line 649
    .line 650
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 651
    .line 652
    .line 653
    move-result-object v1

    .line 654
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 655
    .line 656
    .line 657
    throw v0

    .line 658
    :cond_22
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 659
    .line 660
    const-string v1, "No start tag found"

    .line 661
    .line 662
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 663
    .line 664
    .line 665
    throw v0
.end method


# virtual methods
.method public a(Lo8/p;J)Lo8/h;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-interface/range {p1 .. p1}, Lo8/p;->getPosition()J

    .line 4
    .line 5
    .line 6
    move-result-wide v4

    .line 7
    const v1, 0x1b8a0

    .line 8
    .line 9
    .line 10
    int-to-long v1, v1

    .line 11
    invoke-interface/range {p1 .. p1}, Lo8/p;->getLength()J

    .line 12
    .line 13
    .line 14
    move-result-wide v6

    .line 15
    sub-long/2addr v6, v4

    .line 16
    invoke-static {v1, v2, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 17
    .line 18
    .line 19
    move-result-wide v1

    .line 20
    long-to-int v1, v1

    .line 21
    iget-object v2, v0, Lbb/g0;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Lw7/p;

    .line 24
    .line 25
    invoke-virtual {v2, v1}, Lw7/p;->F(I)V

    .line 26
    .line 27
    .line 28
    iget-object v3, v2, Lw7/p;->a:[B

    .line 29
    .line 30
    const/4 v6, 0x0

    .line 31
    move-object/from16 v7, p1

    .line 32
    .line 33
    invoke-interface {v7, v3, v6, v1}, Lo8/p;->o([BII)V

    .line 34
    .line 35
    .line 36
    iget v1, v2, Lw7/p;->c:I

    .line 37
    .line 38
    const-wide/16 v6, -0x1

    .line 39
    .line 40
    move-wide v10, v6

    .line 41
    const-wide v14, -0x7fffffffffffffffL    # -4.9E-324

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    :goto_0
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    const/16 v12, 0xbc

    .line 51
    .line 52
    if-lt v3, v12, :cond_7

    .line 53
    .line 54
    iget-object v3, v2, Lw7/p;->a:[B

    .line 55
    .line 56
    iget v12, v2, Lw7/p;->b:I

    .line 57
    .line 58
    :goto_1
    if-ge v12, v1, :cond_0

    .line 59
    .line 60
    aget-byte v13, v3, v12

    .line 61
    .line 62
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 63
    .line 64
    .line 65
    .line 66
    .line 67
    const/16 v8, 0x47

    .line 68
    .line 69
    if-eq v13, v8, :cond_1

    .line 70
    .line 71
    add-int/lit8 v12, v12, 0x1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_0
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 75
    .line 76
    .line 77
    .line 78
    .line 79
    :cond_1
    add-int/lit16 v3, v12, 0xbc

    .line 80
    .line 81
    if-le v3, v1, :cond_2

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_2
    iget v6, v0, Lbb/g0;->e:I

    .line 85
    .line 86
    invoke-static {v2, v12, v6}, Llp/gb;->b(Lw7/p;II)J

    .line 87
    .line 88
    .line 89
    move-result-wide v6

    .line 90
    cmp-long v8, v6, v16

    .line 91
    .line 92
    if-eqz v8, :cond_6

    .line 93
    .line 94
    iget-object v8, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v8, Lw7/u;

    .line 97
    .line 98
    invoke-virtual {v8, v6, v7}, Lw7/u;->b(J)J

    .line 99
    .line 100
    .line 101
    move-result-wide v6

    .line 102
    cmp-long v8, v6, p2

    .line 103
    .line 104
    if-lez v8, :cond_4

    .line 105
    .line 106
    cmp-long v0, v14, v16

    .line 107
    .line 108
    if-nez v0, :cond_3

    .line 109
    .line 110
    new-instance v0, Lo8/h;

    .line 111
    .line 112
    const/4 v1, -0x1

    .line 113
    move-wide v2, v6

    .line 114
    invoke-direct/range {v0 .. v5}, Lo8/h;-><init>(IJJ)V

    .line 115
    .line 116
    .line 117
    return-object v0

    .line 118
    :cond_3
    add-long v16, v4, v10

    .line 119
    .line 120
    new-instance v12, Lo8/h;

    .line 121
    .line 122
    const/4 v13, 0x0

    .line 123
    const-wide v14, -0x7fffffffffffffffL    # -4.9E-324

    .line 124
    .line 125
    .line 126
    .line 127
    .line 128
    invoke-direct/range {v12 .. v17}, Lo8/h;-><init>(IJJ)V

    .line 129
    .line 130
    .line 131
    return-object v12

    .line 132
    :cond_4
    move-wide v14, v6

    .line 133
    const-wide/32 v6, 0x186a0

    .line 134
    .line 135
    .line 136
    add-long/2addr v6, v14

    .line 137
    cmp-long v6, v6, p2

    .line 138
    .line 139
    if-lez v6, :cond_5

    .line 140
    .line 141
    int-to-long v0, v12

    .line 142
    add-long v10, v4, v0

    .line 143
    .line 144
    new-instance v6, Lo8/h;

    .line 145
    .line 146
    const/4 v7, 0x0

    .line 147
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 148
    .line 149
    .line 150
    .line 151
    .line 152
    invoke-direct/range {v6 .. v11}, Lo8/h;-><init>(IJJ)V

    .line 153
    .line 154
    .line 155
    return-object v6

    .line 156
    :cond_5
    int-to-long v6, v12

    .line 157
    move-wide v10, v6

    .line 158
    :cond_6
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 159
    .line 160
    .line 161
    int-to-long v6, v3

    .line 162
    goto :goto_0

    .line 163
    :cond_7
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 164
    .line 165
    .line 166
    .line 167
    .line 168
    :goto_2
    cmp-long v0, v14, v16

    .line 169
    .line 170
    if-eqz v0, :cond_8

    .line 171
    .line 172
    add-long v16, v4, v6

    .line 173
    .line 174
    new-instance v12, Lo8/h;

    .line 175
    .line 176
    const/4 v13, -0x2

    .line 177
    invoke-direct/range {v12 .. v17}, Lo8/h;-><init>(IJJ)V

    .line 178
    .line 179
    .line 180
    return-object v12

    .line 181
    :cond_8
    sget-object v0, Lo8/h;->d:Lo8/h;

    .line 182
    .line 183
    return-object v0
.end method

.method public b(ILo1/q;)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    const-string v0, "size should be >=0"

    .line 5
    .line 6
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    :goto_0
    if-nez p1, :cond_1

    .line 10
    .line 11
    return-void

    .line 12
    :cond_1
    new-instance v0, Lo1/h;

    .line 13
    .line 14
    iget v1, p0, Lbb/g0;->e:I

    .line 15
    .line 16
    invoke-direct {v0, v1, p1, p2}, Lo1/h;-><init>(IILo1/q;)V

    .line 17
    .line 18
    .line 19
    iget p2, p0, Lbb/g0;->e:I

    .line 20
    .line 21
    add-int/2addr p2, p1

    .line 22
    iput p2, p0, Lbb/g0;->e:I

    .line 23
    .line 24
    iget-object p0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Ln2/b;

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/widget/ImageView;

    .line 4
    .line 5
    invoke-virtual {v0}, Landroid/widget/ImageView;->getDrawable()Landroid/graphics/drawable/Drawable;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-static {v1}, Lm/g1;->a(Landroid/graphics/drawable/Drawable;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    if-eqz v1, :cond_1

    .line 15
    .line 16
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ld01/o;

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    invoke-virtual {v0}, Landroid/view/View;->getDrawableState()[I

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v1, p0, v0}, Lm/s;->e(Landroid/graphics/drawable/Drawable;Ld01/o;[I)V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public d(Lb0/p1;)V
    .locals 6

    .line 1
    iget-object v0, p1, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {v0}, Lb0/a1;->r()Landroid/media/Image;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_0
    iget-object v1, p1, Lb0/p1;->h:Lb0/v0;

    .line 12
    .line 13
    invoke-interface {v1}, Lb0/v0;->d()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-static {v0, v1}, Lmv/a;->a(Landroid/media/Image;I)Lmv/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Lay0/k;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    iget v1, p0, Lbb/g0;->e:I

    .line 28
    .line 29
    add-int/lit8 v1, v1, 0x1

    .line 30
    .line 31
    iput v1, p0, Lbb/g0;->e:I

    .line 32
    .line 33
    new-instance v1, Lhv/b;

    .line 34
    .line 35
    const/16 v2, 0x100

    .line 36
    .line 37
    invoke-direct {v1, v2}, Lhv/b;-><init>(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1}, Llp/c1;->a(Lhv/b;)Llv/c;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {v1, v0}, Lnv/b;->b(Lmv/a;)Laq/t;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    iget v3, v0, Lmv/a;->c:I

    .line 49
    .line 50
    iget v4, v0, Lmv/a;->d:I

    .line 51
    .line 52
    new-instance v5, Lgv/a;

    .line 53
    .line 54
    invoke-direct {v5, v1, v3, v4}, Lgv/a;-><init>(Llv/c;II)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    sget-object v1, Laq/l;->a:Lj0/e;

    .line 61
    .line 62
    new-instance v3, Laq/t;

    .line 63
    .line 64
    invoke-direct {v3}, Laq/t;-><init>()V

    .line 65
    .line 66
    .line 67
    new-instance v4, Laq/q;

    .line 68
    .line 69
    invoke-direct {v4, v1, v5, v3}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/i;Laq/t;)V

    .line 70
    .line 71
    .line 72
    iget-object v5, v2, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 73
    .line 74
    invoke-virtual {v5, v4}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2}, Laq/t;->s()V

    .line 78
    .line 79
    .line 80
    new-instance v2, Lnd0/b;

    .line 81
    .line 82
    const/4 v4, 0x0

    .line 83
    invoke-direct {v2, p0, v4}, Lnd0/b;-><init>(Lbb/g0;I)V

    .line 84
    .line 85
    .line 86
    new-instance v4, Lnd0/c;

    .line 87
    .line 88
    const/4 v5, 0x0

    .line 89
    invoke-direct {v4, v5, v2}, Lnd0/c;-><init>(ILay0/k;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v3, v1, v4}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 93
    .line 94
    .line 95
    new-instance v1, Lj9/d;

    .line 96
    .line 97
    const/16 v2, 0xb

    .line 98
    .line 99
    invoke-direct {v1, v2}, Lj9/d;-><init>(I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, v1}, Laq/t;->l(Laq/f;)Laq/t;

    .line 103
    .line 104
    .line 105
    new-instance v1, La0/h;

    .line 106
    .line 107
    const/16 v2, 0x14

    .line 108
    .line 109
    invoke-direct {v1, v2, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v3, v1}, Laq/t;->k(Laq/e;)Laq/t;

    .line 113
    .line 114
    .line 115
    :cond_1
    iget-object v1, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v1, Lay0/k;

    .line 118
    .line 119
    if-eqz v1, :cond_2

    .line 120
    .line 121
    iget v1, p0, Lbb/g0;->e:I

    .line 122
    .line 123
    add-int/lit8 v1, v1, 0x1

    .line 124
    .line 125
    iput v1, p0, Lbb/g0;->e:I

    .line 126
    .line 127
    sget-object v1, Lqv/a;->c:Lqv/a;

    .line 128
    .line 129
    invoke-static {}, Lfv/f;->c()Lfv/f;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    const-class v3, Lpv/e;

    .line 134
    .line 135
    invoke-virtual {v2, v3}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    check-cast v2, Lpv/e;

    .line 140
    .line 141
    iget-object v3, v2, Lpv/e;->a:Lpv/f;

    .line 142
    .line 143
    new-instance v4, Lpv/d;

    .line 144
    .line 145
    invoke-virtual {v3, v1}, Lap0/o;->y(Ljava/lang/Object;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    check-cast v3, Lpv/a;

    .line 150
    .line 151
    iget-object v2, v2, Lpv/e;->b:Lfv/d;

    .line 152
    .line 153
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    iget-object v2, v2, Lfv/d;->a:Lgt/b;

    .line 157
    .line 158
    invoke-interface {v2}, Lgt/b;->get()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 163
    .line 164
    invoke-virtual {v1}, Lqv/a;->b()Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    invoke-static {v5}, Llp/ng;->c(Ljava/lang/String;)Llp/lg;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    invoke-direct {v4, v3, v2, v5, v1}, Lpv/d;-><init>(Lpv/a;Ljava/util/concurrent/Executor;Llp/lg;Lov/f;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v4, v0}, Lnv/b;->b(Lmv/a;)Laq/t;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    const-string v1, "process(...)"

    .line 180
    .line 181
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    new-instance v1, Lnd0/b;

    .line 185
    .line 186
    const/4 v2, 0x1

    .line 187
    invoke-direct {v1, p0, v2}, Lnd0/b;-><init>(Lbb/g0;I)V

    .line 188
    .line 189
    .line 190
    new-instance v2, Lnd0/c;

    .line 191
    .line 192
    const/4 v3, 0x0

    .line 193
    invoke-direct {v2, v3, v1}, Lnd0/c;-><init>(ILay0/k;)V

    .line 194
    .line 195
    .line 196
    sget-object v1, Laq/l;->a:Lj0/e;

    .line 197
    .line 198
    invoke-virtual {v0, v1, v2}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 199
    .line 200
    .line 201
    new-instance v1, Lj9/d;

    .line 202
    .line 203
    const/16 v2, 0xb

    .line 204
    .line 205
    invoke-direct {v1, v2}, Lj9/d;-><init>(I)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v0, v1}, Laq/t;->l(Laq/f;)Laq/t;

    .line 209
    .line 210
    .line 211
    new-instance v1, La0/h;

    .line 212
    .line 213
    const/16 v2, 0x14

    .line 214
    .line 215
    invoke-direct {v1, v2, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v0, v1}, Laq/t;->k(Laq/e;)Laq/t;

    .line 219
    .line 220
    .line 221
    :cond_2
    :goto_0
    return-void
.end method

.method public e()Lhr/c1;
    .locals 2

    .line 1
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lhr/i0;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget v0, p0, Lbb/g0;->e:I

    .line 8
    .line 9
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, [Ljava/lang/Object;

    .line 12
    .line 13
    invoke-static {v0, v1, p0}, Lhr/c1;->a(I[Ljava/lang/Object;Lbb/g0;)Lhr/c1;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lhr/i0;

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    return-object v0

    .line 24
    :cond_0
    invoke-virtual {p0}, Lhr/i0;->a()Ljava/lang/IllegalArgumentException;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-virtual {v0}, Lhr/i0;->a()Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    throw p0
.end method

.method public g(I)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/util/SparseArray;

    .line 4
    .line 5
    iget v1, p0, Lbb/g0;->e:I

    .line 6
    .line 7
    const/4 v2, -0x1

    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput v1, p0, Lbb/g0;->e:I

    .line 12
    .line 13
    :cond_0
    :goto_0
    iget v1, p0, Lbb/g0;->e:I

    .line 14
    .line 15
    if-lez v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->keyAt(I)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-ge p1, v1, :cond_1

    .line 22
    .line 23
    iget v1, p0, Lbb/g0;->e:I

    .line 24
    .line 25
    add-int/lit8 v1, v1, -0x1

    .line 26
    .line 27
    iput v1, p0, Lbb/g0;->e:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    :goto_1
    iget v1, p0, Lbb/g0;->e:I

    .line 31
    .line 32
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    add-int/lit8 v2, v2, -0x1

    .line 37
    .line 38
    if-ge v1, v2, :cond_2

    .line 39
    .line 40
    iget v1, p0, Lbb/g0;->e:I

    .line 41
    .line 42
    add-int/lit8 v1, v1, 0x1

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->keyAt(I)I

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-lt p1, v1, :cond_2

    .line 49
    .line 50
    iget v1, p0, Lbb/g0;->e:I

    .line 51
    .line 52
    add-int/lit8 v1, v1, 0x1

    .line 53
    .line 54
    iput v1, p0, Lbb/g0;->e:I

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_2
    iget p0, p0, Lbb/g0;->e:I

    .line 58
    .line 59
    invoke-virtual {v0, p0}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0
.end method

.method public h(I)Lo1/h;
    .locals 3

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget v0, p0, Lbb/g0;->e:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const-string v0, "Index "

    .line 9
    .line 10
    const-string v1, ", size "

    .line 11
    .line 12
    invoke-static {v0, p1, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget v1, p0, Lbb/g0;->e:I

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0}, Lj1/b;->e(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Lo1/h;

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    iget v1, v0, Lo1/h;->a:I

    .line 35
    .line 36
    iget v2, v0, Lo1/h;->b:I

    .line 37
    .line 38
    add-int/2addr v2, v1

    .line 39
    if-ge p1, v2, :cond_1

    .line 40
    .line 41
    if-gt v1, p1, :cond_1

    .line 42
    .line 43
    return-object v0

    .line 44
    :cond_1
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Ln2/b;

    .line 47
    .line 48
    invoke-static {p1, v0}, Lo1/y;->e(ILn2/b;)I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    iget-object v0, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 53
    .line 54
    aget-object p1, v0, p1

    .line 55
    .line 56
    check-cast p1, Lo1/h;

    .line 57
    .line 58
    iput-object p1, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 59
    .line 60
    return-object p1
.end method

.method public i(Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/collection/h0;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/collection/h0;->d(Ljava/lang/Object;)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-ltz p1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Landroidx/collection/h0;->c:[I

    .line 12
    .line 13
    aget p0, p0, p1

    .line 14
    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, -0x1

    .line 17
    return p0
.end method

.method public j()V
    .locals 2

    .line 1
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lw7/p;

    .line 4
    .line 5
    sget-object v0, Lw7/w;->b:[B

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    array-length v1, v0

    .line 11
    invoke-virtual {p0, v1, v0}, Lw7/p;->G(I[B)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public k(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [Ljava/lang/Object;

    .line 4
    .line 5
    iget p0, p0, Lbb/g0;->e:I

    .line 6
    .line 7
    sub-int/2addr p1, p0

    .line 8
    if-ltz p1, :cond_0

    .line 9
    .line 10
    array-length p0, v0

    .line 11
    if-ge p1, p0, :cond_0

    .line 12
    .line 13
    aget-object p0, v0, p1

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

.method public l()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "$"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lbb/g0;->e:I

    .line 9
    .line 10
    add-int/lit8 v1, v1, 0x1

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_3

    .line 14
    .line 15
    iget-object v3, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v3, [Ljava/lang/Object;

    .line 18
    .line 19
    aget-object v3, v3, v2

    .line 20
    .line 21
    instance-of v4, v3, Lsz0/g;

    .line 22
    .line 23
    if-eqz v4, :cond_1

    .line 24
    .line 25
    check-cast v3, Lsz0/g;

    .line 26
    .line 27
    invoke-interface {v3}, Lsz0/g;->getKind()Lkp/y8;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    sget-object v5, Lsz0/k;->c:Lsz0/k;

    .line 32
    .line 33
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-eqz v4, :cond_0

    .line 38
    .line 39
    iget-object v3, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v3, [I

    .line 42
    .line 43
    aget v3, v3, v2

    .line 44
    .line 45
    const/4 v4, -0x1

    .line 46
    if-eq v3, v4, :cond_2

    .line 47
    .line 48
    const-string v3, "["

    .line 49
    .line 50
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    iget-object v3, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v3, [I

    .line 56
    .line 57
    aget v3, v3, v2

    .line 58
    .line 59
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v3, "]"

    .line 63
    .line 64
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_0
    iget-object v4, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v4, [I

    .line 71
    .line 72
    aget v4, v4, v2

    .line 73
    .line 74
    if-ltz v4, :cond_2

    .line 75
    .line 76
    const-string v5, "."

    .line 77
    .line 78
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-interface {v3, v4}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    sget-object v4, Lwz0/q;->a:Lwz0/q;

    .line 90
    .line 91
    if-eq v3, v4, :cond_2

    .line 92
    .line 93
    const-string v4, "[\'"

    .line 94
    .line 95
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v3, "\']"

    .line 102
    .line 103
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    :cond_2
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_3
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0
.end method

.method public m()I
    .locals 1

    .line 1
    iget p0, p0, Lbb/g0;->e:I

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    if-eq p0, v0, :cond_1

    .line 5
    .line 6
    const/4 v0, 0x3

    .line 7
    if-eq p0, v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    const/16 p0, 0x200

    .line 12
    .line 13
    return p0

    .line 14
    :cond_1
    const/16 p0, 0x800

    .line 15
    .line 16
    return p0
.end method

.method public n(IIIIIIZZ)V
    .locals 9

    .line 1
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [J

    .line 4
    .line 5
    iget v1, p0, Lbb/g0;->e:I

    .line 6
    .line 7
    add-int/lit8 v2, v1, 0x3

    .line 8
    .line 9
    iput v2, p0, Lbb/g0;->e:I

    .line 10
    .line 11
    array-length v3, v0

    .line 12
    if-gt v3, v2, :cond_0

    .line 13
    .line 14
    mul-int/lit8 v3, v3, 0x2

    .line 15
    .line 16
    invoke-static {v3, v2}, Ljava/lang/Math;->max(II)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v3, "copyOf(...)"

    .line 25
    .line 26
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 30
    .line 31
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, [J

    .line 34
    .line 35
    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iput-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 43
    .line 44
    :cond_0
    iget-object p0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, [J

    .line 47
    .line 48
    int-to-long v2, p2

    .line 49
    const/16 p2, 0x20

    .line 50
    .line 51
    shl-long/2addr v2, p2

    .line 52
    int-to-long v4, p3

    .line 53
    const-wide v6, 0xffffffffL

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    and-long/2addr v4, v6

    .line 59
    or-long/2addr v2, v4

    .line 60
    aput-wide v2, p0, v1

    .line 61
    .line 62
    add-int/lit8 p3, v1, 0x1

    .line 63
    .line 64
    int-to-long v2, p4

    .line 65
    shl-long/2addr v2, p2

    .line 66
    int-to-long v4, p5

    .line 67
    and-long/2addr v4, v6

    .line 68
    or-long/2addr v2, v4

    .line 69
    aput-wide v2, p0, p3

    .line 70
    .line 71
    add-int/lit8 p2, v1, 0x2

    .line 72
    .line 73
    move/from16 p3, p8

    .line 74
    .line 75
    int-to-long v2, p3

    .line 76
    const/16 p3, 0x3f

    .line 77
    .line 78
    shl-long/2addr v2, p3

    .line 79
    move/from16 p3, p7

    .line 80
    .line 81
    int-to-long v4, p3

    .line 82
    const/16 p3, 0x3e

    .line 83
    .line 84
    shl-long/2addr v4, p3

    .line 85
    or-long/2addr v2, v4

    .line 86
    const/4 p3, 0x1

    .line 87
    int-to-long v4, p3

    .line 88
    const/16 p3, 0x3d

    .line 89
    .line 90
    shl-long/2addr v4, p3

    .line 91
    or-long/2addr v2, v4

    .line 92
    const/4 p3, 0x0

    .line 93
    const/16 v0, 0x1ff

    .line 94
    .line 95
    invoke-static {p3, v0}, Ljava/lang/Math;->min(II)I

    .line 96
    .line 97
    .line 98
    move-result p3

    .line 99
    int-to-long v4, p3

    .line 100
    const/16 p3, 0x34

    .line 101
    .line 102
    shl-long/2addr v4, p3

    .line 103
    or-long/2addr v2, v4

    .line 104
    const v4, 0x3ffffff

    .line 105
    .line 106
    .line 107
    and-int v5, p6, v4

    .line 108
    .line 109
    int-to-long v6, v5

    .line 110
    const/16 v8, 0x1a

    .line 111
    .line 112
    shl-long/2addr v6, v8

    .line 113
    or-long/2addr v2, v6

    .line 114
    and-int/2addr p1, v4

    .line 115
    int-to-long v6, p1

    .line 116
    or-long/2addr v2, v6

    .line 117
    aput-wide v2, p0, p2

    .line 118
    .line 119
    if-gez p6, :cond_1

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_1
    add-int/lit8 p1, v1, -0x3

    .line 123
    .line 124
    :goto_0
    if-ltz p1, :cond_3

    .line 125
    .line 126
    add-int/lit8 p2, p1, 0x2

    .line 127
    .line 128
    aget-wide v2, p0, p2

    .line 129
    .line 130
    long-to-int v6, v2

    .line 131
    and-int/2addr v6, v4

    .line 132
    if-ne v6, v5, :cond_2

    .line 133
    .line 134
    sub-int/2addr v1, p1

    .line 135
    const-wide v4, -0x1ff0000000000001L    # -5.363123171977038E154

    .line 136
    .line 137
    .line 138
    .line 139
    .line 140
    and-long/2addr v2, v4

    .line 141
    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    int-to-long v0, p1

    .line 146
    shl-long/2addr v0, p3

    .line 147
    or-long/2addr v0, v2

    .line 148
    aput-wide v0, p0, p2

    .line 149
    .line 150
    return-void

    .line 151
    :cond_2
    add-int/lit8 p1, p1, -0x3

    .line 152
    .line 153
    goto :goto_0

    .line 154
    :cond_3
    :goto_1
    return-void
.end method

.method public o()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Shader;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Landroid/content/res/ColorStateList;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public p(Landroid/util/AttributeSet;I)V
    .locals 8

    .line 1
    iget-object p0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Landroid/widget/ImageView;

    .line 5
    .line 6
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    sget-object v2, Lg/a;->f:[I

    .line 11
    .line 12
    invoke-static {p0, p1, v2, p2}, Lil/g;->R(Landroid/content/Context;Landroid/util/AttributeSet;[II)Lil/g;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    iget-object v1, p0, Lil/g;->f:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v7, v1

    .line 19
    check-cast v7, Landroid/content/res/TypedArray;

    .line 20
    .line 21
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget-object v3, p0, Lil/g;->f:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v4, v3

    .line 28
    check-cast v4, Landroid/content/res/TypedArray;

    .line 29
    .line 30
    sget-object v3, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    move-object v3, p1

    .line 34
    move v5, p2

    .line 35
    invoke-static/range {v0 .. v6}, Ld6/o0;->b(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    .line 36
    .line 37
    .line 38
    :try_start_0
    invoke-virtual {v0}, Landroid/widget/ImageView;->getDrawable()Landroid/graphics/drawable/Drawable;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    const/4 p2, -0x1

    .line 43
    if-nez p1, :cond_0

    .line 44
    .line 45
    const/4 v1, 0x1

    .line 46
    invoke-virtual {v7, v1, p2}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eq v1, p2, :cond_0

    .line 51
    .line 52
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-static {p1, v1}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-eqz p1, :cond_0

    .line 61
    .line 62
    invoke-virtual {v0, p1}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception v0

    .line 67
    move-object p1, v0

    .line 68
    goto :goto_1

    .line 69
    :cond_0
    :goto_0
    if-eqz p1, :cond_1

    .line 70
    .line 71
    invoke-static {p1}, Lm/g1;->a(Landroid/graphics/drawable/Drawable;)V

    .line 72
    .line 73
    .line 74
    :cond_1
    const/4 p1, 0x2

    .line 75
    invoke-virtual {v7, p1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_2

    .line 80
    .line 81
    invoke-virtual {p0, p1}, Lil/g;->y(I)Landroid/content/res/ColorStateList;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {v0, p1}, Landroid/widget/ImageView;->setImageTintList(Landroid/content/res/ColorStateList;)V

    .line 86
    .line 87
    .line 88
    :cond_2
    const/4 p1, 0x3

    .line 89
    invoke-virtual {v7, p1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-eqz v1, :cond_3

    .line 94
    .line 95
    invoke-virtual {v7, p1, p2}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    const/4 p2, 0x0

    .line 100
    invoke-static {p1, p2}, Lm/g1;->b(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuff$Mode;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    invoke-virtual {v0, p1}, Landroid/widget/ImageView;->setImageTintMode(Landroid/graphics/PorterDuff$Mode;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 105
    .line 106
    .line 107
    :cond_3
    invoke-virtual {p0}, Lil/g;->U()V

    .line 108
    .line 109
    .line 110
    return-void

    .line 111
    :goto_1
    invoke-virtual {p0}, Lil/g;->U()V

    .line 112
    .line 113
    .line 114
    throw p1
.end method

.method public q(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Lbb/g0;->e:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    mul-int/lit8 v0, v0, 0x2

    .line 6
    .line 7
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, [Ljava/lang/Object;

    .line 10
    .line 11
    array-length v2, v1

    .line 12
    if-le v0, v2, :cond_0

    .line 13
    .line 14
    array-length v2, v1

    .line 15
    invoke-static {v2, v0}, Lhr/b0;->h(II)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 24
    .line 25
    :cond_0
    invoke-static {p1, p2}, Lhr/q;->b(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, [Ljava/lang/Object;

    .line 31
    .line 32
    iget v1, p0, Lbb/g0;->e:I

    .line 33
    .line 34
    mul-int/lit8 v2, v1, 0x2

    .line 35
    .line 36
    aput-object p1, v0, v2

    .line 37
    .line 38
    add-int/lit8 v2, v2, 0x1

    .line 39
    .line 40
    aput-object p2, v0, v2

    .line 41
    .line 42
    add-int/lit8 v1, v1, 0x1

    .line 43
    .line 44
    iput v1, p0, Lbb/g0;->e:I

    .line 45
    .line 46
    return-void
.end method

.method public r(Ljava/lang/Iterable;)V
    .locals 3

    .line 1
    instance-of v0, p1, Ljava/util/Collection;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget v0, p0, Lbb/g0;->e:I

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Ljava/util/Collection;

    .line 9
    .line 10
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    add-int/2addr v1, v0

    .line 15
    mul-int/lit8 v1, v1, 0x2

    .line 16
    .line 17
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, [Ljava/lang/Object;

    .line 20
    .line 21
    array-length v2, v0

    .line 22
    if-le v1, v2, :cond_0

    .line 23
    .line 24
    array-length v2, v0

    .line 25
    invoke-static {v2, v1}, Lhr/b0;->h(II)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 34
    .line 35
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Ljava/util/Map$Entry;

    .line 50
    .line 51
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    invoke-virtual {p0, v1, v0}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    return-void
.end method

.method public s()V
    .locals 5

    .line 1
    iget v0, p0, Lbb/g0;->e:I

    .line 2
    .line 3
    mul-int/lit8 v0, v0, 0x2

    .line 4
    .line 5
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, [Ljava/lang/Object;

    .line 8
    .line 9
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "copyOf(...)"

    .line 14
    .line 15
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 19
    .line 20
    new-array v1, v0, [I

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    move v3, v2

    .line 24
    :goto_0
    if-ge v3, v0, :cond_0

    .line 25
    .line 26
    const/4 v4, -0x1

    .line 27
    aput v4, v1, v3

    .line 28
    .line 29
    add-int/lit8 v3, v3, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, [I

    .line 35
    .line 36
    const/16 v3, 0xe

    .line 37
    .line 38
    invoke-static {v2, v2, v3, v0, v1}, Lmx0/n;->l(III[I[I)V

    .line 39
    .line 40
    .line 41
    iput-object v1, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 42
    .line 43
    return-void
.end method

.method public t(Ljava/lang/CharSequence;)Ljava/util/List;
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lgr/k;

    .line 7
    .line 8
    iget-object v0, v0, Lgr/k;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lgr/c;

    .line 11
    .line 12
    new-instance v1, Lgr/l;

    .line 13
    .line 14
    invoke-direct {v1, p0, p1, v0}, Lgr/l;-><init>(Lbb/g0;Ljava/lang/CharSequence;Lgr/c;)V

    .line 15
    .line 16
    .line 17
    new-instance p0, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    :goto_0
    invoke-virtual {v1}, Lgr/l;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    invoke-virtual {v1}, Lgr/l;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    check-cast p1, Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lbb/g0;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :sswitch_0
    invoke-virtual {p0}, Lbb/g0;->l()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :sswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Ld01/i0;

    .line 24
    .line 25
    sget-object v2, Ld01/i0;->f:Ld01/i0;

    .line 26
    .line 27
    if-ne v1, v2, :cond_0

    .line 28
    .line 29
    const-string v1, "HTTP/1.0"

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const-string v1, "HTTP/1.1"

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    :goto_0
    const/16 v1, 0x20

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget v2, p0, Lbb/g0;->e:I

    .line 46
    .line 47
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_1
        0x13 -> :sswitch_0
    .end sparse-switch
.end method

.method public u(ILay0/p;)V
    .locals 6

    .line 1
    const v0, 0x3ffffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p1, v0

    .line 5
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, [J

    .line 8
    .line 9
    iget p0, p0, Lbb/g0;->e:I

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    array-length v3, v1

    .line 13
    add-int/lit8 v3, v3, -0x2

    .line 14
    .line 15
    if-ge v2, v3, :cond_1

    .line 16
    .line 17
    if-ge v2, p0, :cond_1

    .line 18
    .line 19
    add-int/lit8 v3, v2, 0x2

    .line 20
    .line 21
    aget-wide v3, v1, v3

    .line 22
    .line 23
    long-to-int v3, v3

    .line 24
    and-int/2addr v3, v0

    .line 25
    if-ne v3, p1, :cond_0

    .line 26
    .line 27
    aget-wide p0, v1, v2

    .line 28
    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    aget-wide v0, v1, v2

    .line 32
    .line 33
    const/16 v2, 0x20

    .line 34
    .line 35
    shr-long v3, p0, v2

    .line 36
    .line 37
    long-to-int v3, v3

    .line 38
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    long-to-int p0, p0

    .line 43
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    shr-long v4, v0, v2

    .line 48
    .line 49
    long-to-int p1, v4

    .line 50
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    long-to-int v0, v0

    .line 55
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    invoke-interface {p2, v3, p0, p1, v0}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_0
    add-int/lit8 v2, v2, 0x3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    return-void
.end method

.method public v(Ljava/lang/String;Ljo/d;)V
    .locals 4

    .line 1
    iget v0, p0, Lbb/g0;->e:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, [Ljava/lang/Object;

    .line 8
    .line 9
    array-length v2, v1

    .line 10
    add-int/2addr v0, v0

    .line 11
    if-le v0, v2, :cond_3

    .line 12
    .line 13
    if-ltz v0, :cond_2

    .line 14
    .line 15
    shr-int/lit8 v3, v2, 0x1

    .line 16
    .line 17
    add-int/2addr v2, v3

    .line 18
    add-int/lit8 v2, v2, 0x1

    .line 19
    .line 20
    if-ge v2, v0, :cond_0

    .line 21
    .line 22
    add-int/lit8 v0, v0, -0x1

    .line 23
    .line 24
    invoke-static {v0}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    add-int v2, v0, v0

    .line 29
    .line 30
    :cond_0
    if-gez v2, :cond_1

    .line 31
    .line 32
    const v2, 0x7fffffff

    .line 33
    .line 34
    .line 35
    :cond_1
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iput-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    new-instance p0, Ljava/lang/AssertionError;

    .line 43
    .line 44
    const-string p1, "cannot store more than MAX_VALUE elements"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_3
    :goto_0
    iget-object v0, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, [Ljava/lang/Object;

    .line 53
    .line 54
    iget v1, p0, Lbb/g0;->e:I

    .line 55
    .line 56
    add-int v2, v1, v1

    .line 57
    .line 58
    aput-object p1, v0, v2

    .line 59
    .line 60
    add-int/lit8 v2, v2, 0x1

    .line 61
    .line 62
    aput-object p2, v0, v2

    .line 63
    .line 64
    add-int/lit8 v1, v1, 0x1

    .line 65
    .line 66
    iput v1, p0, Lbb/g0;->e:I

    .line 67
    .line 68
    return-void
.end method

.method public w()[B
    .locals 6

    .line 1
    const-class v0, Llp/vb;

    .line 2
    .line 3
    sget-object v1, Llp/og;->f:Llp/og;

    .line 4
    .line 5
    iget-object v2, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lin/z1;

    .line 8
    .line 9
    iget-object v3, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Ljp/uf;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    iput-object v4, v3, Ljp/uf;->h:Ljava/lang/Object;

    .line 19
    .line 20
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ljp/uf;

    .line 23
    .line 24
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 25
    .line 26
    iput-object v3, p0, Ljp/uf;->f:Ljava/lang/Object;

    .line 27
    .line 28
    new-instance v3, Llp/lf;

    .line 29
    .line 30
    invoke-direct {v3, p0}, Llp/lf;-><init>(Ljp/uf;)V

    .line 31
    .line 32
    .line 33
    iput-object v3, v2, Lin/z1;->a:Ljava/lang/Object;

    .line 34
    .line 35
    :try_start_0
    invoke-static {}, Llp/og;->b()V

    .line 36
    .line 37
    .line 38
    new-instance p0, Llp/vb;

    .line 39
    .line 40
    invoke-direct {p0, v2}, Llp/vb;-><init>(Lin/z1;)V

    .line 41
    .line 42
    .line 43
    new-instance v2, Llp/f0;

    .line 44
    .line 45
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 46
    .line 47
    .line 48
    new-instance v3, Ljava/util/HashMap;

    .line 49
    .line 50
    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    .line 51
    .line 52
    .line 53
    iput-object v3, v2, Llp/f0;->d:Ljava/lang/Object;

    .line 54
    .line 55
    new-instance v3, Ljava/util/HashMap;

    .line 56
    .line 57
    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object v3, v2, Llp/f0;->e:Ljava/lang/Object;

    .line 61
    .line 62
    sget-object v3, Llp/f0;->g:Llp/d0;

    .line 63
    .line 64
    iput-object v3, v2, Llp/f0;->f:Ljava/lang/Object;

    .line 65
    .line 66
    invoke-virtual {v1, v2}, Llp/og;->a(Lat/a;)V

    .line 67
    .line 68
    .line 69
    new-instance v1, Ljava/util/HashMap;

    .line 70
    .line 71
    iget-object v3, v2, Llp/f0;->d:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v3, Ljava/util/HashMap;

    .line 74
    .line 75
    invoke-direct {v1, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 76
    .line 77
    .line 78
    new-instance v3, Ljava/util/HashMap;

    .line 79
    .line 80
    iget-object v4, v2, Llp/f0;->e:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v4, Ljava/util/HashMap;

    .line 83
    .line 84
    invoke-direct {v3, v4}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 85
    .line 86
    .line 87
    iget-object v2, v2, Llp/f0;->f:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v2, Llp/d0;

    .line 90
    .line 91
    new-instance v4, Ljava/io/ByteArrayOutputStream;

    .line 92
    .line 93
    invoke-direct {v4}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_1

    .line 94
    .line 95
    .line 96
    :try_start_1
    new-instance v5, Llp/e0;

    .line 97
    .line 98
    invoke-direct {v5, v4, v1, v3, v2}, Llp/e0;-><init>(Ljava/io/ByteArrayOutputStream;Ljava/util/HashMap;Ljava/util/HashMap;Lzs/d;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    check-cast v1, Lzs/d;

    .line 106
    .line 107
    if-eqz v1, :cond_0

    .line 108
    .line 109
    invoke-interface {v1, p0, v5}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_0
    new-instance p0, Lzs/b;

    .line 114
    .line 115
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    const-string v1, "No encoder for "

    .line 120
    .line 121
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 129
    :catch_0
    :goto_0
    :try_start_2
    invoke-virtual {v4}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 130
    .line 131
    .line 132
    move-result-object p0
    :try_end_2
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_2 .. :try_end_2} :catch_1

    .line 133
    return-object p0

    .line 134
    :catch_1
    move-exception p0

    .line 135
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 136
    .line 137
    const-string v1, "Failed to covert logging to UTF-8 byte array"

    .line 138
    .line 139
    invoke-direct {v0, v1, p0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    throw v0
.end method

.method public x(I)[B
    .locals 11

    .line 1
    const-class v0, Ljp/cc;

    .line 2
    .line 3
    iget-object v1, p0, Lbb/g0;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lin/z1;

    .line 6
    .line 7
    xor-int/lit8 v2, p1, 0x1

    .line 8
    .line 9
    iget-object v3, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Ljp/uf;

    .line 12
    .line 13
    const/4 v4, 0x1

    .line 14
    if-eq v4, v2, :cond_0

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v2, v4

    .line 19
    :goto_0
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    iput-object v2, v3, Ljp/uf;->h:Ljava/lang/Object;

    .line 24
    .line 25
    iget-object p0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Ljp/uf;

    .line 28
    .line 29
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 30
    .line 31
    iput-object v2, p0, Ljp/uf;->f:Ljava/lang/Object;

    .line 32
    .line 33
    new-instance v2, Ljp/vf;

    .line 34
    .line 35
    invoke-direct {v2, p0}, Ljp/vf;-><init>(Ljp/uf;)V

    .line 36
    .line 37
    .line 38
    iput-object v2, v1, Lin/z1;->a:Ljava/lang/Object;

    .line 39
    .line 40
    :try_start_0
    invoke-static {}, Ljp/zg;->b()V
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_2

    .line 41
    .line 42
    .line 43
    sget-object p0, Ljp/zg;->f:Ljp/zg;

    .line 44
    .line 45
    if-nez p1, :cond_1

    .line 46
    .line 47
    :try_start_1
    new-instance p1, Ljp/cc;

    .line 48
    .line 49
    invoke-direct {p1, v1}, Ljp/cc;-><init>(Lin/z1;)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Lbt/d;

    .line 53
    .line 54
    invoke-direct {v0}, Lbt/d;-><init>()V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, v0}, Ljp/zg;->a(Lat/a;)V

    .line 58
    .line 59
    .line 60
    iput-boolean v4, v0, Lbt/d;->g:Z

    .line 61
    .line 62
    new-instance v6, Ljava/io/StringWriter;

    .line 63
    .line 64
    invoke-direct {v6}, Ljava/io/StringWriter;-><init>()V
    :try_end_1
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_1 .. :try_end_1} :catch_2

    .line 65
    .line 66
    .line 67
    :try_start_2
    new-instance v5, Lbt/e;

    .line 68
    .line 69
    iget-object v7, v0, Lbt/d;->d:Ljava/util/HashMap;

    .line 70
    .line 71
    iget-object v8, v0, Lbt/d;->e:Ljava/util/HashMap;

    .line 72
    .line 73
    iget-object v9, v0, Lbt/d;->f:Lbt/a;

    .line 74
    .line 75
    iget-boolean v10, v0, Lbt/d;->g:Z

    .line 76
    .line 77
    invoke-direct/range {v5 .. v10}, Lbt/e;-><init>(Ljava/io/Writer;Ljava/util/Map;Ljava/util/Map;Lzs/d;Z)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v5, p1}, Lbt/e;->h(Ljava/lang/Object;)Lbt/e;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v5}, Lbt/e;->j()V

    .line 84
    .line 85
    .line 86
    iget-object p0, v5, Lbt/e;->b:Landroid/util/JsonWriter;

    .line 87
    .line 88
    invoke-virtual {p0}, Landroid/util/JsonWriter;->flush()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 89
    .line 90
    .line 91
    :catch_0
    :try_start_3
    invoke-virtual {v6}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    const-string p1, "utf-8"

    .line 96
    .line 97
    invoke-virtual {p0, p1}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :cond_1
    new-instance p1, Ljp/cc;

    .line 103
    .line 104
    invoke-direct {p1, v1}, Ljp/cc;-><init>(Lin/z1;)V

    .line 105
    .line 106
    .line 107
    new-instance v1, Ljp/o0;

    .line 108
    .line 109
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 110
    .line 111
    .line 112
    new-instance v2, Ljava/util/HashMap;

    .line 113
    .line 114
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 115
    .line 116
    .line 117
    iput-object v2, v1, Ljp/o0;->d:Ljava/lang/Object;

    .line 118
    .line 119
    new-instance v2, Ljava/util/HashMap;

    .line 120
    .line 121
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 122
    .line 123
    .line 124
    iput-object v2, v1, Ljp/o0;->e:Ljava/io/Serializable;

    .line 125
    .line 126
    sget-object v2, Ljp/o0;->g:Ljp/m0;

    .line 127
    .line 128
    iput-object v2, v1, Ljp/o0;->f:Ljava/lang/Object;

    .line 129
    .line 130
    invoke-virtual {p0, v1}, Ljp/zg;->a(Lat/a;)V

    .line 131
    .line 132
    .line 133
    new-instance p0, Ljava/util/HashMap;

    .line 134
    .line 135
    iget-object v2, v1, Ljp/o0;->d:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v2, Ljava/util/HashMap;

    .line 138
    .line 139
    invoke-direct {p0, v2}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 140
    .line 141
    .line 142
    new-instance v2, Ljava/util/HashMap;

    .line 143
    .line 144
    iget-object v3, v1, Ljp/o0;->e:Ljava/io/Serializable;

    .line 145
    .line 146
    check-cast v3, Ljava/util/HashMap;

    .line 147
    .line 148
    invoke-direct {v2, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 149
    .line 150
    .line 151
    iget-object v1, v1, Ljp/o0;->f:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v1, Ljp/m0;

    .line 154
    .line 155
    new-instance v3, Ljava/io/ByteArrayOutputStream;

    .line 156
    .line 157
    invoke-direct {v3}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_3
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_3 .. :try_end_3} :catch_2

    .line 158
    .line 159
    .line 160
    :try_start_4
    new-instance v4, Ljp/n0;

    .line 161
    .line 162
    invoke-direct {v4, v3, p0, v2, v1}, Ljp/n0;-><init>(Ljava/io/ByteArrayOutputStream;Ljava/util/HashMap;Ljava/util/HashMap;Lzs/d;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    check-cast p0, Lzs/d;

    .line 170
    .line 171
    if-eqz p0, :cond_2

    .line 172
    .line 173
    invoke-interface {p0, p1, v4}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    goto :goto_1

    .line 177
    :cond_2
    new-instance p0, Lzs/b;

    .line 178
    .line 179
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    const-string v0, "No encoder for "

    .line 184
    .line 185
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw p0
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1

    .line 193
    :catch_1
    :goto_1
    :try_start_5
    invoke-virtual {v3}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 194
    .line 195
    .line 196
    move-result-object p0
    :try_end_5
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_5 .. :try_end_5} :catch_2

    .line 197
    return-object p0

    .line 198
    :catch_2
    move-exception v0

    .line 199
    move-object p0, v0

    .line 200
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    .line 201
    .line 202
    const-string v0, "Failed to covert logging to UTF-8 byte array"

    .line 203
    .line 204
    invoke-direct {p1, v0, p0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 205
    .line 206
    .line 207
    throw p1
.end method
