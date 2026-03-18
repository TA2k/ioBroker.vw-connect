.class public final synthetic Lnw/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:Lnw/g;

.field public final synthetic e:Lc1/h2;

.field public final synthetic f:Landroid/graphics/Bitmap;


# direct methods
.method public synthetic constructor <init>(Lnw/g;Lc1/h2;Landroid/graphics/Bitmap;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnw/c;->d:Lnw/g;

    .line 5
    .line 6
    iput-object p2, p0, Lnw/c;->e:Lc1/h2;

    .line 7
    .line 8
    iput-object p3, p0, Lnw/c;->f:Landroid/graphics/Bitmap;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    check-cast p1, Lmw/i;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Float;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    check-cast p3, Ljava/lang/Float;

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result p3

    .line 15
    check-cast p4, Ljava/lang/Float;

    .line 16
    .line 17
    check-cast p5, Ljava/lang/Float;

    .line 18
    .line 19
    const-string p4, "entry"

    .line 20
    .line 21
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-wide p4, p1, Lmw/i;->a:D

    .line 25
    .line 26
    const-string v0, "<this>"

    .line 27
    .line 28
    iget-object v1, p0, Lnw/c;->e:Lc1/h2;

    .line 29
    .line 30
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, v1, Lc1/h2;->c:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Landroid/graphics/RectF;

    .line 36
    .line 37
    iget v1, v0, Landroid/graphics/RectF;->left:F

    .line 38
    .line 39
    const/4 v2, 0x1

    .line 40
    int-to-float v3, v2

    .line 41
    sub-float/2addr v1, v3

    .line 42
    cmpg-float v1, p2, v1

    .line 43
    .line 44
    if-lez v1, :cond_2

    .line 45
    .line 46
    iget v1, v0, Landroid/graphics/RectF;->right:F

    .line 47
    .line 48
    add-float/2addr v1, v3

    .line 49
    cmpl-float v1, p2, v1

    .line 50
    .line 51
    if-ltz v1, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    iget v1, v0, Landroid/graphics/RectF;->top:F

    .line 55
    .line 56
    iget v3, v0, Landroid/graphics/RectF;->bottom:F

    .line 57
    .line 58
    invoke-static {p3, v1, v3}, Lkp/r9;->d(FFF)F

    .line 59
    .line 60
    .line 61
    move-result p3

    .line 62
    iget-object v1, p0, Lnw/c;->d:Lnw/g;

    .line 63
    .line 64
    iget-object v1, v1, Lnw/g;->g:Ljava/util/LinkedHashMap;

    .line 65
    .line 66
    invoke-static {p4, p5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {v1, v3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    if-nez v4, :cond_1

    .line 75
    .line 76
    new-instance v4, Low/e;

    .line 77
    .line 78
    invoke-direct {v4, p4, p5, p2}, Low/e;-><init>(DF)V

    .line 79
    .line 80
    .line 81
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    invoke-interface {v1, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    :cond_1
    check-cast v4, Ljava/util/List;

    .line 89
    .line 90
    invoke-static {v4}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p4

    .line 94
    check-cast p4, Low/e;

    .line 95
    .line 96
    iget-object p4, p4, Low/e;->c:Ljava/util/List;

    .line 97
    .line 98
    check-cast p4, Ljava/util/Collection;

    .line 99
    .line 100
    new-instance p5, Low/d;

    .line 101
    .line 102
    invoke-static {p2}, Lcy0/a;->i(F)I

    .line 103
    .line 104
    .line 105
    move-result p2

    .line 106
    iget v1, v0, Landroid/graphics/RectF;->left:F

    .line 107
    .line 108
    float-to-double v3, v1

    .line 109
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 110
    .line 111
    .line 112
    move-result-wide v3

    .line 113
    double-to-float v1, v3

    .line 114
    float-to-int v1, v1

    .line 115
    iget v0, v0, Landroid/graphics/RectF;->right:F

    .line 116
    .line 117
    float-to-int v0, v0

    .line 118
    sub-int/2addr v0, v2

    .line 119
    invoke-static {p2, v1, v0}, Lkp/r9;->e(III)I

    .line 120
    .line 121
    .line 122
    move-result p2

    .line 123
    invoke-static {p3}, Lcy0/a;->i(F)I

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    iget-object p0, p0, Lnw/c;->f:Landroid/graphics/Bitmap;

    .line 128
    .line 129
    invoke-virtual {p0, p2, v0}, Landroid/graphics/Bitmap;->getPixel(II)I

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    invoke-direct {p5, p1, p3, p0}, Low/d;-><init>(Lmw/i;FI)V

    .line 134
    .line 135
    .line 136
    invoke-interface {p4, p5}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0
.end method
