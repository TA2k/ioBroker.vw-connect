.class public final Lu/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lap0/o;Lk21/a;Lhy0/d;)V
    .locals 6

    const/4 v5, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    .line 1
    invoke-direct/range {v0 .. v5}, Lu/x0;-><init>(Lap0/o;Lk21/a;Lhy0/d;Lh21/a;Lg21/a;)V

    return-void
.end method

.method public constructor <init>(Lap0/o;Lk21/a;Lhy0/d;Lh21/a;Lg21/a;)V
    .locals 1

    const-string v0, "logger"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "scope"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "clazz"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 4
    iput-object p2, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 5
    iput-object p3, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 6
    iput-object p4, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 7
    iput-object p5, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 8
    new-instance p1, Ljava/lang/StringBuilder;

    const-string p2, "t:\'"

    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {p3}, Lm21/a;->a(Lhy0/d;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "\' - q:\'"

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p2, 0x27

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lu/x0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lf8/p;Landroid/media/MediaFormat;Lt7/o;Landroid/view/Surface;Landroid/media/MediaCrypto;Lgw0/c;)V
    .locals 0

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    iput-object p1, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 20
    iput-object p2, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 21
    iput-object p3, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 22
    iput-object p4, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 23
    iput-object p5, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 24
    iput-object p6, p0, Lu/x0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lr7/a;Lay0/n;)V
    .locals 4

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p1, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 11
    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 12
    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 13
    new-instance p2, Lzb/c0;

    sget-object v0, Lmx0/s;->d:Lmx0/s;

    invoke-direct {p2, v0}, Lzb/c0;-><init>(Ljava/util/List;)V

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 14
    new-instance v1, Lzb/r;

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-direct {v1, p0, v2, v3}, Lzb/r;-><init>(Lu/x0;Lkotlin/coroutines/Continuation;I)V

    .line 15
    new-instance v2, Lne0/n;

    invoke-direct {v2, v1, p2}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 16
    new-instance p2, Lzb/c0;

    invoke-direct {p2, v0}, Lzb/c0;-><init>(Ljava/util/List;)V

    sget-object v0, Lyy0/u1;->b:Lyy0/w1;

    invoke-static {v2, p1, v0, p2}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    move-result-object p1

    iput-object p1, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 17
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Lu/x0;->f:Ljava/lang/Object;

    return-void
.end method

.method public static final a(Lu/x0;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lu/x0;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 4
    .line 5
    instance-of v1, p1, Lzb/s;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lzb/s;

    .line 11
    .line 12
    iget v2, v1, Lzb/s;->f:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lzb/s;->f:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lzb/s;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lzb/s;-><init>(Lu/x0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v1, Lzb/s;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lzb/s;->f:I

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    const/4 v5, 0x1

    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    if-ne v3, v5, :cond_1

    .line 40
    .line 41
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :catchall_0
    move-exception p0

    .line 46
    goto :goto_2

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :try_start_1
    invoke-virtual {v0, v4, v5}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-eqz p1, :cond_3

    .line 63
    .line 64
    iput v5, v1, Lzb/s;->f:I

    .line 65
    .line 66
    invoke-static {p0, v1}, Lu/x0;->j(Lu/x0;Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 70
    if-ne p0, v2, :cond_3

    .line 71
    .line 72
    return-object v2

    .line 73
    :cond_3
    :goto_1
    invoke-virtual {v0, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 74
    .line 75
    .line 76
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0

    .line 79
    :goto_2
    invoke-virtual {v0, v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 80
    .line 81
    .line 82
    throw p0
.end method

.method public static b(I[I)Z
    .locals 4

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    :goto_0
    if-ge v2, v0, :cond_1

    .line 5
    .line 6
    aget v3, p1, v2

    .line 7
    .line 8
    if-ne v3, p0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    return v1
.end method

.method public static d(Landroid/content/Context;I)Landroid/content/res/ColorStateList;
    .locals 6

    .line 1
    const v0, 0x7f04011e

    .line 2
    .line 3
    .line 4
    invoke-static {p0, v0}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const v1, 0x7f040119

    .line 9
    .line 10
    .line 11
    invoke-static {p0, v1}, Lm/m2;->b(Landroid/content/Context;I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    sget-object v1, Lm/m2;->b:[I

    .line 16
    .line 17
    sget-object v2, Lm/m2;->d:[I

    .line 18
    .line 19
    invoke-static {v0, p1}, Ls5/a;->c(II)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    sget-object v4, Lm/m2;->c:[I

    .line 24
    .line 25
    invoke-static {v0, p1}, Ls5/a;->c(II)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    sget-object v5, Lm/m2;->f:[I

    .line 30
    .line 31
    filled-new-array {v1, v2, v4, v5}, [[I

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    filled-new-array {p0, v3, v0, p1}, [I

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    new-instance p1, Landroid/content/res/ColorStateList;

    .line 40
    .line 41
    invoke-direct {p1, v1, p0}, Landroid/content/res/ColorStateList;-><init>([[I[I)V

    .line 42
    .line 43
    .line 44
    return-object p1
.end method

.method public static g(Lm/h2;Landroid/content/Context;I)Landroid/graphics/drawable/LayerDrawable;
    .locals 4

    .line 1
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p2}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    const v0, 0x7f08007b

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, p1, v0}, Lm/h2;->c(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const v1, 0x7f08007c

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, p1, v1}, Lm/h2;->c(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    instance-of p1, v0, Landroid/graphics/drawable/BitmapDrawable;

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-ne p1, p2, :cond_0

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-ne p1, p2, :cond_0

    .line 39
    .line 40
    check-cast v0, Landroid/graphics/drawable/BitmapDrawable;

    .line 41
    .line 42
    new-instance p1, Landroid/graphics/drawable/BitmapDrawable;

    .line 43
    .line 44
    invoke-virtual {v0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-direct {p1, v2}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/graphics/Bitmap;)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    sget-object p1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 53
    .line 54
    invoke-static {p2, p2, p1}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    new-instance v2, Landroid/graphics/Canvas;

    .line 59
    .line 60
    invoke-direct {v2, p1}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, v1, v1, p2, p2}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, v2}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 67
    .line 68
    .line 69
    new-instance v0, Landroid/graphics/drawable/BitmapDrawable;

    .line 70
    .line 71
    invoke-direct {v0, p1}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/graphics/Bitmap;)V

    .line 72
    .line 73
    .line 74
    new-instance v2, Landroid/graphics/drawable/BitmapDrawable;

    .line 75
    .line 76
    invoke-direct {v2, p1}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/graphics/Bitmap;)V

    .line 77
    .line 78
    .line 79
    move-object p1, v2

    .line 80
    :goto_0
    sget-object v2, Landroid/graphics/Shader$TileMode;->REPEAT:Landroid/graphics/Shader$TileMode;

    .line 81
    .line 82
    invoke-virtual {p1, v2}, Landroid/graphics/drawable/BitmapDrawable;->setTileModeX(Landroid/graphics/Shader$TileMode;)V

    .line 83
    .line 84
    .line 85
    instance-of v2, p0, Landroid/graphics/drawable/BitmapDrawable;

    .line 86
    .line 87
    if-eqz v2, :cond_1

    .line 88
    .line 89
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    if-ne v2, p2, :cond_1

    .line 94
    .line 95
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-ne v2, p2, :cond_1

    .line 100
    .line 101
    check-cast p0, Landroid/graphics/drawable/BitmapDrawable;

    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_1
    sget-object v2, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 105
    .line 106
    invoke-static {p2, p2, v2}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    new-instance v3, Landroid/graphics/Canvas;

    .line 111
    .line 112
    invoke-direct {v3, v2}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0, v1, v1, p2, p2}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p0, v3}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 119
    .line 120
    .line 121
    new-instance p0, Landroid/graphics/drawable/BitmapDrawable;

    .line 122
    .line 123
    invoke-direct {p0, v2}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/graphics/Bitmap;)V

    .line 124
    .line 125
    .line 126
    :goto_1
    new-instance p2, Landroid/graphics/drawable/LayerDrawable;

    .line 127
    .line 128
    const/4 v2, 0x3

    .line 129
    new-array v2, v2, [Landroid/graphics/drawable/Drawable;

    .line 130
    .line 131
    aput-object v0, v2, v1

    .line 132
    .line 133
    const/4 v0, 0x1

    .line 134
    aput-object p0, v2, v0

    .line 135
    .line 136
    const/4 p0, 0x2

    .line 137
    aput-object p1, v2, p0

    .line 138
    .line 139
    invoke-direct {p2, v2}, Landroid/graphics/drawable/LayerDrawable;-><init>([Landroid/graphics/drawable/Drawable;)V

    .line 140
    .line 141
    .line 142
    const/high16 p1, 0x1020000

    .line 143
    .line 144
    invoke-virtual {p2, v1, p1}, Landroid/graphics/drawable/LayerDrawable;->setId(II)V

    .line 145
    .line 146
    .line 147
    const p1, 0x102000f

    .line 148
    .line 149
    .line 150
    invoke-virtual {p2, v0, p1}, Landroid/graphics/drawable/LayerDrawable;->setId(II)V

    .line 151
    .line 152
    .line 153
    const p1, 0x102000d

    .line 154
    .line 155
    .line 156
    invoke-virtual {p2, p0, p1}, Landroid/graphics/drawable/LayerDrawable;->setId(II)V

    .line 157
    .line 158
    .line 159
    return-object p2
.end method

.method public static final j(Lu/x0;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lzb/t;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzb/t;

    .line 7
    .line 8
    iget v1, v0, Lzb/t;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lzb/t;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzb/t;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lzb/t;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzb/t;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget-object p0, v0, Lzb/t;->e:Lzb/d0;

    .line 38
    .line 39
    iget-object v0, v0, Lzb/t;->d:Lu/x0;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    move-object v7, p1

    .line 45
    move-object p1, p0

    .line 46
    move-object p0, v0

    .line 47
    move-object v0, v7

    .line 48
    goto :goto_2

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Lyy0/c2;

    .line 63
    .line 64
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p1, Lzb/d0;

    .line 69
    .line 70
    iget-object v2, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v2, Lyy0/c2;

    .line 73
    .line 74
    new-instance v5, Lzb/c0;

    .line 75
    .line 76
    invoke-virtual {p1}, Lzb/d0;->a()Ljava/util/List;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    invoke-direct {v5, v6}, Lzb/c0;-><init>(Ljava/util/List;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2, v3, v5}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    iget-object v2, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v2, Lrx0/i;

    .line 92
    .line 93
    instance-of v5, p1, Lzb/a0;

    .line 94
    .line 95
    if-eqz v5, :cond_3

    .line 96
    .line 97
    move-object v5, p1

    .line 98
    check-cast v5, Lzb/a0;

    .line 99
    .line 100
    iget-object v5, v5, Lzb/a0;->c:Ljava/lang/Object;

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    instance-of v5, p1, Lzb/b0;

    .line 104
    .line 105
    if-eqz v5, :cond_4

    .line 106
    .line 107
    move-object v5, p1

    .line 108
    check-cast v5, Lzb/b0;

    .line 109
    .line 110
    iget-object v5, v5, Lzb/b0;->b:Ljava/lang/Object;

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_4
    move-object v5, v3

    .line 114
    :goto_1
    iput-object p0, v0, Lzb/t;->d:Lu/x0;

    .line 115
    .line 116
    iput-object p1, v0, Lzb/t;->e:Lzb/d0;

    .line 117
    .line 118
    iput v4, v0, Lzb/t;->g:I

    .line 119
    .line 120
    invoke-interface {v2, v5, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    if-ne v0, v1, :cond_5

    .line 125
    .line 126
    return-object v1

    .line 127
    :cond_5
    :goto_2
    check-cast v0, Llx0/o;

    .line 128
    .line 129
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 130
    .line 131
    iget-object v1, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v1, Lyy0/c2;

    .line 134
    .line 135
    iget-object p0, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p0, Ljava/util/ArrayList;

    .line 138
    .line 139
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    if-nez v2, :cond_7

    .line 144
    .line 145
    check-cast v0, Lzb/y;

    .line 146
    .line 147
    iget-object p1, v0, Lzb/y;->b:Ljava/lang/Object;

    .line 148
    .line 149
    iget-object v2, v0, Lzb/y;->a:Ljava/util/ArrayList;

    .line 150
    .line 151
    if-nez p1, :cond_6

    .line 152
    .line 153
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 154
    .line 155
    .line 156
    new-instance p1, Lzb/z;

    .line 157
    .line 158
    invoke-static {p0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    invoke-direct {p1, p0}, Lzb/z;-><init>(Ljava/util/List;)V

    .line 163
    .line 164
    .line 165
    goto :goto_4

    .line 166
    :cond_6
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 167
    .line 168
    .line 169
    new-instance p1, Lzb/b0;

    .line 170
    .line 171
    invoke-static {p0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    iget-object v0, v0, Lzb/y;->b:Ljava/lang/Object;

    .line 176
    .line 177
    invoke-direct {p1, p0, v0}, Lzb/b0;-><init>(Ljava/util/List;Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    goto :goto_4

    .line 181
    :cond_7
    new-instance p0, Lzb/a0;

    .line 182
    .line 183
    invoke-virtual {p1}, Lzb/d0;->a()Ljava/util/List;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    instance-of v4, p1, Lzb/a0;

    .line 188
    .line 189
    if-eqz v4, :cond_8

    .line 190
    .line 191
    check-cast p1, Lzb/a0;

    .line 192
    .line 193
    iget-object p1, p1, Lzb/a0;->c:Ljava/lang/Object;

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_8
    instance-of v4, p1, Lzb/b0;

    .line 197
    .line 198
    if-eqz v4, :cond_9

    .line 199
    .line 200
    check-cast p1, Lzb/b0;

    .line 201
    .line 202
    iget-object p1, p1, Lzb/b0;->b:Ljava/lang/Object;

    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_9
    move-object p1, v3

    .line 206
    :goto_3
    invoke-direct {p0, v0, v2, p1}, Lzb/a0;-><init>(Ljava/util/List;Ljava/lang/Throwable;Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    move-object p1, p0

    .line 210
    :goto_4
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    invoke-virtual {v1, v3, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 217
    .line 218
    return-object p0
.end method

.method public static o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    sget-object p2, Lm/s;->b:Landroid/graphics/PorterDuff$Mode;

    .line 8
    .line 9
    :cond_0
    invoke-static {p1, p2}, Lm/s;->c(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuffColorFilter;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public declared-synchronized c()Lh6/e;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Ljava/lang/String;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Lu/x0;->m()Lhu/q;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception v0

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    :goto_0
    invoke-virtual {p0}, Lu/x0;->l()Lj1/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lu/x0;->f:Ljava/lang/Object;

    .line 22
    .line 23
    new-instance v0, Lh6/e;

    .line 24
    .line 25
    const/16 v1, 0x18

    .line 26
    .line 27
    invoke-direct {v0, v1}, Lh6/e;-><init>(I)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Lu/x0;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Lj1/a;

    .line 33
    .line 34
    iput-object v1, v0, Lh6/e;->e:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    .line 36
    monitor-exit p0

    .line 37
    return-object v0

    .line 38
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 39
    throw v0
.end method

.method public e()Lh0/z1;
    .locals 6

    .line 1
    new-instance v0, Landroid/graphics/SurfaceTexture;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Landroid/graphics/SurfaceTexture;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Landroid/util/Size;

    .line 10
    .line 11
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-virtual {v0, v2, v3}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 20
    .line 21
    .line 22
    new-instance v2, Landroid/view/Surface;

    .line 23
    .line 24
    invoke-direct {v2, v0}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 25
    .line 26
    .line 27
    iget-object v3, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v3, Lu/w0;

    .line 30
    .line 31
    invoke-static {v3, v1}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    const/4 v3, 0x1

    .line 36
    iget-object v4, v1, Lh0/u1;->b:Lb0/n1;

    .line 37
    .line 38
    iput v3, v4, Lb0/n1;->d:I

    .line 39
    .line 40
    new-instance v3, Lb0/u1;

    .line 41
    .line 42
    invoke-direct {v3, v2}, Lb0/u1;-><init>(Landroid/view/Surface;)V

    .line 43
    .line 44
    .line 45
    iput-object v3, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 46
    .line 47
    iget-object v3, v3, Lh0/t0;->e:Ly4/k;

    .line 48
    .line 49
    invoke-static {v3}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    new-instance v4, Lb81/d;

    .line 54
    .line 55
    const/16 v5, 0x16

    .line 56
    .line 57
    invoke-direct {v4, v5, v2, v0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    new-instance v2, Lk0/g;

    .line 65
    .line 66
    const/4 v5, 0x0

    .line 67
    invoke-direct {v2, v5, v3, v4}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    invoke-interface {v3, v0, v2}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 71
    .line 72
    .line 73
    iget-object v0, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v0, Lb0/u1;

    .line 76
    .line 77
    sget-object v2, Lb0/y;->d:Lb0/y;

    .line 78
    .line 79
    const/4 v3, -0x1

    .line 80
    invoke-virtual {v1, v0, v2, v3}, Lh0/v1;->b(Lh0/t0;Lb0/y;I)V

    .line 81
    .line 82
    .line 83
    iget-object v0, p0, Lu/x0;->f:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Lh0/w1;

    .line 86
    .line 87
    if-eqz v0, :cond_0

    .line 88
    .line 89
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 90
    .line 91
    .line 92
    :cond_0
    new-instance v0, Lh0/w1;

    .line 93
    .line 94
    new-instance v2, Lb0/q0;

    .line 95
    .line 96
    const/4 v3, 0x3

    .line 97
    invoke-direct {v2, p0, v3}, Lb0/q0;-><init>(Ljava/lang/Object;I)V

    .line 98
    .line 99
    .line 100
    invoke-direct {v0, v2}, Lh0/w1;-><init>(Lh0/x1;)V

    .line 101
    .line 102
    .line 103
    iput-object v0, p0, Lu/x0;->f:Ljava/lang/Object;

    .line 104
    .line 105
    iput-object v0, v1, Lh0/u1;->f:Lh0/w1;

    .line 106
    .line 107
    invoke-virtual {v1}, Lh0/v1;->c()Lh0/z1;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0
.end method

.method public f()Ljava/util/ArrayList;
    .locals 2

    .line 1
    iget-object v0, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    new-instance v1, Ljava/util/ArrayList;

    .line 5
    .line 6
    iget-object p0, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/LinkedHashSet;

    .line 9
    .line 10
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 11
    .line 12
    .line 13
    monitor-exit v0

    .line 14
    return-object v1

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method

.method public h()Ljava/util/ArrayList;
    .locals 4

    .line 1
    iget-object v0, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    new-instance v1, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lu/x0;->f()Ljava/util/ArrayList;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 14
    .line 15
    .line 16
    iget-object v2, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    :try_start_1
    new-instance v3, Ljava/util/ArrayList;

    .line 20
    .line 21
    iget-object p0, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Ljava/util/LinkedHashSet;

    .line 24
    .line 25
    invoke-direct {v3, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 26
    .line 27
    .line 28
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 29
    :try_start_2
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 30
    .line 31
    .line 32
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 33
    return-object v1

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto :goto_0

    .line 36
    :catchall_1
    move-exception p0

    .line 37
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 38
    :try_start_4
    throw p0

    .line 39
    :goto_0
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 40
    throw p0
.end method

.method public i(Landroid/content/Context;I)Landroid/content/res/ColorStateList;
    .locals 7

    .line 1
    const v0, 0x7f080050

    .line 2
    .line 3
    .line 4
    if-ne p2, v0, :cond_0

    .line 5
    .line 6
    const p0, 0x7f060015

    .line 7
    .line 8
    .line 9
    invoke-static {p1, p0}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    const v0, 0x7f08007e

    .line 15
    .line 16
    .line 17
    if-ne p2, v0, :cond_1

    .line 18
    .line 19
    const p0, 0x7f060018

    .line 20
    .line 21
    .line 22
    invoke-static {p1, p0}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_1
    const v0, 0x7f08007d

    .line 28
    .line 29
    .line 30
    const/4 v1, 0x0

    .line 31
    if-ne p2, v0, :cond_3

    .line 32
    .line 33
    const/4 p0, 0x3

    .line 34
    new-array p2, p0, [[I

    .line 35
    .line 36
    new-array p0, p0, [I

    .line 37
    .line 38
    const v0, 0x7f040152

    .line 39
    .line 40
    .line 41
    invoke-static {p1, v0}, Lm/m2;->d(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    const/4 v3, 0x2

    .line 46
    const v4, 0x7f04011d

    .line 47
    .line 48
    .line 49
    const/4 v5, 0x1

    .line 50
    if-eqz v2, :cond_2

    .line 51
    .line 52
    invoke-virtual {v2}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    if-eqz v6, :cond_2

    .line 57
    .line 58
    sget-object v0, Lm/m2;->b:[I

    .line 59
    .line 60
    aput-object v0, p2, v1

    .line 61
    .line 62
    invoke-virtual {v2, v0, v1}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    aput v0, p0, v1

    .line 67
    .line 68
    sget-object v0, Lm/m2;->e:[I

    .line 69
    .line 70
    aput-object v0, p2, v5

    .line 71
    .line 72
    invoke-static {p1, v4}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    aput p1, p0, v5

    .line 77
    .line 78
    sget-object p1, Lm/m2;->f:[I

    .line 79
    .line 80
    aput-object p1, p2, v3

    .line 81
    .line 82
    invoke-virtual {v2}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    aput p1, p0, v3

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_2
    sget-object v2, Lm/m2;->b:[I

    .line 90
    .line 91
    aput-object v2, p2, v1

    .line 92
    .line 93
    invoke-static {p1, v0}, Lm/m2;->b(Landroid/content/Context;I)I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    aput v2, p0, v1

    .line 98
    .line 99
    sget-object v1, Lm/m2;->e:[I

    .line 100
    .line 101
    aput-object v1, p2, v5

    .line 102
    .line 103
    invoke-static {p1, v4}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    aput v1, p0, v5

    .line 108
    .line 109
    sget-object v1, Lm/m2;->f:[I

    .line 110
    .line 111
    aput-object v1, p2, v3

    .line 112
    .line 113
    invoke-static {p1, v0}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    aput p1, p0, v3

    .line 118
    .line 119
    :goto_0
    new-instance p1, Landroid/content/res/ColorStateList;

    .line 120
    .line 121
    invoke-direct {p1, p2, p0}, Landroid/content/res/ColorStateList;-><init>([[I[I)V

    .line 122
    .line 123
    .line 124
    return-object p1

    .line 125
    :cond_3
    const v0, 0x7f080044

    .line 126
    .line 127
    .line 128
    if-ne p2, v0, :cond_4

    .line 129
    .line 130
    const p0, 0x7f040119

    .line 131
    .line 132
    .line 133
    invoke-static {p1, p0}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    invoke-static {p1, p0}, Lu/x0;->d(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    return-object p0

    .line 142
    :cond_4
    const v0, 0x7f08003e

    .line 143
    .line 144
    .line 145
    if-ne p2, v0, :cond_5

    .line 146
    .line 147
    invoke-static {p1, v1}, Lu/x0;->d(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :cond_5
    const v0, 0x7f080043

    .line 153
    .line 154
    .line 155
    if-ne p2, v0, :cond_6

    .line 156
    .line 157
    const p0, 0x7f040117

    .line 158
    .line 159
    .line 160
    invoke-static {p1, p0}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    invoke-static {p1, p0}, Lu/x0;->d(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    return-object p0

    .line 169
    :cond_6
    const v0, 0x7f080079

    .line 170
    .line 171
    .line 172
    if-eq p2, v0, :cond_c

    .line 173
    .line 174
    const v0, 0x7f08007a

    .line 175
    .line 176
    .line 177
    if-ne p2, v0, :cond_7

    .line 178
    .line 179
    goto :goto_1

    .line 180
    :cond_7
    iget-object v0, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v0, [I

    .line 183
    .line 184
    invoke-static {p2, v0}, Lu/x0;->b(I[I)Z

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    if-eqz v0, :cond_8

    .line 189
    .line 190
    const p0, 0x7f04011f

    .line 191
    .line 192
    .line 193
    invoke-static {p1, p0}, Lm/m2;->d(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    return-object p0

    .line 198
    :cond_8
    iget-object v0, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v0, [I

    .line 201
    .line 202
    invoke-static {p2, v0}, Lu/x0;->b(I[I)Z

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    if-eqz v0, :cond_9

    .line 207
    .line 208
    const p0, 0x7f060014

    .line 209
    .line 210
    .line 211
    invoke-static {p1, p0}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    return-object p0

    .line 216
    :cond_9
    iget-object p0, p0, Lu/x0;->f:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast p0, [I

    .line 219
    .line 220
    invoke-static {p2, p0}, Lu/x0;->b(I[I)Z

    .line 221
    .line 222
    .line 223
    move-result p0

    .line 224
    if-eqz p0, :cond_a

    .line 225
    .line 226
    const p0, 0x7f060013

    .line 227
    .line 228
    .line 229
    invoke-static {p1, p0}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    return-object p0

    .line 234
    :cond_a
    const p0, 0x7f080076

    .line 235
    .line 236
    .line 237
    if-ne p2, p0, :cond_b

    .line 238
    .line 239
    const p0, 0x7f060016

    .line 240
    .line 241
    .line 242
    invoke-static {p1, p0}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    return-object p0

    .line 247
    :cond_b
    const/4 p0, 0x0

    .line 248
    return-object p0

    .line 249
    :cond_c
    :goto_1
    const p0, 0x7f060017

    .line 250
    .line 251
    .line 252
    invoke-static {p1, p0}, Ln5/a;->c(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    return-object p0
.end method

.method public k(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Lzb/d0;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lzb/d0;

    .line 16
    .line 17
    invoke-virtual {v0}, Lzb/d0;->a()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    add-int/lit8 v0, v0, -0x5

    .line 26
    .line 27
    if-gt v0, p1, :cond_0

    .line 28
    .line 29
    instance-of p1, v1, Lzb/b0;

    .line 30
    .line 31
    if-eqz p1, :cond_0

    .line 32
    .line 33
    iget-object p1, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Lr7/a;

    .line 36
    .line 37
    new-instance v0, Lzb/r;

    .line 38
    .line 39
    const/4 v1, 0x1

    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-direct {v0, p0, v2, v1}, Lzb/r;-><init>(Lu/x0;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x3

    .line 45
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    :cond_0
    return-void
.end method

.method public l()Lj1/a;
    .locals 10

    .line 1
    const/16 v0, 0x11

    .line 2
    .line 3
    :try_start_0
    iget-object v1, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lhu/q;
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    const/4 v2, 0x5

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    :try_start_1
    iget-object v3, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v3, Lh6/e;

    .line 13
    .line 14
    invoke-static {v3, v1}, Lhu/q;->N(Lh6/e;Lhu/q;)Lhu/q;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    new-instance v3, Lj1/a;

    .line 19
    .line 20
    iget-object v1, v1, Lhu/q;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Lqr/y;

    .line 23
    .line 24
    invoke-virtual {v1, v2}, Lqr/y;->f(I)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 29
    .line 30
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/v;->d(Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 31
    .line 32
    .line 33
    check-cast v4, Lqr/v;

    .line 34
    .line 35
    invoke-direct {v3, v4, v0}, Lj1/a;-><init>(Ljava/lang/Object;I)V
    :try_end_1
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/security/GeneralSecurityException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/io/FileNotFoundException; {:try_start_1 .. :try_end_1} :catch_0

    .line 36
    .line 37
    .line 38
    return-object v3

    .line 39
    :catch_0
    move-exception v1

    .line 40
    goto :goto_0

    .line 41
    :catch_1
    move-exception v1

    .line 42
    :try_start_2
    const-string v3, "e"

    .line 43
    .line 44
    const-string v4, "cannot decrypt keyset: "

    .line 45
    .line 46
    invoke-static {v3, v4, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 47
    .line 48
    .line 49
    :cond_0
    iget-object v1, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Lh6/e;

    .line 52
    .line 53
    invoke-virtual {v1}, Lh6/e;->z()[B

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    invoke-static {v1, v3}, Lqr/y;->t([BLcom/google/crypto/tink/shaded/protobuf/p;)Lqr/y;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-virtual {v1}, Lqr/y;->p()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-lez v3, :cond_1

    .line 70
    .line 71
    new-instance v3, Lj1/a;

    .line 72
    .line 73
    invoke-virtual {v1, v2}, Lqr/y;->f(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 78
    .line 79
    invoke-virtual {v2, v1}, Lcom/google/crypto/tink/shaded/protobuf/v;->d(Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 80
    .line 81
    .line 82
    check-cast v2, Lqr/v;

    .line 83
    .line 84
    invoke-direct {v3, v2, v0}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 85
    .line 86
    .line 87
    return-object v3

    .line 88
    :cond_1
    new-instance v1, Ljava/security/GeneralSecurityException;

    .line 89
    .line 90
    const-string v2, "empty keyset"

    .line 91
    .line 92
    invoke-direct {v1, v2}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw v1
    :try_end_2
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_0

    .line 96
    :goto_0
    const-string v2, "e"

    .line 97
    .line 98
    const-string v3, "keyset not found, will generate a new one"

    .line 99
    .line 100
    invoke-static {v2, v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 101
    .line 102
    .line 103
    iget-object v1, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v1, Lh6/e;

    .line 106
    .line 107
    if-eqz v1, :cond_9

    .line 108
    .line 109
    new-instance v1, Lj1/a;

    .line 110
    .line 111
    invoke-static {}, Lqr/y;->s()Lqr/v;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    invoke-direct {v1, v2, v0}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 116
    .line 117
    .line 118
    iget-object v0, p0, Lu/x0;->e:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v0, Lh6/e;

    .line 121
    .line 122
    monitor-enter v1

    .line 123
    :try_start_3
    iget-object v0, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lqr/t;

    .line 126
    .line 127
    monitor-enter v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 128
    :try_start_4
    invoke-virtual {v1, v0}, Lj1/a;->t(Lqr/t;)Lqr/x;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 133
    .line 134
    .line 135
    iget-object v2, v2, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 136
    .line 137
    check-cast v2, Lqr/y;

    .line 138
    .line 139
    invoke-static {v2, v0}, Lqr/y;->n(Lqr/y;Lqr/x;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 140
    .line 141
    .line 142
    :try_start_5
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 143
    monitor-exit v1

    .line 144
    invoke-virtual {v1}, Lj1/a;->p()Lhu/q;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    iget-object v0, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v0, Lqr/y;

    .line 151
    .line 152
    invoke-static {v0}, Lmr/h;->a(Lqr/y;)Lqr/c0;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    invoke-virtual {v0}, Lqr/c0;->o()Lqr/b0;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    invoke-virtual {v0}, Lqr/b0;->q()I

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    monitor-enter v1

    .line 165
    const/4 v2, 0x0

    .line 166
    move v3, v2

    .line 167
    :goto_1
    :try_start_6
    iget-object v4, v1, Lj1/a;->e:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v4, Lqr/v;

    .line 170
    .line 171
    iget-object v4, v4, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 172
    .line 173
    check-cast v4, Lqr/y;

    .line 174
    .line 175
    invoke-virtual {v4}, Lqr/y;->p()I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    if-ge v3, v4, :cond_8

    .line 180
    .line 181
    iget-object v4, v1, Lj1/a;->e:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v4, Lqr/v;

    .line 184
    .line 185
    iget-object v4, v4, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 186
    .line 187
    check-cast v4, Lqr/y;

    .line 188
    .line 189
    invoke-virtual {v4, v3}, Lqr/y;->o(I)Lqr/x;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    invoke-virtual {v4}, Lqr/x;->r()I

    .line 194
    .line 195
    .line 196
    move-result v5

    .line 197
    if-ne v5, v0, :cond_7

    .line 198
    .line 199
    invoke-virtual {v4}, Lqr/x;->t()Lqr/r;

    .line 200
    .line 201
    .line 202
    move-result-object v3

    .line 203
    sget-object v4, Lqr/r;->f:Lqr/r;

    .line 204
    .line 205
    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v3

    .line 209
    if-eqz v3, :cond_6

    .line 210
    .line 211
    iget-object v3, v1, Lj1/a;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v3, Lqr/v;

    .line 214
    .line 215
    invoke-virtual {v3}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 216
    .line 217
    .line 218
    iget-object v3, v3, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 219
    .line 220
    check-cast v3, Lqr/y;

    .line 221
    .line 222
    invoke-static {v3, v0}, Lqr/y;->m(Lqr/y;I)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 223
    .line 224
    .line 225
    monitor-exit v1

    .line 226
    iget-object v0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast v0, Lhu/q;

    .line 229
    .line 230
    if-eqz v0, :cond_4

    .line 231
    .line 232
    invoke-virtual {v1}, Lj1/a;->p()Lhu/q;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    iget-object v3, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast v3, Lhu/q;

    .line 239
    .line 240
    iget-object p0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast p0, Lhu/q;

    .line 243
    .line 244
    iget-object v0, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast v0, Lqr/y;

    .line 247
    .line 248
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/a;->c()[B

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    new-array v5, v2, [B

    .line 253
    .line 254
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 255
    .line 256
    .line 257
    :try_start_7
    invoke-virtual {p0, v4, v5}, Lhu/q;->z([B[B)[B

    .line 258
    .line 259
    .line 260
    move-result-object v4
    :try_end_7
    .catch Ljava/security/ProviderException; {:try_start_7 .. :try_end_7} :catch_2
    .catch Ljava/security/GeneralSecurityException; {:try_start_7 .. :try_end_7} :catch_2

    .line 261
    goto :goto_2

    .line 262
    :catch_2
    move-exception v6

    .line 263
    const-string v7, "q"

    .line 264
    .line 265
    const-string v8, "encountered a potentially transient KeyStore error, will wait and retry"

    .line 266
    .line 267
    invoke-static {v7, v8, v6}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 268
    .line 269
    .line 270
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 271
    .line 272
    .line 273
    move-result-wide v6

    .line 274
    const-wide/high16 v8, 0x4059000000000000L    # 100.0

    .line 275
    .line 276
    mul-double/2addr v6, v8

    .line 277
    double-to-int v6, v6

    .line 278
    int-to-long v6, v6

    .line 279
    :try_start_8
    invoke-static {v6, v7}, Ljava/lang/Thread;->sleep(J)V
    :try_end_8
    .catch Ljava/lang/InterruptedException; {:try_start_8 .. :try_end_8} :catch_3

    .line 280
    .line 281
    .line 282
    :catch_3
    invoke-virtual {p0, v4, v5}, Lhu/q;->z([B[B)[B

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    :goto_2
    :try_start_9
    new-array v5, v2, [B

    .line 287
    .line 288
    invoke-virtual {p0, v4, v5}, Lhu/q;->w([B[B)[B

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 293
    .line 294
    .line 295
    move-result-object v5

    .line 296
    invoke-static {p0, v5}, Lqr/y;->t([BLcom/google/crypto/tink/shaded/protobuf/p;)Lqr/y;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->equals(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result p0
    :try_end_9
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_9 .. :try_end_9} :catch_4

    .line 304
    if-eqz p0, :cond_3

    .line 305
    .line 306
    invoke-static {}, Lqr/g;->p()Lqr/f;

    .line 307
    .line 308
    .line 309
    move-result-object p0

    .line 310
    array-length v5, v4

    .line 311
    invoke-static {v4, v2, v5}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 312
    .line 313
    .line 314
    move-result-object v2

    .line 315
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 316
    .line 317
    .line 318
    iget-object v4, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 319
    .line 320
    check-cast v4, Lqr/g;

    .line 321
    .line 322
    invoke-static {v4, v2}, Lqr/g;->m(Lqr/g;Lcom/google/crypto/tink/shaded/protobuf/h;)V

    .line 323
    .line 324
    .line 325
    invoke-static {v0}, Lmr/h;->a(Lqr/y;)Lqr/c0;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 330
    .line 331
    .line 332
    iget-object v2, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 333
    .line 334
    check-cast v2, Lqr/g;

    .line 335
    .line 336
    invoke-static {v2, v0}, Lqr/g;->n(Lqr/g;Lqr/c0;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 340
    .line 341
    .line 342
    move-result-object p0

    .line 343
    check-cast p0, Lqr/g;

    .line 344
    .line 345
    iget-object v0, v3, Lhu/q;->e:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v0, Landroid/content/SharedPreferences$Editor;

    .line 348
    .line 349
    const-string v2, "core-google-shortcuts.TINK_KEYSET"

    .line 350
    .line 351
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/a;->c()[B

    .line 352
    .line 353
    .line 354
    move-result-object p0

    .line 355
    invoke-static {p0}, Lkp/d6;->b([B)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object p0

    .line 359
    invoke-interface {v0, v2, p0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->commit()Z

    .line 364
    .line 365
    .line 366
    move-result p0

    .line 367
    if-eqz p0, :cond_2

    .line 368
    .line 369
    goto :goto_3

    .line 370
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 371
    .line 372
    const-string v0, "Failed to write to SharedPreferences"

    .line 373
    .line 374
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    throw p0

    .line 378
    :cond_3
    :try_start_a
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 379
    .line 380
    const-string v0, "cannot encrypt keyset"

    .line 381
    .line 382
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    throw p0
    :try_end_a
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_a .. :try_end_a} :catch_4

    .line 386
    :catch_4
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 387
    .line 388
    const-string v0, "invalid keyset, corrupted key material"

    .line 389
    .line 390
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    throw p0

    .line 394
    :cond_4
    invoke-virtual {v1}, Lj1/a;->p()Lhu/q;

    .line 395
    .line 396
    .line 397
    move-result-object v0

    .line 398
    iget-object p0, p0, Lu/x0;->b:Ljava/lang/Object;

    .line 399
    .line 400
    check-cast p0, Lhu/q;

    .line 401
    .line 402
    iget-object v0, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 403
    .line 404
    check-cast v0, Lqr/y;

    .line 405
    .line 406
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 407
    .line 408
    check-cast p0, Landroid/content/SharedPreferences$Editor;

    .line 409
    .line 410
    const-string v2, "core-google-shortcuts.TINK_KEYSET"

    .line 411
    .line 412
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/a;->c()[B

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    invoke-static {v0}, Lkp/d6;->b([B)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object v0

    .line 420
    invoke-interface {p0, v2, v0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 421
    .line 422
    .line 423
    move-result-object p0

    .line 424
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->commit()Z

    .line 425
    .line 426
    .line 427
    move-result p0

    .line 428
    if-eqz p0, :cond_5

    .line 429
    .line 430
    :goto_3
    return-object v1

    .line 431
    :cond_5
    new-instance p0, Ljava/io/IOException;

    .line 432
    .line 433
    const-string v0, "Failed to write to SharedPreferences"

    .line 434
    .line 435
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 436
    .line 437
    .line 438
    throw p0

    .line 439
    :cond_6
    :try_start_b
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 440
    .line 441
    new-instance v2, Ljava/lang/StringBuilder;

    .line 442
    .line 443
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 444
    .line 445
    .line 446
    const-string v3, "cannot set key as primary because it\'s not enabled: "

    .line 447
    .line 448
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 449
    .line 450
    .line 451
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 452
    .line 453
    .line 454
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    throw p0

    .line 462
    :catchall_0
    move-exception p0

    .line 463
    goto :goto_4

    .line 464
    :cond_7
    add-int/lit8 v3, v3, 0x1

    .line 465
    .line 466
    goto/16 :goto_1

    .line 467
    .line 468
    :cond_8
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 469
    .line 470
    new-instance v2, Ljava/lang/StringBuilder;

    .line 471
    .line 472
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 473
    .line 474
    .line 475
    const-string v3, "key not found: "

    .line 476
    .line 477
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 478
    .line 479
    .line 480
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 481
    .line 482
    .line 483
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 488
    .line 489
    .line 490
    throw p0

    .line 491
    :goto_4
    monitor-exit v1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 492
    throw p0

    .line 493
    :catchall_1
    move-exception p0

    .line 494
    :try_start_c
    monitor-exit v1
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_1

    .line 495
    :try_start_d
    throw p0

    .line 496
    :goto_5
    monitor-exit v1
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_2

    .line 497
    throw p0

    .line 498
    :catchall_2
    move-exception p0

    .line 499
    goto :goto_5

    .line 500
    :cond_9
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 501
    .line 502
    const-string v0, "cannot read or generate keyset"

    .line 503
    .line 504
    invoke-direct {p0, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 505
    .line 506
    .line 507
    throw p0
.end method

.method public m()Lhu/q;
    .locals 6

    .line 1
    new-instance v0, Lj1/a;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lj1/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Lj1/a;->r(Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v2, 0x0

    .line 17
    const-string v3, "cannot use Android Keystore, it\'ll be disabled"

    .line 18
    .line 19
    const-string v4, "e"

    .line 20
    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    :try_start_0
    iget-object v5, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v5, Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {v5}, Lj1/a;->n(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/ProviderException; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception p0

    .line 32
    invoke-static {v4, v3, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 33
    .line 34
    .line 35
    return-object v2

    .line 36
    :cond_0
    :goto_0
    :try_start_1
    iget-object v5, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v5, Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v5}, Lj1/a;->o(Ljava/lang/String;)Lhu/q;

    .line 41
    .line 42
    .line 43
    move-result-object p0
    :try_end_1
    .catch Ljava/security/GeneralSecurityException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/security/ProviderException; {:try_start_1 .. :try_end_1} :catch_1

    .line 44
    return-object p0

    .line 45
    :catch_1
    move-exception v0

    .line 46
    if-nez v1, :cond_1

    .line 47
    .line 48
    invoke-static {v4, v3, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 49
    .line 50
    .line 51
    return-object v2

    .line 52
    :cond_1
    new-instance v1, Ljava/security/KeyStoreException;

    .line 53
    .line 54
    iget-object p0, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p0, Ljava/lang/String;

    .line 57
    .line 58
    const-string v2, "the master key "

    .line 59
    .line 60
    const-string v3, " exists but is unusable"

    .line 61
    .line 62
    invoke-static {v2, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-direct {v1, p0, v0}, Ljava/security/KeyStoreException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 67
    .line 68
    .line 69
    throw v1
.end method

.method public n()V
    .locals 4

    .line 1
    iget-object v0, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lyy0/c2;

    .line 11
    .line 12
    new-instance v1, Lzb/b0;

    .line 13
    .line 14
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    invoke-direct {v1, v2, v3}, Lzb/b0;-><init>(Ljava/util/List;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lr7/a;

    .line 29
    .line 30
    new-instance v1, Lzb/r;

    .line 31
    .line 32
    const/4 v2, 0x2

    .line 33
    invoke-direct {v1, p0, v3, v2}, Lzb/r;-><init>(Lu/x0;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    const/4 p0, 0x3

    .line 37
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    return-void
.end method
