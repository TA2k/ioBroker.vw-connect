.class public final Lml/a;
.super Landroid/graphics/drawable/Drawable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/graphics/drawable/Drawable$Callback;
.implements Landroid/graphics/drawable/Animatable;


# instance fields
.field public final synthetic d:I

.field public final e:I

.field public final f:Z

.field public final g:Ljava/util/ArrayList;

.field public final h:I

.field public final i:I

.field public j:J

.field public k:I

.field public l:I

.field public m:Landroid/graphics/drawable/Drawable;

.field public final n:Landroid/graphics/drawable/Drawable;

.field public final o:Ljava/lang/Enum;


# direct methods
.method public constructor <init>(Landroid/graphics/drawable/Drawable;Lul/f;IZ)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lml/a;->d:I

    .line 1
    invoke-direct {p0}, Landroid/graphics/drawable/Drawable;-><init>()V

    .line 2
    iput-object p2, p0, Lml/a;->o:Ljava/lang/Enum;

    .line 3
    iput p3, p0, Lml/a;->e:I

    .line 4
    iput-boolean p4, p0, Lml/a;->f:Z

    .line 5
    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Lml/a;->g:Ljava/util/ArrayList;

    const/4 p2, 0x0

    if-eqz p1, :cond_0

    .line 6
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    move-result p4

    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p4

    goto :goto_0

    :cond_0
    move-object p4, p2

    :goto_0
    invoke-virtual {p0, p2, p4}, Lml/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;)I

    move-result p4

    iput p4, p0, Lml/a;->h:I

    if-eqz p1, :cond_1

    .line 7
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    move-result p4

    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p4

    goto :goto_1

    :cond_1
    move-object p4, p2

    :goto_1
    invoke-virtual {p0, p2, p4}, Lml/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;)I

    move-result p4

    iput p4, p0, Lml/a;->i:I

    const/16 p4, 0xff

    .line 8
    iput p4, p0, Lml/a;->k:I

    .line 9
    iput-object p2, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    if-eqz p1, :cond_2

    .line 10
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    move-result-object p2

    :cond_2
    iput-object p2, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    if-lez p3, :cond_5

    .line 11
    iget-object p1, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    if-nez p1, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {p1, p0}, Landroid/graphics/drawable/Drawable;->setCallback(Landroid/graphics/drawable/Drawable$Callback;)V

    :goto_2
    if-nez p2, :cond_4

    goto :goto_3

    .line 12
    :cond_4
    invoke-virtual {p2, p0}, Landroid/graphics/drawable/Drawable;->setCallback(Landroid/graphics/drawable/Drawable$Callback;)V

    :goto_3
    return-void

    .line 13
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "durationMillis must be > 0."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Lnm/g;IZ)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lml/a;->d:I

    .line 14
    invoke-direct {p0}, Landroid/graphics/drawable/Drawable;-><init>()V

    .line 15
    iput-object p1, p0, Lml/a;->o:Ljava/lang/Enum;

    .line 16
    iput p2, p0, Lml/a;->e:I

    .line 17
    iput-boolean p3, p0, Lml/a;->f:Z

    .line 18
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lml/a;->g:Ljava/util/ArrayList;

    const/4 p1, 0x0

    .line 19
    invoke-virtual {p0, p1, p1}, Lml/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;)I

    move-result p3

    iput p3, p0, Lml/a;->h:I

    .line 20
    invoke-virtual {p0, p1, p1}, Lml/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;)I

    move-result p3

    iput p3, p0, Lml/a;->i:I

    const/16 p3, 0xff

    .line 21
    iput p3, p0, Lml/a;->k:I

    .line 22
    iput-object p1, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 23
    iput-object p1, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    if-lez p2, :cond_0

    return-void

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "durationMillis must be > 0."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public final a(Ljava/lang/Integer;Ljava/lang/Integer;)I
    .locals 1

    .line 1
    iget p0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, -0x1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eq v0, p0, :cond_5

    .line 15
    .line 16
    :goto_0
    if-nez p2, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-ne v0, p0, :cond_2

    .line 24
    .line 25
    goto :goto_3

    .line 26
    :cond_2
    :goto_1
    if-eqz p1, :cond_3

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    goto :goto_2

    .line 33
    :cond_3
    move p1, p0

    .line 34
    :goto_2
    if-eqz p2, :cond_4

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    :cond_4
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    :cond_5
    :goto_3
    return p0

    .line 45
    :pswitch_0
    const/4 p0, -0x1

    .line 46
    if-nez p1, :cond_6

    .line 47
    .line 48
    goto :goto_4

    .line 49
    :cond_6
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eq v0, p0, :cond_b

    .line 54
    .line 55
    :goto_4
    if-nez p2, :cond_7

    .line 56
    .line 57
    goto :goto_5

    .line 58
    :cond_7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-ne v0, p0, :cond_8

    .line 63
    .line 64
    goto :goto_7

    .line 65
    :cond_8
    :goto_5
    if-eqz p1, :cond_9

    .line 66
    .line 67
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    goto :goto_6

    .line 72
    :cond_9
    move p1, p0

    .line 73
    :goto_6
    if-eqz p2, :cond_a

    .line 74
    .line 75
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    :cond_a
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    :cond_b
    :goto_7
    return p0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b()V
    .locals 4

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    iput v0, p0, Lml/a;->l:I

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 11
    .line 12
    iget-object v0, p0, Lml/a;->g:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const/4 v2, 0x0

    .line 19
    :goto_0
    if-ge v2, v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    check-cast v3, Llq/a;

    .line 26
    .line 27
    iget-object v3, v3, Llq/a;->b:Llq/c;

    .line 28
    .line 29
    iget-object v3, v3, Llq/c;->r:Landroid/content/res/ColorStateList;

    .line 30
    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0, v3}, Lml/a;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    return-void

    .line 40
    :pswitch_0
    const/4 v0, 0x2

    .line 41
    iput v0, p0, Lml/a;->l:I

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    iput-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 45
    .line 46
    iget-object v0, p0, Lml/a;->g:Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    const/4 v2, 0x0

    .line 53
    :goto_1
    if-ge v2, v1, :cond_3

    .line 54
    .line 55
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, Llq/a;

    .line 60
    .line 61
    iget-object v3, v3, Llq/a;->b:Llq/c;

    .line 62
    .line 63
    iget-object v3, v3, Llq/c;->r:Landroid/content/res/ColorStateList;

    .line 64
    .line 65
    if-eqz v3, :cond_2

    .line 66
    .line 67
    invoke-virtual {p0, v3}, Lml/a;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 68
    .line 69
    .line 70
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_3
    return-void

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public c(Landroid/graphics/drawable/Drawable;Landroid/graphics/Rect;)V
    .locals 10

    .line 1
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-lez v0, :cond_1

    .line 10
    .line 11
    if-gtz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p2}, Landroid/graphics/Rect;->width()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    invoke-virtual {p2}, Landroid/graphics/Rect;->height()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    iget-object p0, p0, Lml/a;->o:Ljava/lang/Enum;

    .line 23
    .line 24
    check-cast p0, Lul/f;

    .line 25
    .line 26
    invoke-static {v0, v1, v2, v3, p0}, Llp/pd;->a(IIIILul/f;)D

    .line 27
    .line 28
    .line 29
    move-result-wide v4

    .line 30
    int-to-double v6, v2

    .line 31
    int-to-double v8, v0

    .line 32
    mul-double/2addr v8, v4

    .line 33
    sub-double/2addr v6, v8

    .line 34
    const/4 p0, 0x2

    .line 35
    int-to-double v8, p0

    .line 36
    div-double/2addr v6, v8

    .line 37
    invoke-static {v6, v7}, Lcy0/a;->h(D)I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    int-to-double v2, v3

    .line 42
    int-to-double v0, v1

    .line 43
    mul-double/2addr v4, v0

    .line 44
    sub-double/2addr v2, v4

    .line 45
    div-double/2addr v2, v8

    .line 46
    invoke-static {v2, v3}, Lcy0/a;->h(D)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget v1, p2, Landroid/graphics/Rect;->left:I

    .line 51
    .line 52
    add-int/2addr v1, p0

    .line 53
    iget v2, p2, Landroid/graphics/Rect;->top:I

    .line 54
    .line 55
    add-int/2addr v2, v0

    .line 56
    iget v3, p2, Landroid/graphics/Rect;->right:I

    .line 57
    .line 58
    sub-int/2addr v3, p0

    .line 59
    iget p0, p2, Landroid/graphics/Rect;->bottom:I

    .line 60
    .line 61
    sub-int/2addr p0, v0

    .line 62
    invoke-virtual {p1, v1, v2, v3, p0}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    :goto_0
    invoke-virtual {p1, p2}, Landroid/graphics/drawable/Drawable;->setBounds(Landroid/graphics/Rect;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public d(Landroid/graphics/drawable/Drawable;Landroid/graphics/Rect;)V
    .locals 10

    .line 1
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-lez v0, :cond_1

    .line 10
    .line 11
    if-gtz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {p2}, Landroid/graphics/Rect;->width()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    invoke-virtual {p2}, Landroid/graphics/Rect;->height()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    iget-object p0, p0, Lml/a;->o:Ljava/lang/Enum;

    .line 23
    .line 24
    check-cast p0, Lnm/g;

    .line 25
    .line 26
    invoke-static {v0, v1, v2, v3, p0}, Lno/nordicsemi/android/ble/d;->e(IIIILnm/g;)D

    .line 27
    .line 28
    .line 29
    move-result-wide v4

    .line 30
    int-to-double v6, v2

    .line 31
    int-to-double v8, v0

    .line 32
    mul-double/2addr v8, v4

    .line 33
    sub-double/2addr v6, v8

    .line 34
    const/4 p0, 0x2

    .line 35
    int-to-double v8, p0

    .line 36
    div-double/2addr v6, v8

    .line 37
    invoke-static {v6, v7}, Lcy0/a;->h(D)I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    int-to-double v2, v3

    .line 42
    int-to-double v0, v1

    .line 43
    mul-double/2addr v4, v0

    .line 44
    sub-double/2addr v2, v4

    .line 45
    div-double/2addr v2, v8

    .line 46
    invoke-static {v2, v3}, Lcy0/a;->h(D)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    iget v1, p2, Landroid/graphics/Rect;->left:I

    .line 51
    .line 52
    add-int/2addr v1, p0

    .line 53
    iget v2, p2, Landroid/graphics/Rect;->top:I

    .line 54
    .line 55
    add-int/2addr v2, v0

    .line 56
    iget v3, p2, Landroid/graphics/Rect;->right:I

    .line 57
    .line 58
    sub-int/2addr v3, p0

    .line 59
    iget p0, p2, Landroid/graphics/Rect;->bottom:I

    .line 60
    .line 61
    sub-int/2addr p0, v0

    .line 62
    invoke-virtual {p1, v1, v2, v3, p0}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :cond_1
    :goto_0
    invoke-virtual {p1, p2}, Landroid/graphics/drawable/Drawable;->setBounds(Landroid/graphics/Rect;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public final draw(Landroid/graphics/Canvas;)V
    .locals 11

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lml/a;->l:I

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 11
    .line 12
    if-eqz v0, :cond_7

    .line 13
    .line 14
    iget p0, p0, Lml/a;->k:I

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    :try_start_0
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 27
    .line 28
    .line 29
    goto/16 :goto_3

    .line 30
    .line 31
    :catchall_0
    move-exception v0

    .line 32
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 33
    .line 34
    .line 35
    throw v0

    .line 36
    :cond_0
    const/4 v1, 0x2

    .line 37
    iget-object v2, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 38
    .line 39
    if-ne v0, v1, :cond_1

    .line 40
    .line 41
    if-eqz v2, :cond_7

    .line 42
    .line 43
    iget p0, p0, Lml/a;->k:I

    .line 44
    .line 45
    invoke-virtual {v2, p0}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    :try_start_1
    invoke-virtual {v2, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 56
    .line 57
    .line 58
    goto :goto_3

    .line 59
    :catchall_1
    move-exception v0

    .line 60
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 61
    .line 62
    .line 63
    throw v0

    .line 64
    :cond_1
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 65
    .line 66
    .line 67
    move-result-wide v0

    .line 68
    iget-wide v3, p0, Lml/a;->j:J

    .line 69
    .line 70
    sub-long/2addr v0, v3

    .line 71
    long-to-double v0, v0

    .line 72
    iget v3, p0, Lml/a;->e:I

    .line 73
    .line 74
    int-to-double v3, v3

    .line 75
    div-double v5, v0, v3

    .line 76
    .line 77
    const-wide/16 v7, 0x0

    .line 78
    .line 79
    const-wide/high16 v9, 0x3ff0000000000000L    # 1.0

    .line 80
    .line 81
    invoke-static/range {v5 .. v10}, Lkp/r9;->c(DDD)D

    .line 82
    .line 83
    .line 84
    move-result-wide v0

    .line 85
    iget v3, p0, Lml/a;->k:I

    .line 86
    .line 87
    int-to-double v7, v3

    .line 88
    mul-double/2addr v0, v7

    .line 89
    double-to-int v0, v0

    .line 90
    iget-boolean v1, p0, Lml/a;->f:Z

    .line 91
    .line 92
    if-eqz v1, :cond_2

    .line 93
    .line 94
    sub-int/2addr v3, v0

    .line 95
    :cond_2
    const-wide/high16 v7, 0x3ff0000000000000L    # 1.0

    .line 96
    .line 97
    cmpl-double v1, v5, v7

    .line 98
    .line 99
    if-ltz v1, :cond_3

    .line 100
    .line 101
    const/4 v1, 0x1

    .line 102
    goto :goto_0

    .line 103
    :cond_3
    const/4 v1, 0x0

    .line 104
    :goto_0
    if-nez v1, :cond_4

    .line 105
    .line 106
    iget-object v4, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 107
    .line 108
    if-eqz v4, :cond_4

    .line 109
    .line 110
    invoke-virtual {v4, v3}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    :try_start_2
    invoke-virtual {v4, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 121
    .line 122
    .line 123
    goto :goto_1

    .line 124
    :catchall_2
    move-exception v0

    .line 125
    move-object p0, v0

    .line 126
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :cond_4
    :goto_1
    if-eqz v2, :cond_5

    .line 131
    .line 132
    invoke-virtual {v2, v0}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    :try_start_3
    invoke-virtual {v2, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 143
    .line 144
    .line 145
    goto :goto_2

    .line 146
    :catchall_3
    move-exception v0

    .line 147
    move-object p0, v0

    .line 148
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_5
    :goto_2
    if-eqz v1, :cond_6

    .line 153
    .line 154
    invoke-virtual {p0}, Lml/a;->b()V

    .line 155
    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_6
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 159
    .line 160
    .line 161
    :cond_7
    :goto_3
    return-void

    .line 162
    :pswitch_0
    iget v0, p0, Lml/a;->l:I

    .line 163
    .line 164
    if-nez v0, :cond_8

    .line 165
    .line 166
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 167
    .line 168
    if-eqz v0, :cond_f

    .line 169
    .line 170
    iget p0, p0, Lml/a;->k:I

    .line 171
    .line 172
    invoke-virtual {v0, p0}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 176
    .line 177
    .line 178
    move-result p0

    .line 179
    :try_start_4
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 180
    .line 181
    .line 182
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 183
    .line 184
    .line 185
    goto/16 :goto_7

    .line 186
    .line 187
    :catchall_4
    move-exception v0

    .line 188
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 189
    .line 190
    .line 191
    throw v0

    .line 192
    :cond_8
    const/4 v1, 0x2

    .line 193
    iget-object v2, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 194
    .line 195
    if-ne v0, v1, :cond_9

    .line 196
    .line 197
    if-eqz v2, :cond_f

    .line 198
    .line 199
    iget p0, p0, Lml/a;->k:I

    .line 200
    .line 201
    invoke-virtual {v2, p0}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 205
    .line 206
    .line 207
    move-result p0

    .line 208
    :try_start_5
    invoke-virtual {v2, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 209
    .line 210
    .line 211
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 212
    .line 213
    .line 214
    goto :goto_7

    .line 215
    :catchall_5
    move-exception v0

    .line 216
    invoke-virtual {p1, p0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 217
    .line 218
    .line 219
    throw v0

    .line 220
    :cond_9
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 221
    .line 222
    .line 223
    move-result-wide v0

    .line 224
    iget-wide v3, p0, Lml/a;->j:J

    .line 225
    .line 226
    sub-long/2addr v0, v3

    .line 227
    long-to-double v0, v0

    .line 228
    iget v3, p0, Lml/a;->e:I

    .line 229
    .line 230
    int-to-double v3, v3

    .line 231
    div-double v5, v0, v3

    .line 232
    .line 233
    const-wide/16 v7, 0x0

    .line 234
    .line 235
    const-wide/high16 v9, 0x3ff0000000000000L    # 1.0

    .line 236
    .line 237
    invoke-static/range {v5 .. v10}, Lkp/r9;->c(DDD)D

    .line 238
    .line 239
    .line 240
    move-result-wide v0

    .line 241
    iget v3, p0, Lml/a;->k:I

    .line 242
    .line 243
    int-to-double v7, v3

    .line 244
    mul-double/2addr v0, v7

    .line 245
    double-to-int v0, v0

    .line 246
    iget-boolean v1, p0, Lml/a;->f:Z

    .line 247
    .line 248
    if-eqz v1, :cond_a

    .line 249
    .line 250
    sub-int/2addr v3, v0

    .line 251
    :cond_a
    const-wide/high16 v7, 0x3ff0000000000000L    # 1.0

    .line 252
    .line 253
    cmpl-double v1, v5, v7

    .line 254
    .line 255
    if-ltz v1, :cond_b

    .line 256
    .line 257
    const/4 v1, 0x1

    .line 258
    goto :goto_4

    .line 259
    :cond_b
    const/4 v1, 0x0

    .line 260
    :goto_4
    if-nez v1, :cond_c

    .line 261
    .line 262
    iget-object v4, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 263
    .line 264
    if-eqz v4, :cond_c

    .line 265
    .line 266
    invoke-virtual {v4, v3}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 270
    .line 271
    .line 272
    move-result v3

    .line 273
    :try_start_6
    invoke-virtual {v4, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 274
    .line 275
    .line 276
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 277
    .line 278
    .line 279
    goto :goto_5

    .line 280
    :catchall_6
    move-exception v0

    .line 281
    move-object p0, v0

    .line 282
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 283
    .line 284
    .line 285
    throw p0

    .line 286
    :cond_c
    :goto_5
    if-eqz v2, :cond_d

    .line 287
    .line 288
    invoke-virtual {v2, v0}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 289
    .line 290
    .line 291
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 292
    .line 293
    .line 294
    move-result v3

    .line 295
    :try_start_7
    invoke-virtual {v2, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_7

    .line 296
    .line 297
    .line 298
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 299
    .line 300
    .line 301
    goto :goto_6

    .line 302
    :catchall_7
    move-exception v0

    .line 303
    move-object p0, v0

    .line 304
    invoke-virtual {p1, v3}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 305
    .line 306
    .line 307
    throw p0

    .line 308
    :cond_d
    :goto_6
    if-eqz v1, :cond_e

    .line 309
    .line 310
    invoke-virtual {p0}, Lml/a;->b()V

    .line 311
    .line 312
    .line 313
    goto :goto_7

    .line 314
    :cond_e
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 315
    .line 316
    .line 317
    :cond_f
    :goto_7
    return-void

    .line 318
    nop

    .line 319
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getAlpha()I
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lml/a;->k:I

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p0, Lml/a;->k:I

    .line 10
    .line 11
    return p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getColorFilter()Landroid/graphics/ColorFilter;
    .locals 3

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lml/a;->l:I

    .line 7
    .line 8
    if-eqz v0, :cond_4

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object v2, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    if-eq v0, v1, :cond_1

    .line 14
    .line 15
    const/4 p0, 0x2

    .line 16
    if-eq v0, p0, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    if-eqz v2, :cond_5

    .line 20
    .line 21
    invoke-virtual {v2}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    goto :goto_2

    .line 26
    :cond_1
    if-eqz v2, :cond_3

    .line 27
    .line 28
    invoke-virtual {v2}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    move-object p0, v0

    .line 36
    goto :goto_2

    .line 37
    :cond_3
    :goto_0
    iget-object p0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 38
    .line 39
    if-eqz p0, :cond_5

    .line 40
    .line 41
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    goto :goto_2

    .line 46
    :cond_4
    iget-object p0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 47
    .line 48
    if-eqz p0, :cond_5

    .line 49
    .line 50
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    goto :goto_2

    .line 55
    :cond_5
    :goto_1
    const/4 p0, 0x0

    .line 56
    :goto_2
    return-object p0

    .line 57
    :pswitch_0
    iget v0, p0, Lml/a;->l:I

    .line 58
    .line 59
    if-eqz v0, :cond_a

    .line 60
    .line 61
    const/4 v1, 0x1

    .line 62
    iget-object v2, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 63
    .line 64
    if-eq v0, v1, :cond_7

    .line 65
    .line 66
    const/4 p0, 0x2

    .line 67
    if-eq v0, p0, :cond_6

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_6
    if-eqz v2, :cond_b

    .line 71
    .line 72
    invoke-virtual {v2}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    goto :goto_5

    .line 77
    :cond_7
    if-eqz v2, :cond_9

    .line 78
    .line 79
    invoke-virtual {v2}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-nez v0, :cond_8

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_8
    move-object p0, v0

    .line 87
    goto :goto_5

    .line 88
    :cond_9
    :goto_3
    iget-object p0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 89
    .line 90
    if-eqz p0, :cond_b

    .line 91
    .line 92
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    goto :goto_5

    .line 97
    :cond_a
    iget-object p0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 98
    .line 99
    if-eqz p0, :cond_b

    .line 100
    .line 101
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getColorFilter()Landroid/graphics/ColorFilter;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    goto :goto_5

    .line 106
    :cond_b
    :goto_4
    const/4 p0, 0x0

    .line 107
    :goto_5
    return-object p0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getIntrinsicHeight()I
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lml/a;->i:I

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p0, Lml/a;->i:I

    .line 10
    .line 11
    return p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getIntrinsicWidth()I
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lml/a;->h:I

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p0, Lml/a;->h:I

    .line 10
    .line 11
    return p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final getOpacity()I
    .locals 3

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    iget v1, p0, Lml/a;->l:I

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    if-eqz v0, :cond_4

    .line 13
    .line 14
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v2, 0x2

    .line 20
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 21
    .line 22
    if-ne v1, v2, :cond_1

    .line 23
    .line 24
    if-eqz p0, :cond_4

    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    if-eqz v0, :cond_2

    .line 32
    .line 33
    if-eqz p0, :cond_2

    .line 34
    .line 35
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {v0, p0}, Landroid/graphics/drawable/Drawable;->resolveOpacity(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    goto :goto_0

    .line 48
    :cond_2
    if-eqz v0, :cond_3

    .line 49
    .line 50
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    goto :goto_0

    .line 55
    :cond_3
    if-eqz p0, :cond_4

    .line 56
    .line 57
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    goto :goto_0

    .line 62
    :cond_4
    const/4 p0, -0x2

    .line 63
    :goto_0
    return p0

    .line 64
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 65
    .line 66
    iget v1, p0, Lml/a;->l:I

    .line 67
    .line 68
    if-nez v1, :cond_5

    .line 69
    .line 70
    if-eqz v0, :cond_9

    .line 71
    .line 72
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    goto :goto_1

    .line 77
    :cond_5
    const/4 v2, 0x2

    .line 78
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 79
    .line 80
    if-ne v1, v2, :cond_6

    .line 81
    .line 82
    if-eqz p0, :cond_9

    .line 83
    .line 84
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    goto :goto_1

    .line 89
    :cond_6
    if-eqz v0, :cond_7

    .line 90
    .line 91
    if-eqz p0, :cond_7

    .line 92
    .line 93
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    invoke-static {v0, p0}, Landroid/graphics/drawable/Drawable;->resolveOpacity(II)I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    goto :goto_1

    .line 106
    :cond_7
    if-eqz v0, :cond_8

    .line 107
    .line 108
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    goto :goto_1

    .line 113
    :cond_8
    if-eqz p0, :cond_9

    .line 114
    .line 115
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getOpacity()I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    goto :goto_1

    .line 120
    :cond_9
    const/4 p0, -0x2

    .line 121
    :goto_1
    return p0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invalidateDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    iget p1, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final isRunning()Z
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lml/a;->l:I

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    if-ne p0, v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    return v0

    .line 14
    :pswitch_0
    iget p0, p0, Lml/a;->l:I

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    if-ne p0, v0, :cond_1

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const/4 v0, 0x0

    .line 21
    :goto_1
    return v0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public isStateful()Z
    .locals 2

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v0, v1

    .line 22
    :goto_0
    if-nez v0, :cond_2

    .line 23
    .line 24
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 25
    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move p0, v1

    .line 34
    :goto_1
    if-eqz p0, :cond_3

    .line 35
    .line 36
    :cond_2
    const/4 v1, 0x1

    .line 37
    :cond_3
    return v1

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final onBoundsChange(Landroid/graphics/Rect;)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, v0, p1}, Lml/a;->d(Landroid/graphics/drawable/Drawable;Landroid/graphics/Rect;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, v0, p1}, Lml/a;->d(Landroid/graphics/drawable/Drawable;Landroid/graphics/Rect;)V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {p0, v0, p1}, Lml/a;->c(Landroid/graphics/drawable/Drawable;Landroid/graphics/Rect;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object v0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    if-eqz v0, :cond_3

    .line 31
    .line 32
    invoke-virtual {p0, v0, p1}, Lml/a;->c(Landroid/graphics/drawable/Drawable;Landroid/graphics/Rect;)V

    .line 33
    .line 34
    .line 35
    :cond_3
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onLevelChange(I)Z
    .locals 2

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v0, v1

    .line 17
    :goto_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move p0, v1

    .line 27
    :goto_1
    if-nez v0, :cond_2

    .line 28
    .line 29
    if-eqz p0, :cond_3

    .line 30
    .line 31
    :cond_2
    const/4 v1, 0x1

    .line 32
    :cond_3
    return v1

    .line 33
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    if-eqz v0, :cond_4

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    goto :goto_2

    .line 43
    :cond_4
    move v0, v1

    .line 44
    :goto_2
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 45
    .line 46
    if-eqz p0, :cond_5

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setLevel(I)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    goto :goto_3

    .line 53
    :cond_5
    move p0, v1

    .line 54
    :goto_3
    if-nez v0, :cond_6

    .line 55
    .line 56
    if-eqz p0, :cond_7

    .line 57
    .line 58
    :cond_6
    const/4 v1, 0x1

    .line 59
    :cond_7
    return v1

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onStateChange([I)Z
    .locals 2

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v0, v1

    .line 17
    :goto_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move p0, v1

    .line 27
    :goto_1
    if-nez v0, :cond_2

    .line 28
    .line 29
    if-eqz p0, :cond_3

    .line 30
    .line 31
    :cond_2
    const/4 v1, 0x1

    .line 32
    :cond_3
    return v1

    .line 33
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    if-eqz v0, :cond_4

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    goto :goto_2

    .line 43
    :cond_4
    move v0, v1

    .line 44
    :goto_2
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 45
    .line 46
    if-eqz p0, :cond_5

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    goto :goto_3

    .line 53
    :cond_5
    move p0, v1

    .line 54
    :goto_3
    if-nez v0, :cond_6

    .line 55
    .line 56
    if-eqz p0, :cond_7

    .line 57
    .line 58
    :cond_6
    const/4 v1, 0x1

    .line 59
    :cond_7
    return v1

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final scheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;J)V
    .locals 0

    .line 1
    iget p1, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p2, p3, p4}, Landroid/graphics/drawable/Drawable;->scheduleSelf(Ljava/lang/Runnable;J)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-virtual {p0, p2, p3, p4}, Landroid/graphics/drawable/Drawable;->scheduleSelf(Ljava/lang/Runnable;J)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final setAlpha(I)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    if-ltz p1, :cond_0

    .line 7
    .line 8
    const/16 v0, 0x100

    .line 9
    .line 10
    if-ge p1, v0, :cond_0

    .line 11
    .line 12
    iput p1, p0, Lml/a;->k:I

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    const-string p0, "Invalid alpha: "

    .line 16
    .line 17
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p1

    .line 31
    :pswitch_0
    if-ltz p1, :cond_1

    .line 32
    .line 33
    const/16 v0, 0x100

    .line 34
    .line 35
    if-ge p1, v0, :cond_1

    .line 36
    .line 37
    iput p1, p0, Lml/a;->k:I

    .line 38
    .line 39
    return-void

    .line 40
    :cond_1
    const-string p0, "Invalid alpha: "

    .line 41
    .line 42
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p1

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final setColorFilter(Landroid/graphics/ColorFilter;)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 22
    .line 23
    if-nez v0, :cond_2

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_2
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 30
    .line 31
    if-nez p0, :cond_3

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_3
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 35
    .line 36
    .line 37
    :goto_1
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final setTint(I)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTint(I)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTint(I)V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTint(I)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTint(I)V

    .line 33
    .line 34
    .line 35
    :cond_3
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final setTintBlendMode(Landroid/graphics/BlendMode;)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintBlendMode(Landroid/graphics/BlendMode;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTintBlendMode(Landroid/graphics/BlendMode;)V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintBlendMode(Landroid/graphics/BlendMode;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTintBlendMode(Landroid/graphics/BlendMode;)V

    .line 33
    .line 34
    .line 35
    :cond_3
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final setTintList(Landroid/content/res/ColorStateList;)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 33
    .line 34
    .line 35
    :cond_3
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final setTintMode(Landroid/graphics/PorterDuff$Mode;)V
    .locals 1

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintMode(Landroid/graphics/PorterDuff$Mode;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTintMode(Landroid/graphics/PorterDuff$Mode;)V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void

    .line 21
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setTintMode(Landroid/graphics/PorterDuff$Mode;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object p0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->setTintMode(Landroid/graphics/PorterDuff$Mode;)V

    .line 33
    .line 34
    .line 35
    :cond_3
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final start()V
    .locals 4

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    check-cast v0, Landroid/graphics/drawable/Animatable;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object v0, v2

    .line 17
    :goto_0
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-interface {v0}, Landroid/graphics/drawable/Animatable;->start()V

    .line 20
    .line 21
    .line 22
    :cond_1
    iget-object v0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 23
    .line 24
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 25
    .line 26
    if-eqz v1, :cond_2

    .line 27
    .line 28
    move-object v2, v0

    .line 29
    check-cast v2, Landroid/graphics/drawable/Animatable;

    .line 30
    .line 31
    :cond_2
    if-eqz v2, :cond_3

    .line 32
    .line 33
    invoke-interface {v2}, Landroid/graphics/drawable/Animatable;->start()V

    .line 34
    .line 35
    .line 36
    :cond_3
    iget v0, p0, Lml/a;->l:I

    .line 37
    .line 38
    if-eqz v0, :cond_4

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_4
    const/4 v0, 0x1

    .line 42
    iput v0, p0, Lml/a;->l:I

    .line 43
    .line 44
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 45
    .line 46
    .line 47
    move-result-wide v0

    .line 48
    iput-wide v0, p0, Lml/a;->j:J

    .line 49
    .line 50
    iget-object v0, p0, Lml/a;->g:Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    const/4 v2, 0x0

    .line 57
    :goto_1
    if-ge v2, v1, :cond_5

    .line 58
    .line 59
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    check-cast v3, Llq/a;

    .line 64
    .line 65
    invoke-virtual {v3, p0}, Llq/a;->a(Landroid/graphics/drawable/Drawable;)V

    .line 66
    .line 67
    .line 68
    add-int/lit8 v2, v2, 0x1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_5
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 72
    .line 73
    .line 74
    :goto_2
    return-void

    .line 75
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 76
    .line 77
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 78
    .line 79
    const/4 v2, 0x0

    .line 80
    if-eqz v1, :cond_6

    .line 81
    .line 82
    check-cast v0, Landroid/graphics/drawable/Animatable;

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_6
    move-object v0, v2

    .line 86
    :goto_3
    if-eqz v0, :cond_7

    .line 87
    .line 88
    invoke-interface {v0}, Landroid/graphics/drawable/Animatable;->start()V

    .line 89
    .line 90
    .line 91
    :cond_7
    iget-object v0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 92
    .line 93
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 94
    .line 95
    if-eqz v1, :cond_8

    .line 96
    .line 97
    move-object v2, v0

    .line 98
    check-cast v2, Landroid/graphics/drawable/Animatable;

    .line 99
    .line 100
    :cond_8
    if-eqz v2, :cond_9

    .line 101
    .line 102
    invoke-interface {v2}, Landroid/graphics/drawable/Animatable;->start()V

    .line 103
    .line 104
    .line 105
    :cond_9
    iget v0, p0, Lml/a;->l:I

    .line 106
    .line 107
    if-eqz v0, :cond_a

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_a
    const/4 v0, 0x1

    .line 111
    iput v0, p0, Lml/a;->l:I

    .line 112
    .line 113
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 114
    .line 115
    .line 116
    move-result-wide v0

    .line 117
    iput-wide v0, p0, Lml/a;->j:J

    .line 118
    .line 119
    iget-object v0, p0, Lml/a;->g:Ljava/util/ArrayList;

    .line 120
    .line 121
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    const/4 v2, 0x0

    .line 126
    :goto_4
    if-ge v2, v1, :cond_b

    .line 127
    .line 128
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    check-cast v3, Llq/a;

    .line 133
    .line 134
    invoke-virtual {v3, p0}, Llq/a;->a(Landroid/graphics/drawable/Drawable;)V

    .line 135
    .line 136
    .line 137
    add-int/lit8 v2, v2, 0x1

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :cond_b
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 141
    .line 142
    .line 143
    :goto_5
    return-void

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final stop()V
    .locals 3

    .line 1
    iget v0, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    check-cast v0, Landroid/graphics/drawable/Animatable;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object v0, v2

    .line 17
    :goto_0
    if-eqz v0, :cond_1

    .line 18
    .line 19
    invoke-interface {v0}, Landroid/graphics/drawable/Animatable;->stop()V

    .line 20
    .line 21
    .line 22
    :cond_1
    iget-object v0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 23
    .line 24
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 25
    .line 26
    if-eqz v1, :cond_2

    .line 27
    .line 28
    move-object v2, v0

    .line 29
    check-cast v2, Landroid/graphics/drawable/Animatable;

    .line 30
    .line 31
    :cond_2
    if-eqz v2, :cond_3

    .line 32
    .line 33
    invoke-interface {v2}, Landroid/graphics/drawable/Animatable;->stop()V

    .line 34
    .line 35
    .line 36
    :cond_3
    iget v0, p0, Lml/a;->l:I

    .line 37
    .line 38
    const/4 v1, 0x2

    .line 39
    if-eq v0, v1, :cond_4

    .line 40
    .line 41
    invoke-virtual {p0}, Lml/a;->b()V

    .line 42
    .line 43
    .line 44
    :cond_4
    return-void

    .line 45
    :pswitch_0
    iget-object v0, p0, Lml/a;->m:Landroid/graphics/drawable/Drawable;

    .line 46
    .line 47
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    if-eqz v1, :cond_5

    .line 51
    .line 52
    check-cast v0, Landroid/graphics/drawable/Animatable;

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_5
    move-object v0, v2

    .line 56
    :goto_1
    if-eqz v0, :cond_6

    .line 57
    .line 58
    invoke-interface {v0}, Landroid/graphics/drawable/Animatable;->stop()V

    .line 59
    .line 60
    .line 61
    :cond_6
    iget-object v0, p0, Lml/a;->n:Landroid/graphics/drawable/Drawable;

    .line 62
    .line 63
    instance-of v1, v0, Landroid/graphics/drawable/Animatable;

    .line 64
    .line 65
    if-eqz v1, :cond_7

    .line 66
    .line 67
    move-object v2, v0

    .line 68
    check-cast v2, Landroid/graphics/drawable/Animatable;

    .line 69
    .line 70
    :cond_7
    if-eqz v2, :cond_8

    .line 71
    .line 72
    invoke-interface {v2}, Landroid/graphics/drawable/Animatable;->stop()V

    .line 73
    .line 74
    .line 75
    :cond_8
    iget v0, p0, Lml/a;->l:I

    .line 76
    .line 77
    const/4 v1, 0x2

    .line 78
    if-eq v0, v1, :cond_9

    .line 79
    .line 80
    invoke-virtual {p0}, Lml/a;->b()V

    .line 81
    .line 82
    .line 83
    :cond_9
    return-void

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final unscheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget p1, p0, Lml/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p2}, Landroid/graphics/drawable/Drawable;->unscheduleSelf(Ljava/lang/Runnable;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-virtual {p0, p2}, Landroid/graphics/drawable/Drawable;->unscheduleSelf(Ljava/lang/Runnable;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
