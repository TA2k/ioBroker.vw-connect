.class public final Liq/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/animation/ValueAnimator$AnimatorUpdateListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Liq/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Liq/b;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onAnimationUpdate(Landroid/animation/ValueAnimator;)V
    .locals 2

    .line 1
    iget v0, p0, Liq/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Liq/b;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/textfield/TextInputLayout;

    .line 9
    .line 10
    iget-object p0, p0, Lcom/google/android/material/textfield/TextInputLayout;->I1:Lrq/b;

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/animation/ValueAnimator;->getAnimatedValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Ljava/lang/Float;

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    invoke-virtual {p0, p1}, Lrq/b;->m(F)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_0
    invoke-virtual {p1}, Landroid/animation/ValueAnimator;->getAnimatedValue()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Ljava/lang/Float;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    const/high16 v0, 0x437f0000    # 255.0f

    .line 37
    .line 38
    mul-float/2addr p1, v0

    .line 39
    float-to-int p1, p1

    .line 40
    iget-object p0, p0, Liq/b;->b:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lka/k;

    .line 43
    .line 44
    iget-object v0, p0, Lka/k;->c:Landroid/graphics/drawable/StateListDrawable;

    .line 45
    .line 46
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Lka/k;->d:Landroid/graphics/drawable/Drawable;

    .line 50
    .line 51
    invoke-virtual {v0, p1}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lka/k;->s:Landroidx/recyclerview/widget/RecyclerView;

    .line 55
    .line 56
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :pswitch_1
    invoke-virtual {p1}, Landroid/animation/ValueAnimator;->getAnimatedValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    check-cast p1, Ljava/lang/Float;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iget-object p0, p0, Liq/b;->b:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 73
    .line 74
    iget-object p0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->i:Lwq/i;

    .line 75
    .line 76
    if-eqz p0, :cond_0

    .line 77
    .line 78
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 79
    .line 80
    iget v1, v0, Lwq/g;->j:F

    .line 81
    .line 82
    cmpl-float v1, v1, p1

    .line 83
    .line 84
    if-eqz v1, :cond_0

    .line 85
    .line 86
    iput p1, v0, Lwq/g;->j:F

    .line 87
    .line 88
    const/4 p1, 0x1

    .line 89
    iput-boolean p1, p0, Lwq/i;->i:Z

    .line 90
    .line 91
    iput-boolean p1, p0, Lwq/i;->j:Z

    .line 92
    .line 93
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 94
    .line 95
    .line 96
    :cond_0
    return-void

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
