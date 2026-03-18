.class public final Lka/e;
.super Landroid/animation/AnimatorListenerAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lka/f;

.field public final synthetic c:Landroid/view/ViewPropertyAnimator;

.field public final synthetic d:Landroid/view/View;

.field public final synthetic e:Lka/h;


# direct methods
.method public synthetic constructor <init>(Lka/h;Lka/f;Landroid/view/ViewPropertyAnimator;Landroid/view/View;I)V
    .locals 0

    .line 1
    iput p5, p0, Lka/e;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lka/e;->e:Lka/h;

    .line 4
    .line 5
    iput-object p2, p0, Lka/e;->b:Lka/f;

    .line 6
    .line 7
    iput-object p3, p0, Lka/e;->c:Landroid/view/ViewPropertyAnimator;

    .line 8
    .line 9
    iput-object p4, p0, Lka/e;->d:Landroid/view/View;

    .line 10
    .line 11
    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    .line 1
    iget p1, p0, Lka/e;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lka/e;->c:Landroid/view/ViewPropertyAnimator;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-virtual {p1, v0}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 10
    .line 11
    .line 12
    const/high16 p1, 0x3f800000    # 1.0f

    .line 13
    .line 14
    iget-object v0, p0, Lka/e;->d:Landroid/view/View;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Landroid/view/View;->setAlpha(F)V

    .line 17
    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    invoke-virtual {v0, p1}, Landroid/view/View;->setTranslationX(F)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, p1}, Landroid/view/View;->setTranslationY(F)V

    .line 24
    .line 25
    .line 26
    iget-object p1, p0, Lka/e;->b:Lka/f;

    .line 27
    .line 28
    iget-object v0, p1, Lka/f;->b:Lka/v0;

    .line 29
    .line 30
    iget-object p0, p0, Lka/e;->e:Lka/h;

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lka/c0;->c(Lka/v0;)V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Lka/h;->r:Ljava/util/ArrayList;

    .line 36
    .line 37
    iget-object p1, p1, Lka/f;->b:Lka/v0;

    .line 38
    .line 39
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0}, Lka/h;->i()V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :pswitch_0
    iget-object p1, p0, Lka/e;->c:Landroid/view/ViewPropertyAnimator;

    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    invoke-virtual {p1, v0}, Landroid/view/ViewPropertyAnimator;->setListener(Landroid/animation/Animator$AnimatorListener;)Landroid/view/ViewPropertyAnimator;

    .line 50
    .line 51
    .line 52
    const/high16 p1, 0x3f800000    # 1.0f

    .line 53
    .line 54
    iget-object v0, p0, Lka/e;->d:Landroid/view/View;

    .line 55
    .line 56
    invoke-virtual {v0, p1}, Landroid/view/View;->setAlpha(F)V

    .line 57
    .line 58
    .line 59
    const/4 p1, 0x0

    .line 60
    invoke-virtual {v0, p1}, Landroid/view/View;->setTranslationX(F)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, p1}, Landroid/view/View;->setTranslationY(F)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lka/e;->b:Lka/f;

    .line 67
    .line 68
    iget-object v0, p1, Lka/f;->a:Lka/v0;

    .line 69
    .line 70
    iget-object p0, p0, Lka/e;->e:Lka/h;

    .line 71
    .line 72
    invoke-virtual {p0, v0}, Lka/c0;->c(Lka/v0;)V

    .line 73
    .line 74
    .line 75
    iget-object v0, p0, Lka/h;->r:Ljava/util/ArrayList;

    .line 76
    .line 77
    iget-object p1, p1, Lka/f;->a:Lka/v0;

    .line 78
    .line 79
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lka/h;->i()V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onAnimationStart(Landroid/animation/Animator;)V
    .locals 0

    .line 1
    iget p1, p0, Lka/e;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lka/e;->b:Lka/f;

    .line 7
    .line 8
    iget-object p1, p1, Lka/f;->b:Lka/v0;

    .line 9
    .line 10
    iget-object p0, p0, Lka/e;->e:Lka/h;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object p1, p0, Lka/e;->b:Lka/f;

    .line 17
    .line 18
    iget-object p1, p1, Lka/f;->a:Lka/v0;

    .line 19
    .line 20
    iget-object p0, p0, Lka/e;->e:Lka/h;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
