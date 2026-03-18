.class public final Lbb/p;
.super Landroid/animation/AnimatorListenerAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILandroid/view/View;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lbb/p;->a:I

    iput-object p3, p0, Lbb/p;->b:Ljava/lang/Object;

    iput-object p2, p0, Lbb/p;->c:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method

.method public constructor <init>(Lbb/x;Landroidx/collection/f;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lbb/p;->a:I

    .line 2
    iput-object p1, p0, Lbb/p;->c:Ljava/lang/Object;

    iput-object p2, p0, Lbb/p;->b:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationCancel(Landroid/animation/Animator;)V
    .locals 1

    .line 1
    iget v0, p0, Lbb/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationCancel(Landroid/animation/Animator;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object p0, p0, Lbb/p;->b:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ld6/x0;

    .line 13
    .line 14
    invoke-interface {p0}, Ld6/x0;->a()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final onAnimationEnd(Landroid/animation/Animator;)V
    .locals 2

    .line 1
    iget v0, p0, Lbb/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lbb/p;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Ld6/f1;

    .line 9
    .line 10
    const/high16 v0, 0x3f800000    # 1.0f

    .line 11
    .line 12
    iget-object v1, p1, Ld6/f1;->a:Ld6/e1;

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Ld6/e1;->e(F)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lbb/p;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Landroid/view/View;

    .line 20
    .line 21
    invoke-static {p0, p1}, Ld6/b1;->f(Landroid/view/View;Ld6/f1;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_0
    iget-object p0, p0, Lbb/p;->b:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Ld6/x0;

    .line 28
    .line 29
    invoke-interface {p0}, Ld6/x0;->c()V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_1
    iget-object v0, p0, Lbb/p;->b:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Landroidx/collection/f;

    .line 36
    .line 37
    invoke-virtual {v0, p1}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lbb/p;->c:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lbb/x;

    .line 43
    .line 44
    iget-object p0, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public onAnimationStart(Landroid/animation/Animator;)V
    .locals 1

    .line 1
    iget v0, p0, Lbb/p;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationStart(Landroid/animation/Animator;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    iget-object p0, p0, Lbb/p;->b:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ld6/x0;

    .line 13
    .line 14
    invoke-interface {p0}, Ld6/x0;->b()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_1
    iget-object p0, p0, Lbb/p;->c:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lbb/x;

    .line 21
    .line 22
    iget-object p0, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
