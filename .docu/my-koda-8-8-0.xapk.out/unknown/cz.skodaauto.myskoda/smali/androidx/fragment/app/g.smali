.class public final Landroidx/fragment/app/g;
.super Landroid/animation/AnimatorListenerAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Landroid/view/ViewGroup;

.field public final synthetic b:Landroid/view/View;

.field public final synthetic c:Z

.field public final synthetic d:Landroidx/fragment/app/g2;

.field public final synthetic e:Landroidx/fragment/app/h;


# direct methods
.method public constructor <init>(Landroid/view/ViewGroup;Landroid/view/View;ZLandroidx/fragment/app/g2;Landroidx/fragment/app/h;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/fragment/app/g;->a:Landroid/view/ViewGroup;

    .line 2
    .line 3
    iput-object p2, p0, Landroidx/fragment/app/g;->b:Landroid/view/View;

    .line 4
    .line 5
    iput-boolean p3, p0, Landroidx/fragment/app/g;->c:Z

    .line 6
    .line 7
    iput-object p4, p0, Landroidx/fragment/app/g;->d:Landroidx/fragment/app/g2;

    .line 8
    .line 9
    iput-object p5, p0, Landroidx/fragment/app/g;->e:Landroidx/fragment/app/h;

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
    .locals 4

    .line 1
    const-string v0, "anim"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Landroidx/fragment/app/g;->a:Landroid/view/ViewGroup;

    .line 7
    .line 8
    iget-object v0, p0, Landroidx/fragment/app/g;->b:Landroid/view/View;

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->endViewTransition(Landroid/view/View;)V

    .line 11
    .line 12
    .line 13
    iget-boolean v1, p0, Landroidx/fragment/app/g;->c:Z

    .line 14
    .line 15
    iget-object v2, p0, Landroidx/fragment/app/g;->d:Landroidx/fragment/app/g2;

    .line 16
    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget v1, v2, Landroidx/fragment/app/g2;->a:I

    .line 20
    .line 21
    const/4 v3, 0x3

    .line 22
    if-ne v1, v3, :cond_1

    .line 23
    .line 24
    :cond_0
    iget v1, v2, Landroidx/fragment/app/g2;->a:I

    .line 25
    .line 26
    const-string v3, "viewToAnimate"

    .line 27
    .line 28
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1, v0, p1}, La7/g0;->a(ILandroid/view/View;Landroid/view/ViewGroup;)V

    .line 32
    .line 33
    .line 34
    :cond_1
    iget-object p0, p0, Landroidx/fragment/app/g;->e:Landroidx/fragment/app/h;

    .line 35
    .line 36
    iget-object p1, p0, Landroidx/fragment/app/h;->c:Landroidx/fragment/app/f;

    .line 37
    .line 38
    iget-object p1, p1, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 39
    .line 40
    invoke-virtual {p1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x2

    .line 44
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_2

    .line 49
    .line 50
    new-instance p0, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string p1, "Animator from operation "

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string p1, " has ended."

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string p1, "FragmentManager"

    .line 70
    .line 71
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    :cond_2
    return-void
.end method
