.class public final Landroidx/lifecycle/l0$a;
.super Landroidx/lifecycle/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/lifecycle/l0;->onActivityPreCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Landroidx/lifecycle/m0;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/m0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/lifecycle/l0$a;->this$0:Landroidx/lifecycle/m0;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onActivityPostResumed(Landroid/app/Activity;)V
    .locals 1

    .line 1
    const-string v0, "activity"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/lifecycle/l0$a;->this$0:Landroidx/lifecycle/m0;

    .line 7
    .line 8
    iget p1, p0, Landroidx/lifecycle/m0;->e:I

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    add-int/2addr p1, v0

    .line 12
    iput p1, p0, Landroidx/lifecycle/m0;->e:I

    .line 13
    .line 14
    if-ne p1, v0, :cond_1

    .line 15
    .line 16
    iget-boolean p1, p0, Landroidx/lifecycle/m0;->f:Z

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    iget-object p1, p0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 21
    .line 22
    sget-object v0, Landroidx/lifecycle/p;->ON_RESUME:Landroidx/lifecycle/p;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 25
    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    iput-boolean p1, p0, Landroidx/lifecycle/m0;->f:Z

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object p1, p0, Landroidx/lifecycle/m0;->h:Landroid/os/Handler;

    .line 32
    .line 33
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Landroidx/lifecycle/m0;->j:La0/d;

    .line 37
    .line 38
    invoke-virtual {p1, p0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    :goto_0
    return-void
.end method

.method public onActivityPostStarted(Landroid/app/Activity;)V
    .locals 1

    .line 1
    const-string v0, "activity"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/lifecycle/l0$a;->this$0:Landroidx/lifecycle/m0;

    .line 7
    .line 8
    iget p1, p0, Landroidx/lifecycle/m0;->d:I

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    add-int/2addr p1, v0

    .line 12
    iput p1, p0, Landroidx/lifecycle/m0;->d:I

    .line 13
    .line 14
    if-ne p1, v0, :cond_0

    .line 15
    .line 16
    iget-boolean p1, p0, Landroidx/lifecycle/m0;->g:Z

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    iget-object p1, p0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 21
    .line 22
    sget-object v0, Landroidx/lifecycle/p;->ON_START:Landroidx/lifecycle/p;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 25
    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    iput-boolean p1, p0, Landroidx/lifecycle/m0;->g:Z

    .line 29
    .line 30
    :cond_0
    return-void
.end method
