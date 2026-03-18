.class public final Landroidx/core/app/g;
.super Landroid/os/AsyncTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Landroidx/core/app/o;


# direct methods
.method public constructor <init>(Landroidx/core/app/o;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/core/app/g;->a:Landroidx/core/app/o;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/os/AsyncTask;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final doInBackground([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, [Ljava/lang/Void;

    .line 2
    .line 3
    :goto_0
    iget-object p1, p0, Landroidx/core/app/g;->a:Landroidx/core/app/o;

    .line 4
    .line 5
    invoke-virtual {p1}, Landroidx/core/app/o;->dequeueWork()Landroidx/core/app/j;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-interface {v0}, Landroidx/core/app/j;->getIntent()Landroid/content/Intent;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p1, v1}, Landroidx/core/app/o;->onHandleWork(Landroid/content/Intent;)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v0}, Landroidx/core/app/j;->a()V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return-object p0
.end method

.method public final onCancelled(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/core/app/g;->a:Landroidx/core/app/o;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/core/app/o;->processorFinished()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final onPostExecute(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Void;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/core/app/g;->a:Landroidx/core/app/o;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/core/app/o;->processorFinished()V

    .line 6
    .line 7
    .line 8
    return-void
.end method
