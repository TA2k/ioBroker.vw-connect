.class public final Lw3/s2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/w;
.implements Landroidx/lifecycle/v;


# instance fields
.field public final d:Lw3/t;

.field public final e:Ll2/a0;

.field public f:Z

.field public g:Landroidx/lifecycle/r;

.field public h:Lay0/n;


# direct methods
.method public constructor <init>(Lw3/t;Ll2/a0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/s2;->d:Lw3/t;

    .line 5
    .line 6
    iput-object p2, p0, Lw3/s2;->e:Ll2/a0;

    .line 7
    .line 8
    sget-object p1, Lw3/f1;->a:Lt2/b;

    .line 9
    .line 10
    iput-object p1, p0, Lw3/s2;->h:Lay0/n;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lay0/n;)V
    .locals 2

    .line 1
    new-instance v0, Lb1/e;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1, p0, p1}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lw3/s2;->d:Lw3/t;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lw3/t;->setOnViewTreeOwnersAvailable(Lay0/k;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final dispose()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lw3/s2;->f:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lw3/s2;->f:Z

    .line 7
    .line 8
    iget-object v0, p0, Lw3/s2;->d:Lw3/t;

    .line 9
    .line 10
    invoke-virtual {v0}, Lw3/t;->getView()Landroid/view/View;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const v1, 0x7f0a0313

    .line 15
    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {v0, v1, v2}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lw3/s2;->g:Landroidx/lifecycle/r;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    iget-object p0, p0, Lw3/s2;->e:Ll2/a0;

    .line 29
    .line 30
    invoke-virtual {p0}, Ll2/a0;->dispose()V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 0

    .line 1
    sget-object p1, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 2
    .line 3
    if-ne p2, p1, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lw3/s2;->dispose()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    sget-object p1, Landroidx/lifecycle/p;->ON_CREATE:Landroidx/lifecycle/p;

    .line 10
    .line 11
    if-ne p2, p1, :cond_1

    .line 12
    .line 13
    iget-boolean p1, p0, Lw3/s2;->f:Z

    .line 14
    .line 15
    if-nez p1, :cond_1

    .line 16
    .line 17
    iget-object p1, p0, Lw3/s2;->h:Lay0/n;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lw3/s2;->a(Lay0/n;)V

    .line 20
    .line 21
    .line 22
    :cond_1
    return-void
.end method
