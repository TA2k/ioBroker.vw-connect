.class public final Lz9/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lio/o;


# direct methods
.method public constructor <init>(Landroid/os/Bundle;)V
    .locals 2

    const-string v0, "state"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    const-class v0, Lz9/l;

    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 19
    new-instance v0, Lio/o;

    const-string v1, "state"

    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 21
    const-string v1, "nav-entry-state:id"

    invoke-static {v1, p1}, Lkp/t;->g(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/String;

    move-result-object v1

    iput-object v1, v0, Lio/o;->e:Ljava/lang/Object;

    .line 22
    const-string v1, "nav-entry-state:destination-id"

    invoke-static {v1, p1}, Lkp/t;->c(Ljava/lang/String;Landroid/os/Bundle;)I

    move-result v1

    iput v1, v0, Lio/o;->d:I

    .line 23
    const-string v1, "nav-entry-state:args"

    invoke-static {v1, p1}, Lkp/t;->e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    move-result-object v1

    iput-object v1, v0, Lio/o;->f:Ljava/lang/Object;

    .line 24
    const-string v1, "nav-entry-state:saved-state"

    invoke-static {v1, p1}, Lkp/t;->e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    move-result-object p1

    iput-object p1, v0, Lio/o;->g:Ljava/lang/Object;

    .line 25
    iput-object v0, p0, Lz9/l;->a:Lio/o;

    return-void
.end method

.method public constructor <init>(Lz9/k;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lio/o;

    .line 3
    iget-object v1, p1, Lz9/k;->e:Lz9/u;

    .line 4
    iget-object v1, v1, Lz9/u;->e:Lca/j;

    .line 5
    iget v1, v1, Lca/j;->a:I

    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    iget-object v2, p1, Lz9/k;->i:Ljava/lang/String;

    .line 8
    iput-object v2, v0, Lio/o;->e:Ljava/lang/Object;

    .line 9
    iput v1, v0, Lio/o;->d:I

    .line 10
    iget-object p1, p1, Lz9/k;->k:Lca/c;

    invoke-virtual {p1}, Lca/c;->a()Landroid/os/Bundle;

    move-result-object v1

    .line 11
    iput-object v1, v0, Lio/o;->f:Ljava/lang/Object;

    const/4 v1, 0x0

    .line 12
    new-array v2, v1, [Llx0/l;

    .line 13
    invoke-static {v2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Llx0/l;

    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    move-result-object v1

    .line 14
    iput-object v1, v0, Lio/o;->g:Ljava/lang/Object;

    .line 15
    iget-object p1, p1, Lca/c;->h:Lra/e;

    invoke-virtual {p1, v1}, Lra/e;->c(Landroid/os/Bundle;)V

    .line 16
    iput-object v0, p0, Lz9/l;->a:Lio/o;

    return-void
.end method
