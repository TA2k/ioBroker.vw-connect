.class public final Laa/a;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public e:La0/j;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/s0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "SaveableStateHolder_BackStackEntryKey"

    .line 5
    .line 6
    invoke-virtual {p1, v0}, Landroidx/lifecycle/s0;->a(Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Ljava/lang/String;

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {p1, v1, v0}, Landroidx/lifecycle/s0;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    iput-object v1, p0, Laa/a;->d:Ljava/lang/String;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final onCleared()V
    .locals 4

    .line 1
    invoke-super {p0}, Landroidx/lifecycle/b1;->onCleared()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Laa/a;->e:La0/j;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const-string v2, "saveableStateHolderRef"

    .line 8
    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    iget-object v0, v0, La0/j;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/ref/WeakReference;

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lu2/c;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    iget-object v3, p0, Laa/a;->d:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {v0, v3}, Lu2/c;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    iget-object p0, p0, Laa/a;->e:La0/j;

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Ljava/lang/ref/WeakReference;

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->clear()V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_1
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v1

    .line 44
    :cond_2
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v1
.end method
