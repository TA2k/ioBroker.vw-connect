.class public final Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;
.super Ljava/util/ArrayList;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<E:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/util/ArrayList<",
        "TE;>;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u001e\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u0000*\u0004\u0008\u0000\u0010\u00012\u0008\u0012\u0004\u0012\u00028\u00000\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00028\u0000H\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0017\u0010\t\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00028\u0000H\u0016\u00a2\u0006\u0004\u0008\t\u0010\u0008J\u000f\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u0004J\u001d\u0010\u000e\u001a\u00020\u00062\u000c\u0010\r\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u000cH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u001d\u0010\u0010\u001a\u00020\u00062\u000c\u0010\r\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u000cH\u0016\u00a2\u0006\u0004\u0008\u0010\u0010\u000fJ\u001f\u0010\u0013\u001a\u00020\u00062\u000e\u0010\u0012\u001a\n\u0012\u0006\u0008\u0000\u0012\u00028\u00000\u0011H\u0017\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J\u001f\u0010\u0018\u001a\u00020\n2\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0017\u001a\u00020\u0015H\u0014\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J \u0010\u001b\u001a\u00028\u00002\u0006\u0010\u001a\u001a\u00020\u00152\u0006\u0010\u0005\u001a\u00028\u0000H\u0096\u0002\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR$\u0010\u001e\u001a\u0004\u0018\u00010\u001d8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u001e\u0010\u001f\u001a\u0004\u0008 \u0010!\"\u0004\u0008\"\u0010#\u00a8\u0006$"
    }
    d2 = {
        "Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;",
        "E",
        "Ljava/util/ArrayList;",
        "<init>",
        "()V",
        "element",
        "",
        "add",
        "(Ljava/lang/Object;)Z",
        "remove",
        "Llx0/b0;",
        "clear",
        "",
        "elements",
        "addAll",
        "(Ljava/util/Collection;)Z",
        "removeAll",
        "Ljava/util/function/Predicate;",
        "filter",
        "removeIf",
        "(Ljava/util/function/Predicate;)Z",
        "",
        "fromIndex",
        "toIndex",
        "removeRange",
        "(II)V",
        "index",
        "set",
        "(ILjava/lang/Object;)Ljava/lang/Object;",
        "Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;",
        "notifier",
        "Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;",
        "getNotifier",
        "()Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;",
        "setNotifier",
        "(Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;)V",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public add(Ljava/lang/Object;)Z
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TE;)Z"
        }
    .end annotation

    .line 1
    invoke-super {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return p1
.end method

.method public addAll(Ljava/util/Collection;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "+TE;>;)Z"
        }
    .end annotation

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return p1
.end method

.method public clear()V
    .locals 0

    .line 1
    invoke-super {p0}, Ljava/util/ArrayList;->clear()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final getNotifier()Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge getSize()I
    .locals 0

    .line 1
    invoke-super {p0}, Ljava/util/ArrayList;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final bridge remove(I)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)TE;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->removeAt(I)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public remove(Ljava/lang/Object;)Z
    .locals 0

    .line 2
    invoke-super {p0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    move-result p1

    .line 3
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    if-eqz p0, :cond_0

    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    :cond_0
    return p1
.end method

.method public removeAll(Ljava/util/Collection;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "+",
            "Ljava/lang/Object;",
            ">;)Z"
        }
    .end annotation

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/ArrayList;->removeAll(Ljava/util/Collection;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return p1
.end method

.method public bridge removeAt(I)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public removeIf(Ljava/util/function/Predicate;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "-TE;>;)Z"
        }
    .end annotation

    .line 1
    const-string v0, "filter"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/util/ArrayList;->removeIf(Ljava/util/function/Predicate;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 11
    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return p1
.end method

.method public removeRange(II)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Ljava/util/ArrayList;->removeRange(II)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(ITE;)TE;"
        }
    .end annotation

    .line 1
    invoke-super {p0, p1, p2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;->onChange()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-object p1
.end method

.method public final setNotifier(Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->notifier:Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayListNotifier;

    .line 2
    .line 3
    return-void
.end method

.method public final bridge size()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/utils/ChangeAwareCopyOnWriteArrayList;->getSize()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
