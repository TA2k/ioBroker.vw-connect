.class public final Lh6/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:I

.field public c:Z

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lh6/i;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/os/Parcel;)V
    .locals 5

    const/4 v0, 0x0

    iput v0, p0, Lh6/i;->a:I

    const-string v0, "parcel"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    .line 20
    new-array v1, v0, [J

    iput-object v1, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 21
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->readLongArray([J)V

    .line 22
    sget-object v1, Landroid/widget/RemoteViews;->CREATOR:Landroid/os/Parcelable$Creator;

    const-string v2, "CREATOR"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    new-array v2, v0, [Landroid/widget/RemoteViews;

    .line 24
    invoke-virtual {p1, v2, v1}, Landroid/os/Parcel;->readTypedArray([Ljava/lang/Object;Landroid/os/Parcelable$Creator;)V

    const/4 v1, 0x0

    move v3, v1

    :goto_0
    if-ge v3, v0, :cond_1

    .line 25
    aget-object v4, v2, v3

    if-eqz v4, :cond_0

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "null element found in "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v0, 0x2e

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 27
    :cond_1
    iput-object v2, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 28
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result v0

    const/4 v2, 0x1

    if-ne v0, v2, :cond_2

    move v1, v2

    :cond_2
    iput-boolean v1, p0, Lh6/i;->c:Z

    .line 29
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result p1

    iput p1, p0, Lh6/i;->b:I

    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/bottomsheet/BottomSheetBehavior;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh6/i;->a:I

    .line 32
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 33
    new-instance p1, Laq/p;

    const/4 v0, 0x5

    invoke-direct {p1, p0, v0}, Laq/p;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Lh6/i;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lh6/i;->a:I

    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 31
    new-instance p1, Lm8/o;

    const/16 v0, 0x1a

    invoke-direct {p1, p0, v0}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Lh6/i;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>([J[Landroid/widget/RemoteViews;)V
    .locals 3

    const/4 v0, 0x0

    iput v0, p0, Lh6/i;->a:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 4
    iput-object p2, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 5
    iput-boolean v0, p0, Lh6/i;->c:Z

    const/4 v1, 0x1

    .line 6
    iput v1, p0, Lh6/i;->b:I

    .line 7
    array-length p0, p1

    array-length p1, p2

    if-ne p0, p1, :cond_2

    .line 8
    new-instance p0, Ljava/util/ArrayList;

    array-length p1, p2

    invoke-direct {p0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 9
    array-length p1, p2

    :goto_0
    if-ge v0, p1, :cond_0

    aget-object v2, p2, v0

    .line 10
    invoke-virtual {v2}, Landroid/widget/RemoteViews;->getLayoutId()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    .line 11
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    .line 12
    :cond_0
    invoke-static {p0}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p0

    check-cast p0, Ljava/util/Collection;

    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result p0

    if-gt p0, v1, :cond_1

    return-void

    .line 13
    :cond_1
    const-string p1, "View type count is set to 1, but the collection contains "

    .line 14
    const-string p2, " different layout ids"

    .line 15
    invoke-static {p1, p0, p2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 16
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 17
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "RemoteCollectionItems has different number of ids and views"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public a()Lbp/s;
    .locals 4

    .line 1
    iget-object v0, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llo/n;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    const-string v1, "execute parameter required"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lbp/s;

    .line 16
    .line 17
    iget-object v1, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, [Ljo/d;

    .line 20
    .line 21
    iget-boolean v2, p0, Lh6/i;->c:Z

    .line 22
    .line 23
    iget v3, p0, Lh6/i;->b:I

    .line 24
    .line 25
    invoke-direct {v0, p0, v1, v2, v3}, Lbp/s;-><init>(Lh6/i;[Ljo/d;ZI)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method

.method public b(I)V
    .locals 2

    .line 1
    iget v0, p0, Lh6/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 9
    .line 10
    iget-object v1, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 11
    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iput p1, p0, Lh6/i;->b:I

    .line 22
    .line 23
    iget-boolean p1, p0, Lh6/i;->c:Z

    .line 24
    .line 25
    if-nez p1, :cond_1

    .line 26
    .line 27
    iget-object p1, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    check-cast p1, Landroid/view/View;

    .line 34
    .line 35
    iget-object v0, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lm8/o;

    .line 38
    .line 39
    invoke-virtual {p1, v0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 40
    .line 41
    .line 42
    const/4 p1, 0x1

    .line 43
    iput-boolean p1, p0, Lh6/i;->c:Z

    .line 44
    .line 45
    :cond_1
    :goto_0
    return-void

    .line 46
    :pswitch_0
    iget-object v0, p0, Lh6/i;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 49
    .line 50
    iget-object v1, v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->W:Ljava/lang/ref/WeakReference;

    .line 51
    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    if-nez v1, :cond_2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    iput p1, p0, Lh6/i;->b:I

    .line 62
    .line 63
    iget-boolean p1, p0, Lh6/i;->c:Z

    .line 64
    .line 65
    if-nez p1, :cond_3

    .line 66
    .line 67
    iget-object p1, v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->W:Ljava/lang/ref/WeakReference;

    .line 68
    .line 69
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    check-cast p1, Landroid/view/View;

    .line 74
    .line 75
    iget-object v0, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v0, Laq/p;

    .line 78
    .line 79
    invoke-virtual {p1, v0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 80
    .line 81
    .line 82
    const/4 p1, 0x1

    .line 83
    iput-boolean p1, p0, Lh6/i;->c:Z

    .line 84
    .line 85
    :cond_3
    :goto_1
    return-void

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
