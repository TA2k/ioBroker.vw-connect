.class public final Ls6/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/util/SparseArray;

.field public b:Ls6/t;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/util/SparseArray;

    .line 5
    .line 6
    invoke-direct {v0, p1}, Landroid/util/SparseArray;-><init>(I)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ls6/q;->a:Landroid/util/SparseArray;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Ls6/t;II)V
    .locals 3

    .line 1
    invoke-virtual {p1, p2}, Ls6/t;->a(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object p0, p0, Ls6/q;->a:Landroid/util/SparseArray;

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    invoke-virtual {p0, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Ls6/q;

    .line 16
    .line 17
    :goto_0
    const/4 v1, 0x1

    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    new-instance v0, Ls6/q;

    .line 21
    .line 22
    invoke-direct {v0, v1}, Ls6/q;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, p2}, Ls6/t;->a(I)I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    invoke-virtual {p0, v2, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    if-le p3, p2, :cond_2

    .line 33
    .line 34
    add-int/2addr p2, v1

    .line 35
    invoke-virtual {v0, p1, p2, p3}, Ls6/q;->a(Ls6/t;II)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    iput-object p1, v0, Ls6/q;->b:Ls6/t;

    .line 40
    .line 41
    return-void
.end method
