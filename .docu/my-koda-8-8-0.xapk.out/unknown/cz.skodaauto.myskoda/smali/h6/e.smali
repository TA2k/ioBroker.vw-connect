.class public final Lh6/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lju/b;
.implements Laq/e;
.implements Lretrofit2/Converter;
.implements Lul/h;
.implements Ljq/b;
.implements Lk0/a;
.implements Lka/e1;
.implements Lks/b;
.implements Lls/a;
.implements Lkw/b;
.implements Ld6/s;
.implements Lkv/a;
.implements Ll/j;
.implements Llo/n;
.implements Lrl/g;


# static fields
.field public static final synthetic f:I


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    const/16 v0, 0xa

    iput v0, p0, Lh6/e;->d:I

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Lh6/e;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lh6/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    const/16 v0, 0x19

    iput v0, p0, Lh6/e;->d:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const/4 v0, 0x0

    .line 8
    const-string v1, "core-google-shortcuts.PREF_FILE_NAME"

    invoke-virtual {p1, v1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object p1

    iput-object p1, p0, Lh6/e;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/io/File;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lh6/e;->d:I

    const-string v0, "folder"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh6/e;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lh6/e;->d:I

    iput-object p1, p0, Lh6/e;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 1

    const/16 v0, 0x1b

    iput v0, p0, Lh6/e;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Lh6/e;->e:Ljava/lang/Object;

    return-void
.end method

.method public static B(Lh6/e;I)Lo1/k0;
    .locals 10

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lm1/t;

    .line 4
    .line 5
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Lv2/f;->e()Lay0/k;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :goto_0
    move-object v2, v0

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    goto :goto_0

    .line 19
    :goto_1
    invoke-static {v1}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    :try_start_0
    iget-object v0, p0, Lm1/t;->f:Ll2/j1;

    .line 24
    .line 25
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lm1/l;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 32
    .line 33
    .line 34
    iget-object v4, p0, Lm1/t;->p:Lo1/l0;

    .line 35
    .line 36
    iget-wide v6, v0, Lm1/l;->j:J

    .line 37
    .line 38
    iget-boolean v8, p0, Lm1/t;->d:Z

    .line 39
    .line 40
    new-instance v9, Lkq0/a;

    .line 41
    .line 42
    invoke-direct {v9, p1, v0}, Lkq0/a;-><init>(ILm1/l;)V

    .line 43
    .line 44
    .line 45
    move v5, p1

    .line 46
    invoke-virtual/range {v4 .. v9}, Lo1/l0;->a(IJZLay0/k;)Lo1/k0;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :catchall_0
    move-exception v0

    .line 52
    move-object p0, v0

    .line 53
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 54
    .line 55
    .line 56
    throw p0
.end method

.method public static C(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lorg/json/JSONObject;

    .line 7
    .line 8
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v3, Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {p1, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    invoke-virtual {v1, v3, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const-string p1, "name"

    .line 40
    .line 41
    invoke-virtual {v0, p1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 42
    .line 43
    .line 44
    const-string p0, "parameters"

    .line 45
    .line 46
    invoke-virtual {v0, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method


# virtual methods
.method public A(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Landroid/view/View;->clearAnimation()V

    .line 15
    .line 16
    .line 17
    :cond_0
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->removeViewAt(I)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public a(Lrl/a;)Lrl/b;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lpo/c;

    .line 2
    .line 3
    check-cast p2, Laq/k;

    .line 4
    .line 5
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lpo/a;

    .line 10
    .line 11
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lno/p;

    .line 14
    .line 15
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object v1, p1, Lbp/a;->e:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-static {v0, p0}, Lcp/a;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 25
    .line 26
    .line 27
    :try_start_0
    iget-object p0, p1, Lbp/a;->d:Landroid/os/IBinder;

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    const/4 v1, 0x1

    .line 31
    invoke-interface {p0, v1, v0, p1, v1}, Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p2, p1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 43
    .line 44
    .line 45
    throw p0
.end method

.method public apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lp/a;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lp/a;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lk0/h;->c(Ljava/lang/Object;)Lk0/j;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public b(Landroid/view/View;)I
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lka/g0;

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lka/g0;

    .line 16
    .line 17
    iget-object p1, p1, Lka/g0;->b:Landroid/graphics/Rect;

    .line 18
    .line 19
    iget p1, p1, Landroid/graphics/Rect;->left:I

    .line 20
    .line 21
    sub-int/2addr v0, p1

    .line 22
    iget p0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 23
    .line 24
    sub-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lka/f0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lka/f0;->E()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public d(Lil/h;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljl/h;

    .line 4
    .line 5
    iget-object p0, p0, Ljl/h;->j:Lyy0/c2;

    .line 6
    .line 7
    new-instance v0, Lhg/q;

    .line 8
    .line 9
    const/4 v1, 0x4

    .line 10
    invoke-direct {v0, p0, v1}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0, p1}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public e()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/mh;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/mh;->e:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0
.end method

.method public f(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public g(Lms/n;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    const-string p0, "FirebaseCrashlytics"

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-static {p0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const-string p1, "Registered Firebase Analytics event receiver for breadcrumbs"

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-static {p0, p1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh6/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lju/c;

    .line 9
    .line 10
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhu/w0;

    .line 15
    .line 16
    new-instance v0, Lhu/r0;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Lhu/r0;-><init>(Lhu/w0;)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_0
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lj1/a;

    .line 25
    .line 26
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lgt/b;

    .line 29
    .line 30
    new-instance v0, Lhu/l;

    .line 31
    .line 32
    invoke-direct {v0, p0}, Lhu/l;-><init>(Lgt/b;)V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public getFormat()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/mh;

    .line 4
    .line 5
    iget p0, p0, Ljp/mh;->d:I

    .line 6
    .line 7
    return p0
.end method

.method public h()Landroid/graphics/Rect;
    .locals 7

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/mh;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/mh;->h:[Landroid/graphics/Point;

    .line 6
    .line 7
    if-eqz p0, :cond_1

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/high16 v1, -0x80000000

    .line 11
    .line 12
    const v2, 0x7fffffff

    .line 13
    .line 14
    .line 15
    move v3, v2

    .line 16
    move v4, v3

    .line 17
    move v2, v1

    .line 18
    :goto_0
    array-length v5, p0

    .line 19
    if-ge v0, v5, :cond_0

    .line 20
    .line 21
    aget-object v5, p0, v0

    .line 22
    .line 23
    iget v6, v5, Landroid/graphics/Point;->x:I

    .line 24
    .line 25
    invoke-static {v3, v6}, Ljava/lang/Math;->min(II)I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    iget v6, v5, Landroid/graphics/Point;->x:I

    .line 30
    .line 31
    invoke-static {v1, v6}, Ljava/lang/Math;->max(II)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    iget v6, v5, Landroid/graphics/Point;->y:I

    .line 36
    .line 37
    invoke-static {v4, v6}, Ljava/lang/Math;->min(II)I

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    iget v5, v5, Landroid/graphics/Point;->y:I

    .line 42
    .line 43
    invoke-static {v2, v5}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    add-int/lit8 v0, v0, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    new-instance p0, Landroid/graphics/Rect;

    .line 51
    .line 52
    invoke-direct {p0, v3, v4, v1, v2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 53
    .line 54
    .line 55
    return-object p0

    .line 56
    :cond_1
    const/4 p0, 0x0

    .line 57
    return-object p0
.end method

.method public i()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/mh;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/mh;->f:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0
.end method

.method public j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Ld01/v0;

    .line 2
    .line 3
    const-string v0, "body"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/io/File;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/io/File;->mkdirs()Z

    .line 13
    .line 14
    .line 15
    new-instance v0, Ljava/io/File;

    .line 16
    .line 17
    new-instance v1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v2, "pdfExport_"

    .line 20
    .line 21
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-wide/32 v2, 0xf423f

    .line 25
    .line 26
    .line 27
    sget-object v4, Ley0/e;->e:Ley0/a;

    .line 28
    .line 29
    const-wide/32 v5, 0x186a1

    .line 30
    .line 31
    .line 32
    invoke-virtual {v4, v5, v6, v2, v3}, Ley0/e;->d(JJ)J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    const/16 v4, 0x10

    .line 37
    .line 38
    invoke-static {v4}, Lry/a;->a(I)V

    .line 39
    .line 40
    .line 41
    invoke-static {v4, v2, v3}, Lpw/a;->c(IJ)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    const/4 v3, 0x6

    .line 46
    invoke-static {v3, v2}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    const-string v3, ".pdf"

    .line 51
    .line 52
    invoke-static {v1, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-direct {v0, p0, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance p0, Ljava/io/FileOutputStream;

    .line 60
    .line 61
    invoke-direct {p0, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 62
    .line 63
    .line 64
    const/16 v1, 0x2000

    .line 65
    .line 66
    new-instance v2, Ljava/io/BufferedOutputStream;

    .line 67
    .line 68
    invoke-direct {v2, p0, v1}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V

    .line 69
    .line 70
    .line 71
    :try_start_0
    invoke-virtual {p1}, Ld01/v0;->p0()Lu01/h;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-interface {p0}, Lu01/h;->w0()Ljava/io/InputStream;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    instance-of p1, p0, Ljava/io/BufferedInputStream;

    .line 80
    .line 81
    if-eqz p1, :cond_0

    .line 82
    .line 83
    check-cast p0, Ljava/io/BufferedInputStream;

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :catchall_0
    move-exception p0

    .line 87
    goto :goto_1

    .line 88
    :cond_0
    new-instance p1, Ljava/io/BufferedInputStream;

    .line 89
    .line 90
    invoke-direct {p1, p0, v1}, Ljava/io/BufferedInputStream;-><init>(Ljava/io/InputStream;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    .line 92
    .line 93
    move-object p0, p1

    .line 94
    :goto_0
    :try_start_1
    invoke-static {p0, v2}, Llp/ud;->b(Ljava/io/InputStream;Ljava/io/OutputStream;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 95
    .line 96
    .line 97
    :try_start_2
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 98
    .line 99
    .line 100
    invoke-interface {v2}, Ljava/io/Closeable;->close()V

    .line 101
    .line 102
    .line 103
    return-object v0

    .line 104
    :catchall_1
    move-exception p1

    .line 105
    :try_start_3
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 106
    :catchall_2
    move-exception v0

    .line 107
    :try_start_4
    invoke-static {p0, p1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 108
    .line 109
    .line 110
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 111
    :goto_1
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 112
    :catchall_3
    move-exception p1

    .line 113
    invoke-static {v2, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 114
    .line 115
    .line 116
    throw p1
.end method

.method public k()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/mh;

    .line 4
    .line 5
    iget p0, p0, Ljp/mh;->i:I

    .line 6
    .line 7
    return p0
.end method

.method public l(Ll/l;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/appcompat/widget/ActionMenuView;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/appcompat/widget/ActionMenuView;->x:Lj1/a;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lj1/a;->l(Ll/l;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public m(Ll/l;Landroid/view/MenuItem;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/appcompat/widget/ActionMenuView;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/appcompat/widget/ActionMenuView;->C:Lm/m;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    check-cast p0, Lhu/q;

    .line 10
    .line 11
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Landroidx/appcompat/widget/Toolbar;

    .line 14
    .line 15
    iget-object p0, p0, Landroidx/appcompat/widget/Toolbar;->J:Ld6/n;

    .line 16
    .line 17
    invoke-virtual {p0, p2}, Ld6/n;->a(Landroid/view/MenuItem;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public n()I
    .locals 1

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lka/f0;

    .line 4
    .line 5
    iget v0, p0, Lka/f0;->n:I

    .line 6
    .line 7
    invoke-virtual {p0}, Lka/f0;->F()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    sub-int/2addr v0, p0

    .line 12
    return v0
.end method

.method public o(Lrl/a;Landroid/graphics/Bitmap;Ljava/util/Map;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lhm/g;

    .line 4
    .line 5
    invoke-static {p2}, Llp/ye;->b(Landroid/graphics/Bitmap;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lhm/g;->d(Lrl/a;Landroid/graphics/Bitmap;Ljava/util/Map;I)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 4

    .line 1
    iget-object p1, p2, Ld6/w1;->a:Ld6/s1;

    .line 2
    .line 3
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;

    .line 6
    .line 7
    iget-object v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 8
    .line 9
    invoke-static {v0, p2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_5

    .line 14
    .line 15
    iput-object p2, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q:Ld6/w1;

    .line 16
    .line 17
    invoke-virtual {p2}, Ld6/w1;->d()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v1, 0x0

    .line 22
    const/4 v2, 0x1

    .line 23
    if-lez v0, :cond_0

    .line 24
    .line 25
    move v0, v2

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move v0, v1

    .line 28
    :goto_0
    iput-boolean v0, p0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->r:Z

    .line 29
    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, Landroid/view/View;->getBackground()Landroid/graphics/drawable/Drawable;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    if-nez v0, :cond_1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v2, v1

    .line 40
    :goto_1
    invoke-virtual {p0, v2}, Landroid/view/View;->setWillNotDraw(Z)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1}, Ld6/s1;->o()Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_2
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    :goto_2
    if-ge v1, v0, :cond_4

    .line 55
    .line 56
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    sget-object v3, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 61
    .line 62
    invoke-virtual {v2}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-eqz v3, :cond_3

    .line 67
    .line 68
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Ll5/c;

    .line 73
    .line 74
    iget-object v2, v2, Ll5/c;->a:Ll5/a;

    .line 75
    .line 76
    if-eqz v2, :cond_3

    .line 77
    .line 78
    invoke-virtual {p1}, Ld6/s1;->o()Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_3

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    :goto_3
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 89
    .line 90
    .line 91
    :cond_5
    return-object p2
.end method

.method public onComplete(Laq/j;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public p()[Landroid/graphics/Point;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/mh;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/mh;->h:[Landroid/graphics/Point;

    .line 6
    .line 7
    return-object p0
.end method

.method public q(Lmw/j;Lnw/g;)V
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v1, Lnw/g;->d:Lmw/c;

    .line 6
    .line 7
    move-object/from16 v3, p0

    .line 8
    .line 9
    iget-object v3, v3, Lh6/e;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Lmw/l;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    if-eqz v3, :cond_6

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object v5, v0, Lmw/j;->h:Lrw/b;

    .line 20
    .line 21
    iget-wide v6, v0, Lmw/j;->d:D

    .line 22
    .line 23
    invoke-interface {v2, v6, v7, v5}, Lmw/c;->c(DLrw/b;)D

    .line 24
    .line 25
    .line 26
    move-result-wide v6

    .line 27
    iget-wide v8, v0, Lmw/j;->e:D

    .line 28
    .line 29
    invoke-interface {v2, v8, v9, v5}, Lmw/c;->i(DLrw/b;)D

    .line 30
    .line 31
    .line 32
    move-result-wide v8

    .line 33
    iget-object v10, v1, Lnw/g;->d:Lmw/c;

    .line 34
    .line 35
    iget-wide v11, v0, Lmw/j;->f:D

    .line 36
    .line 37
    iget-wide v13, v0, Lmw/j;->g:D

    .line 38
    .line 39
    iget-object v15, v0, Lmw/j;->h:Lrw/b;

    .line 40
    .line 41
    invoke-interface/range {v10 .. v15}, Lmw/c;->j(DDLrw/b;)D

    .line 42
    .line 43
    .line 44
    move-result-wide v10

    .line 45
    iget-object v12, v1, Lnw/g;->d:Lmw/c;

    .line 46
    .line 47
    iget-wide v13, v0, Lmw/j;->f:D

    .line 48
    .line 49
    iget-wide v1, v0, Lmw/j;->g:D

    .line 50
    .line 51
    iget-object v0, v0, Lmw/j;->h:Lrw/b;

    .line 52
    .line 53
    move-object/from16 v17, v0

    .line 54
    .line 55
    move-wide v15, v1

    .line 56
    invoke-interface/range {v12 .. v17}, Lmw/c;->l(DDLrw/b;)D

    .line 57
    .line 58
    .line 59
    move-result-wide v0

    .line 60
    iget-object v2, v3, Lmw/l;->a:Ljava/lang/Double;

    .line 61
    .line 62
    if-eqz v2, :cond_2

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 65
    .line 66
    .line 67
    move-result-wide v12

    .line 68
    cmpl-double v2, v12, v6

    .line 69
    .line 70
    if-lez v2, :cond_1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    move-wide v6, v12

    .line 74
    :cond_2
    :goto_0
    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    iput-object v2, v3, Lmw/l;->a:Ljava/lang/Double;

    .line 79
    .line 80
    iget-object v2, v3, Lmw/l;->b:Ljava/lang/Double;

    .line 81
    .line 82
    if-eqz v2, :cond_4

    .line 83
    .line 84
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 85
    .line 86
    .line 87
    move-result-wide v5

    .line 88
    cmpg-double v2, v5, v8

    .line 89
    .line 90
    if-gez v2, :cond_3

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    move-wide v8, v5

    .line 94
    :cond_4
    :goto_1
    invoke-static {v8, v9}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    iput-object v2, v3, Lmw/l;->b:Ljava/lang/Double;

    .line 99
    .line 100
    iget-object v2, v3, Lmw/l;->c:Ljava/util/LinkedHashMap;

    .line 101
    .line 102
    invoke-virtual {v2, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    check-cast v2, Lmw/k;

    .line 107
    .line 108
    if-eqz v2, :cond_5

    .line 109
    .line 110
    iget-wide v3, v2, Lmw/k;->a:D

    .line 111
    .line 112
    invoke-static {v3, v4, v10, v11}, Ljava/lang/Math;->min(DD)D

    .line 113
    .line 114
    .line 115
    move-result-wide v3

    .line 116
    iput-wide v3, v2, Lmw/k;->a:D

    .line 117
    .line 118
    iget-wide v3, v2, Lmw/k;->b:D

    .line 119
    .line 120
    invoke-static {v3, v4, v0, v1}, Ljava/lang/Math;->max(DD)D

    .line 121
    .line 122
    .line 123
    move-result-wide v0

    .line 124
    iput-wide v0, v2, Lmw/k;->b:D

    .line 125
    .line 126
    return-void

    .line 127
    :cond_5
    iget-object v2, v3, Lmw/l;->c:Ljava/util/LinkedHashMap;

    .line 128
    .line 129
    new-instance v3, Lmw/k;

    .line 130
    .line 131
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 132
    .line 133
    .line 134
    iput-wide v10, v3, Lmw/k;->a:D

    .line 135
    .line 136
    iput-wide v0, v3, Lmw/k;->b:D

    .line 137
    .line 138
    invoke-interface {v2, v4, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    return-void

    .line 142
    :cond_6
    const-string v0, "ranges"

    .line 143
    .line 144
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw v4
.end method

.method public r(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lka/f0;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lka/f0;->u(I)Landroid/view/View;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public s(Landroid/view/View;)I
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lka/g0;

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lka/g0;

    .line 16
    .line 17
    iget-object p1, p1, Lka/g0;->b:Landroid/graphics/Rect;

    .line 18
    .line 19
    iget p1, p1, Landroid/graphics/Rect;->right:I

    .line 20
    .line 21
    add-int/2addr v0, p1

    .line 22
    iget p0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 23
    .line 24
    add-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public t(Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 8

    .line 1
    const-string v0, "$A$:"

    .line 2
    .line 3
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lms/n;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p1, p2}, Lh6/e;->C(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    iget-object v3, p0, Lms/n;->a:Lms/p;

    .line 26
    .line 27
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    iget-wide v0, v3, Lms/p;->d:J

    .line 32
    .line 33
    sub-long v4, p0, v0

    .line 34
    .line 35
    iget-object p0, v3, Lms/p;->p:Lns/d;

    .line 36
    .line 37
    iget-object p0, p0, Lns/d;->a:Lns/b;

    .line 38
    .line 39
    new-instance v2, Lms/o;

    .line 40
    .line 41
    const/4 v7, 0x0

    .line 42
    invoke-direct/range {v2 .. v7}, Lms/o;-><init>(Lms/p;JLjava/lang/String;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v2}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :catch_0
    const/4 p0, 0x0

    .line 50
    const-string p1, "FirebaseCrashlytics"

    .line 51
    .line 52
    const-string p2, "Unable to serialize Firebase Analytics event to breadcrumb."

    .line 53
    .line 54
    invoke-static {p1, p2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 55
    .line 56
    .line 57
    :cond_0
    return-void
.end method

.method public u(C)V
    .locals 1

    .line 1
    const/16 v0, 0x7f

    .line 2
    .line 3
    if-gt p1, v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/BitSet;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ljava/util/BitSet;->set(I)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 14
    .line 15
    const-string p1, "Can only match ASCII characters"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public v()Lll/e;
    .locals 2

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, La8/b;

    .line 4
    .line 5
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lll/d;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    const/4 v1, 0x1

    .line 11
    :try_start_0
    invoke-virtual {p0, v1}, La8/b;->e(Z)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, La8/b;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lll/a;

    .line 17
    .line 18
    iget-object p0, p0, Lll/a;->a:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Lll/d;->d(Ljava/lang/String;)Lll/b;

    .line 21
    .line 22
    .line 23
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    monitor-exit v0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    new-instance v0, Lll/e;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Lll/e;-><init>(Lll/b;)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :cond_0
    const/4 p0, 0x0

    .line 34
    return-object p0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    monitor-exit v0

    .line 37
    throw p0
.end method

.method public w()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll2/x;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public x(Lqn/s;Ljava/lang/Thread;Ljava/lang/Throwable;)V
    .locals 8

    .line 1
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Lms/l;

    .line 5
    .line 6
    const-string p0, "Handling uncaught exception \""

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\" from thread "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "FirebaseCrashlytics"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-static {v0, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v7, 0x0

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    const-string v0, "FirebaseCrashlytics"

    .line 44
    .line 45
    invoke-static {v0, p0, v7}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 46
    .line 47
    .line 48
    :cond_0
    invoke-static {}, Llp/cb;->b()V

    .line 49
    .line 50
    .line 51
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 52
    .line 53
    .line 54
    move-result-wide v2

    .line 55
    iget-object p0, v1, Lms/l;->e:Lns/d;

    .line 56
    .line 57
    iget-object p0, p0, Lns/d;->a:Lns/b;

    .line 58
    .line 59
    new-instance v0, Lms/j;

    .line 60
    .line 61
    move-object v6, p1

    .line 62
    move-object v5, p2

    .line 63
    move-object v4, p3

    .line 64
    invoke-direct/range {v0 .. v6}, Lms/j;-><init>(Lms/l;JLjava/lang/Throwable;Ljava/lang/Thread;Lqn/s;)V

    .line 65
    .line 66
    .line 67
    iget-object p1, p0, Lns/b;->e:Ljava/lang/Object;

    .line 68
    .line 69
    monitor-enter p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 70
    :try_start_1
    iget-object p2, p0, Lns/b;->f:Laq/t;

    .line 71
    .line 72
    iget-object p3, p0, Lns/b;->d:Ljava/util/concurrent/ExecutorService;

    .line 73
    .line 74
    new-instance v2, Lgr/k;

    .line 75
    .line 76
    const/16 v3, 0x11

    .line 77
    .line 78
    invoke-direct {v2, v0, v3}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p2, p3, v2}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    iput-object p2, p0, Lns/b;->f:Laq/t;

    .line 86
    .line 87
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 88
    :try_start_2
    invoke-static {p2}, Lms/v;->a(Laq/t;)V
    :try_end_2
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :catchall_0
    move-exception v0

    .line 93
    move-object p0, v0

    .line 94
    goto :goto_1

    .line 95
    :catch_0
    move-exception v0

    .line 96
    move-object p0, v0

    .line 97
    :try_start_3
    const-string p1, "Error handling uncaught exception"

    .line 98
    .line 99
    const-string p2, "FirebaseCrashlytics"

    .line 100
    .line 101
    invoke-static {p2, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :catch_1
    const-string p0, "Cannot send reports. Timed out while fetching settings."

    .line 106
    .line 107
    const-string p1, "FirebaseCrashlytics"

    .line 108
    .line 109
    invoke-static {p1, p0, v7}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 110
    .line 111
    .line 112
    :goto_0
    monitor-exit v1

    .line 113
    return-void

    .line 114
    :catchall_1
    move-exception v0

    .line 115
    move-object p0, v0

    .line 116
    :try_start_4
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 117
    :try_start_5
    throw p0

    .line 118
    :goto_1
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 119
    throw p0
.end method

.method public y(CC)V
    .locals 0

    .line 1
    :goto_0
    if-gt p1, p2, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lh6/e;->u(C)V

    .line 4
    .line 5
    .line 6
    add-int/lit8 p1, p1, 0x1

    .line 7
    .line 8
    int-to-char p1, p1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    return-void
.end method

.method public z()[B
    .locals 2

    .line 1
    const-string v0, "core-google-shortcuts.TINK_KEYSET"

    .line 2
    .line 3
    :try_start_0
    iget-object p0, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Landroid/content/SharedPreferences;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-interface {p0, v0, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-static {p0}, Lkp/d6;->a(Ljava/lang/String;)[B

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    new-instance p0, Ljava/io/FileNotFoundException;

    .line 20
    .line 21
    const-string v0, "can\'t read keyset; the pref value core-google-shortcuts.TINK_KEYSET does not exist"

    .line 22
    .line 23
    invoke-direct {p0, v0}, Ljava/io/FileNotFoundException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    :catch_0
    new-instance p0, Ljava/io/CharConversionException;

    .line 28
    .line 29
    const-string v0, "can\'t read keyset; the pref value core-google-shortcuts.TINK_KEYSET is not a valid hex string"

    .line 30
    .line 31
    invoke-direct {p0, v0}, Ljava/io/CharConversionException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method
