.class public Lcom/salesforce/marketingcloud/media/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/media/o$c;,
        Lcom/salesforce/marketingcloud/media/o$b;
    }
.end annotation


# static fields
.field static final i:Landroid/os/Handler;


# instance fields
.field final a:Landroid/content/Context;

.field final b:Lcom/salesforce/marketingcloud/media/h;

.field final c:Lcom/salesforce/marketingcloud/media/c;

.field final d:Lcom/salesforce/marketingcloud/media/s;

.field final e:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Landroid/widget/ImageView;",
            "Lcom/salesforce/marketingcloud/media/g;",
            ">;"
        }
    .end annotation
.end field

.field final f:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/Object;",
            "Lcom/salesforce/marketingcloud/media/a;",
            ">;"
        }
    .end annotation
.end field

.field private final g:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/media/v;",
            ">;"
        }
    .end annotation
.end field

.field public h:Ljava/lang/ref/ReferenceQueue;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/media/o$a;

    .line 2
    .line 3
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/media/o$a;-><init>(Landroid/os/Looper;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lcom/salesforce/marketingcloud/media/o;->i:Landroid/os/Handler;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/o;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/o;->b:Lcom/salesforce/marketingcloud/media/h;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/o;->c:Lcom/salesforce/marketingcloud/media/c;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/media/o;->d:Lcom/salesforce/marketingcloud/media/s;

    .line 11
    .line 12
    new-instance p2, Ljava/util/ArrayList;

    .line 13
    .line 14
    const/4 p3, 0x2

    .line 15
    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    .line 16
    .line 17
    .line 18
    new-instance p3, Lcom/salesforce/marketingcloud/media/r;

    .line 19
    .line 20
    invoke-direct {p3, p4}, Lcom/salesforce/marketingcloud/media/r;-><init>(Lcom/salesforce/marketingcloud/media/s;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    new-instance p3, Lcom/salesforce/marketingcloud/media/i;

    .line 27
    .line 28
    invoke-direct {p3, p1}, Lcom/salesforce/marketingcloud/media/i;-><init>(Landroid/content/Context;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-static {p2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/o;->g:Ljava/util/List;

    .line 39
    .line 40
    new-instance p1, Ljava/util/WeakHashMap;

    .line 41
    .line 42
    invoke-direct {p1}, Ljava/util/WeakHashMap;-><init>()V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/o;->f:Ljava/util/Map;

    .line 46
    .line 47
    new-instance p1, Ljava/util/WeakHashMap;

    .line 48
    .line 49
    invoke-direct {p1}, Ljava/util/WeakHashMap;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/o;->e:Ljava/util/Map;

    .line 53
    .line 54
    return-void
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;)Lcom/salesforce/marketingcloud/media/o;
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/media/c;

    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/media/c;-><init>(Landroid/content/Context;)V

    .line 2
    new-instance v1, Lcom/salesforce/marketingcloud/media/s;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->f()Ljava/io/File;

    move-result-object p1

    invoke-direct {v1, p1}, Lcom/salesforce/marketingcloud/media/s;-><init>(Ljava/io/File;)V

    .line 3
    new-instance p1, Lcom/salesforce/marketingcloud/media/h;

    new-instance v2, Lcom/salesforce/marketingcloud/media/m;

    invoke-direct {v2}, Lcom/salesforce/marketingcloud/media/m;-><init>()V

    sget-object v3, Lcom/salesforce/marketingcloud/media/o;->i:Landroid/os/Handler;

    invoke-direct {p1, p0, v2, v3, v0}, Lcom/salesforce/marketingcloud/media/h;-><init>(Landroid/content/Context;Ljava/util/concurrent/ExecutorService;Landroid/os/Handler;Lcom/salesforce/marketingcloud/media/c;)V

    .line 4
    new-instance v2, Lcom/salesforce/marketingcloud/media/o;

    invoke-direct {v2, p0, p1, v0, v1}, Lcom/salesforce/marketingcloud/media/o;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/s;)V

    return-object v2
.end method

.method private a(Lcom/salesforce/marketingcloud/media/a;Lcom/salesforce/marketingcloud/media/v$b;Ljava/lang/Exception;)V
    .locals 1

    .line 42
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->g()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    .line 43
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->f:Ljava/util/Map;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->f()Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p0, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    if-eqz p2, :cond_1

    .line 44
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/media/a;->a(Lcom/salesforce/marketingcloud/media/v$b;)V

    return-void

    .line 45
    :cond_1
    invoke-virtual {p1, p3}, Lcom/salesforce/marketingcloud/media/a;->a(Ljava/lang/Exception;)V

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/String;)Landroid/graphics/Bitmap;
    .locals 0

    .line 40
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->c:Lcom/salesforce/marketingcloud/media/c;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/c;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object p0

    return-object p0
.end method

.method public a(Ljava/util/List;)Lcom/salesforce/marketingcloud/media/b;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Lcom/salesforce/marketingcloud/media/b;"
        }
    .end annotation

    .line 5
    new-instance v0, Lcom/salesforce/marketingcloud/media/b;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-direct {v0, p0, v1}, Lcom/salesforce/marketingcloud/media/b;-><init>(Lcom/salesforce/marketingcloud/media/o;Ljava/util/List;)V

    return-object v0
.end method

.method public a()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/media/v;",
            ">;"
        }
    .end annotation

    .line 14
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->g:Ljava/util/List;

    return-object p0
.end method

.method public a(Landroid/widget/ImageView;Lcom/salesforce/marketingcloud/media/g;)V
    .locals 1

    .line 28
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/o;->e:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 29
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/Object;)V

    .line 30
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->e:Ljava/util/Map;

    invoke-interface {p0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 2

    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->f()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/o;->f:Ljava/util/Map;

    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eq v1, p1, :cond_0

    .line 11
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/Object;)V

    .line 12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/o;->f:Ljava/util/Map;

    invoke-interface {v1, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->b:Lcom/salesforce/marketingcloud/media/h;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/h;->b(Lcom/salesforce/marketingcloud/media/a;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/e;)V
    .locals 1

    .line 24
    iget-object p0, p1, Lcom/salesforce/marketingcloud/media/e;->c:Lcom/salesforce/marketingcloud/media/d;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/d;->b()Lcom/salesforce/marketingcloud/media/f;

    move-result-object p0

    if-eqz p0, :cond_1

    .line 25
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/e;->b()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 26
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/e;->a()Ljava/lang/Exception;

    move-result-object p1

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/media/f;->a(Ljava/lang/Exception;)V

    return-void

    .line 27
    :cond_0
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/media/f;->a()V

    :cond_1
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/n;)V
    .locals 5

    .line 15
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->c()Lcom/salesforce/marketingcloud/media/a;

    move-result-object v0

    .line 16
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->d()Ljava/util/List;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    .line 17
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_0

    const/4 v3, 0x1

    goto :goto_0

    :cond_0
    move v3, v2

    :goto_0
    if-nez v0, :cond_1

    if-eqz v3, :cond_3

    .line 18
    :cond_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->f()Ljava/lang/Exception;

    move-result-object v4

    .line 19
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/n;->i()Lcom/salesforce/marketingcloud/media/v$b;

    move-result-object p1

    if-eqz v0, :cond_2

    .line 20
    invoke-direct {p0, v0, p1, v4}, Lcom/salesforce/marketingcloud/media/o;->a(Lcom/salesforce/marketingcloud/media/a;Lcom/salesforce/marketingcloud/media/v$b;Ljava/lang/Exception;)V

    :cond_2
    if-eqz v3, :cond_3

    .line 21
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v0

    :goto_1
    if-ge v2, v0, :cond_3

    .line 22
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/media/a;

    .line 23
    invoke-direct {p0, v3, p1, v4}, Lcom/salesforce/marketingcloud/media/o;->a(Lcom/salesforce/marketingcloud/media/a;Lcom/salesforce/marketingcloud/media/v$b;Ljava/lang/Exception;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_3
    return-void
.end method

.method public a(Ljava/lang/Object;)V
    .locals 2

    .line 31
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    move-result-object v0

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v1

    if-ne v0, v1, :cond_1

    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/o;->f:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/media/a;

    if-eqz v0, :cond_0

    .line 33
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/a;->a()V

    .line 34
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/o;->b:Lcom/salesforce/marketingcloud/media/h;

    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/media/h;->a(Lcom/salesforce/marketingcloud/media/a;)V

    .line 35
    :cond_0
    instance-of v0, p1, Landroid/widget/ImageView;

    if-eqz v0, :cond_1

    .line 36
    check-cast p1, Landroid/widget/ImageView;

    .line 37
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->e:Ljava/util/Map;

    .line 38
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lcom/salesforce/marketingcloud/media/g;

    if-eqz p0, :cond_1

    .line 39
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/g;->a()V

    :cond_1
    return-void
.end method

.method public a(Ljava/lang/String;Landroid/graphics/Bitmap;)V
    .locals 0

    .line 41
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->c:Lcom/salesforce/marketingcloud/media/c;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/media/c;->a(Ljava/lang/String;Landroid/graphics/Bitmap;)V

    return-void
.end method

.method public a(Ljava/util/Collection;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/util/Collection;Lcom/salesforce/marketingcloud/media/f;)V

    return-void
.end method

.method public a(Ljava/util/Collection;Lcom/salesforce/marketingcloud/media/f;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/media/f;",
            ")V"
        }
    .end annotation

    if-eqz p1, :cond_0

    .line 7
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/o;->b:Lcom/salesforce/marketingcloud/media/h;

    new-instance v1, Lcom/salesforce/marketingcloud/media/d;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iget-object p1, p0, Lcom/salesforce/marketingcloud/media/o;->d:Lcom/salesforce/marketingcloud/media/s;

    invoke-direct {v1, p0, v2, p1, p2}, Lcom/salesforce/marketingcloud/media/d;-><init>(Lcom/salesforce/marketingcloud/media/o;Ljava/util/Collection;Lcom/salesforce/marketingcloud/media/s;Lcom/salesforce/marketingcloud/media/f;)V

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/media/h;->a(Lcom/salesforce/marketingcloud/media/d;)V

    :cond_0
    return-void
.end method

.method public b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/media/u;

    .line 2
    .line 3
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {v0, p0, p1}, Lcom/salesforce/marketingcloud/media/u;-><init>(Lcom/salesforce/marketingcloud/media/o;Landroid/net/Uri;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
