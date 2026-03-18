.class public final Lcom/salesforce/marketingcloud/push/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/push/h$a;
    }
.end annotation


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/push/h$a;

.field private static final d:Ljava/lang/String;

.field private static final e:J = 0x7d0L

.field private static final f:J = 0xfL


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/media/o;

.field private final b:Landroid/os/Handler;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/push/h$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/push/h$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/push/h;->c:Lcom/salesforce/marketingcloud/push/h$a;

    .line 8
    .line 9
    const-string v0, "RichFeaturePreloader"

    .line 10
    .line 11
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/push/h;->d:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;)V
    .locals 1

    .line 1
    const-string v0, "imageHandler"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/h;->a:Lcom/salesforce/marketingcloud/media/o;

    .line 10
    .line 11
    new-instance p1, Landroid/os/Handler;

    .line 12
    .line 13
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-direct {p1, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lcom/salesforce/marketingcloud/push/h;->b:Landroid/os/Handler;

    .line 21
    .line 22
    return-void
.end method

.method private final a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Lcom/salesforce/marketingcloud/push/carousel/a;
    .locals 2

    const/4 p0, 0x0

    if-eqz p1, :cond_0

    .line 2
    iget-object p1, p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->richFeatures:Lcom/salesforce/marketingcloud/push/data/RichFeatures;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/data/RichFeatures;->getViewTemplate()Lcom/salesforce/marketingcloud/push/data/Template;

    move-result-object p1

    if-eqz p1, :cond_0

    .line 3
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/push/data/Template;->f()Lcom/salesforce/marketingcloud/push/data/Template$Type;

    move-result-object v0

    sget-object v1, Lcom/salesforce/marketingcloud/push/data/Template$Type;->CarouselFull:Lcom/salesforce/marketingcloud/push/data/Template$Type;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    move-object p1, p0

    .line 4
    :goto_0
    instance-of v0, p1, Lcom/salesforce/marketingcloud/push/carousel/a;

    if-eqz v0, :cond_1

    check-cast p1, Lcom/salesforce/marketingcloud/push/carousel/a;

    return-object p1

    :cond_1
    return-object p0
.end method

.method public static final synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/push/h;->d:Ljava/lang/String;

    return-object v0
.end method

.method private final a(Lcom/salesforce/marketingcloud/push/carousel/a;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/push/carousel/a;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/push/carousel/a;->l()Ljava/util/List;

    move-result-object p0

    .line 6
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 7
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    .line 8
    check-cast v0, Lcom/salesforce/marketingcloud/push/carousel/a$a;

    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/carousel/a$a;->p()Lcom/salesforce/marketingcloud/push/data/b;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/push/data/b;->o()Ljava/lang/String;

    move-result-object v0

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    :goto_1
    if-eqz v0, :cond_0

    .line 10
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object p1
.end method

.method private static final a(Lcom/salesforce/marketingcloud/push/h;Ljava/util/List;)V
    .locals 7

    const-string v0, "this$0"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "$remainingUrls"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v2, Lcom/salesforce/marketingcloud/push/h;->d:Ljava/lang/String;

    sget-object v4, Lcom/salesforce/marketingcloud/push/h$d;->b:Lcom/salesforce/marketingcloud/push/h$d;

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v3, 0x0

    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 22
    iget-object p0, p0, Lcom/salesforce/marketingcloud/push/h;->a:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/util/List;)Lcom/salesforce/marketingcloud/media/b;

    move-result-object p0

    const/4 p1, 0x0

    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/media/b;->a(Lcom/salesforce/marketingcloud/media/b$a;Z)V

    return-void
.end method

.method private final a(Ljava/lang/String;Ljava/util/List;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v1, Lcom/salesforce/marketingcloud/push/h;->d:Ljava/lang/String;

    sget-object v3, Lcom/salesforce/marketingcloud/push/h$b;->b:Lcom/salesforce/marketingcloud/push/h$b;

    const/4 v4, 0x2

    const/4 v5, 0x0

    const/4 v2, 0x0

    invoke-static/range {v0 .. v5}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 12
    new-instance v0, Ljava/util/concurrent/CountDownLatch;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/push/h;->a:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {v1, p1}, Lcom/salesforce/marketingcloud/media/o;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object v1

    .line 14
    sget-object v2, Lcom/salesforce/marketingcloud/media/o$c;->c:Lcom/salesforce/marketingcloud/media/o$c;

    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object v1

    .line 15
    new-instance v2, Lcom/salesforce/marketingcloud/push/h$c;

    invoke-direct {v2, v0, p1}, Lcom/salesforce/marketingcloud/push/h$c;-><init>(Ljava/util/concurrent/CountDownLatch;Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/f;)V

    .line 16
    invoke-direct {p0, p2, v0}, Lcom/salesforce/marketingcloud/push/h;->a(Ljava/util/List;Ljava/util/concurrent/CountDownLatch;)V

    return-void
.end method

.method private final a(Ljava/util/List;Ljava/util/concurrent/CountDownLatch;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/concurrent/CountDownLatch;",
            ")V"
        }
    .end annotation

    .line 17
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/push/h;->b:Landroid/os/Handler;

    new-instance v1, La8/z;

    const/16 v2, 0x13

    invoke-direct {v1, v2, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const-wide/16 p0, 0x7d0

    .line 19
    invoke-virtual {v0, v1, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 20
    :cond_0
    :try_start_0
    sget-object p0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    const-wide/16 v0, 0xf

    invoke-virtual {p2, v0, v1, p0}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    return-void
.end method

.method public static synthetic b(Lcom/salesforce/marketingcloud/push/h;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/push/h;->a(Lcom/salesforce/marketingcloud/push/h;Ljava/util/List;)V

    return-void
.end method


# virtual methods
.method public final b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 2

    .line 2
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/h;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Lcom/salesforce/marketingcloud/push/carousel/a;

    move-result-object p1

    if-nez p1, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/h;->a(Lcom/salesforce/marketingcloud/push/carousel/a;)Ljava/util/List;

    move-result-object p1

    .line 4
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    :goto_0
    return-void

    .line 5
    :cond_1
    invoke-static {p1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    const/4 v1, 0x1

    invoke-static {p1, v1}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    move-result-object p1

    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/push/h;->a(Ljava/lang/String;Ljava/util/List;)V

    return-void
.end method
