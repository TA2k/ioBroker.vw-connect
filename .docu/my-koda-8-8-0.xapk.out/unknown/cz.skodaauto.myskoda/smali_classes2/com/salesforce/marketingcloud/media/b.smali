.class public Lcom/salesforce/marketingcloud/media/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/media/f;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/media/b$a;
    }
.end annotation


# static fields
.field private static final g:Ljava/lang/String;


# instance fields
.field private final a:Ljava/util/concurrent/atomic/AtomicInteger;

.field private final b:Lcom/salesforce/marketingcloud/media/o;

.field private final c:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private d:Lcom/salesforce/marketingcloud/media/b$a;

.field private e:Z

.field private f:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "BatchRequestHandler"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/media/b;->g:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/media/o;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/b;->b:Lcom/salesforce/marketingcloud/media/o;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/b;->c:Ljava/util/List;

    .line 7
    .line 8
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 9
    .line 10
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/b;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 18
    .line 19
    return-void
.end method

.method private c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/b;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-gtz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/b;->d:Lcom/salesforce/marketingcloud/media/b$a;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/media/b;->e:Z

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/media/b;->f:Z

    .line 18
    .line 19
    xor-int/lit8 p0, p0, 0x1

    .line 20
    .line 21
    invoke-interface {v0, p0}, Lcom/salesforce/marketingcloud/media/b$a;->a(Z)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method


# virtual methods
.method public a()V
    .locals 0

    .line 7
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/b;->c()V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/media/b$a;Z)V
    .locals 3

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/b;->d:Lcom/salesforce/marketingcloud/media/b$a;

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/b;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    move-result v0

    if-nez v0, :cond_0

    if-eqz p1, :cond_2

    const/4 p0, 0x1

    .line 3
    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/media/b$a;->a(Z)V

    return-void

    .line 4
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/media/b;->c:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz p2, :cond_1

    .line 5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/b;->b:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/media/o;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object v0

    sget-object v1, Lcom/salesforce/marketingcloud/media/t$b;->c:Lcom/salesforce/marketingcloud/media/t$b;

    sget-object v2, Lcom/salesforce/marketingcloud/media/t$b;->d:Lcom/salesforce/marketingcloud/media/t$b;

    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/media/t$b;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/t$b;[Lcom/salesforce/marketingcloud/media/t$b;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object v0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/f;)V

    goto :goto_0

    .line 6
    :cond_1
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/b;->b:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {v1, v0}, Lcom/salesforce/marketingcloud/media/o;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/media/u;

    move-result-object v0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/f;)V

    goto :goto_0

    :cond_2
    return-void
.end method

.method public a(Ljava/lang/Exception;)V
    .locals 3

    .line 8
    instance-of v0, p1, Lcom/salesforce/marketingcloud/media/k;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/media/b;->g:Ljava/lang/String;

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Failed to pre-fetch image, but will be ignored since the url cannot be handled."

    invoke-static {v0, p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/media/b;->f:Z

    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/media/b;->g:Ljava/lang/String;

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Failed to pre-fetch image."

    invoke-static {v0, p1, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    :goto_0
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/media/b;->c()V

    return-void
.end method

.method public b()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/media/b;->e:Z

    .line 3
    .line 4
    return-void
.end method
