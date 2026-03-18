.class public abstract Lcom/salesforce/marketingcloud/media/a;
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
        Lcom/salesforce/marketingcloud/media/a$a;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field final a:Lcom/salesforce/marketingcloud/media/t;

.field final b:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "TT;>;"
        }
    .end annotation
.end field

.field final c:Lcom/salesforce/marketingcloud/media/w;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/salesforce/marketingcloud/media/w<",
            "TT;>;"
        }
    .end annotation
.end field

.field private final d:Lcom/salesforce/marketingcloud/media/o;

.field private e:Z


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/w;Lcom/salesforce/marketingcloud/media/t;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/media/o;",
            "Lcom/salesforce/marketingcloud/media/w<",
            "TT;>;",
            "Lcom/salesforce/marketingcloud/media/t;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/a;->d:Lcom/salesforce/marketingcloud/media/o;

    .line 5
    .line 6
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/a;->a:Lcom/salesforce/marketingcloud/media/t;

    .line 7
    .line 8
    const/4 p3, 0x0

    .line 9
    if-nez p2, :cond_0

    .line 10
    .line 11
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/a;->b:Ljava/lang/ref/WeakReference;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/media/a$a;

    .line 15
    .line 16
    iget-object v1, p2, Lcom/salesforce/marketingcloud/media/w;->a:Ljava/lang/Object;

    .line 17
    .line 18
    iget-object p1, p1, Lcom/salesforce/marketingcloud/media/o;->h:Ljava/lang/ref/ReferenceQueue;

    .line 19
    .line 20
    invoke-direct {v0, p0, v1, p1}, Lcom/salesforce/marketingcloud/media/a$a;-><init>(Lcom/salesforce/marketingcloud/media/a;Ljava/lang/Object;Ljava/lang/ref/ReferenceQueue;)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/a;->b:Ljava/lang/ref/WeakReference;

    .line 24
    .line 25
    iput-object p3, p2, Lcom/salesforce/marketingcloud/media/w;->a:Ljava/lang/Object;

    .line 26
    .line 27
    :goto_0
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/a;->c:Lcom/salesforce/marketingcloud/media/w;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    const/4 v0, 0x1

    .line 1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/media/a;->e:Z

    return-void
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/media/v$b;)V
.end method

.method public abstract a(Ljava/lang/Exception;)V
.end method

.method public b()Lcom/salesforce/marketingcloud/media/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/a;->d:Lcom/salesforce/marketingcloud/media/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public c()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/a;->a:Lcom/salesforce/marketingcloud/media/t;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/t;->b:Ljava/lang/String;

    .line 4
    .line 5
    return-object p0
.end method

.method public d()Lcom/salesforce/marketingcloud/media/o$c;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/a;->a:Lcom/salesforce/marketingcloud/media/t;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/t;->c:Lcom/salesforce/marketingcloud/media/o$c;

    .line 4
    .line 5
    return-object p0
.end method

.method public e()Lcom/salesforce/marketingcloud/media/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/a;->a:Lcom/salesforce/marketingcloud/media/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public f()Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TT;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/a;->b:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public g()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/media/a;->e:Z

    .line 2
    .line 3
    return p0
.end method
