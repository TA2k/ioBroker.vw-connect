.class public Lcom/salesforce/marketingcloud/media/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/media/o;

.field private final b:Lcom/salesforce/marketingcloud/media/t$a;

.field private c:Z


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Landroid/net/Uri;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    .line 5
    .line 6
    new-instance p1, Lcom/salesforce/marketingcloud/media/t$a;

    .line 7
    .line 8
    invoke-direct {p1, p2}, Lcom/salesforce/marketingcloud/media/t$a;-><init>(Landroid/net/Uri;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    .line 12
    .line 13
    return-void
.end method

.method private a(J)Lcom/salesforce/marketingcloud/media/t;
    .locals 0

    .line 37
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/t$a;->a()Lcom/salesforce/marketingcloud/media/t;

    move-result-object p0

    .line 38
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/media/t;->l:J

    return-object p0
.end method


# virtual methods
.method public a()Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/t$a;->b()Lcom/salesforce/marketingcloud/media/t$a;

    return-object p0
.end method

.method public a(FFI)Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/media/t$a;->a(FFI)Lcom/salesforce/marketingcloud/media/t$a;

    return-object p0
.end method

.method public a(II)Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/media/t$a;->a(II)Lcom/salesforce/marketingcloud/media/t$a;

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/media/t$a;->a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/t$a;

    return-object p0
.end method

.method public varargs a(Lcom/salesforce/marketingcloud/media/t$b;[Lcom/salesforce/marketingcloud/media/t$b;)Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/media/t$a;->a(Lcom/salesforce/marketingcloud/media/t$b;[Lcom/salesforce/marketingcloud/media/t$b;)Lcom/salesforce/marketingcloud/media/t$a;

    return-object p0
.end method

.method public a(Landroid/widget/ImageView;)V
    .locals 1

    const/4 v0, 0x0

    .line 16
    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/media/u;->a(Landroid/widget/ImageView;Lcom/salesforce/marketingcloud/media/f;)V

    return-void
.end method

.method public a(Landroid/widget/ImageView;Lcom/salesforce/marketingcloud/media/f;)V
    .locals 3

    .line 17
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    move-result-object v0

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v1

    if-ne v0, v1, :cond_6

    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/t$a;->d()Z

    move-result v0

    if-nez v0, :cond_0

    .line 19
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    sget-object v1, Lcom/salesforce/marketingcloud/media/o$c;->c:Lcom/salesforce/marketingcloud/media/o$c;

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/media/t$a;->a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/t$a;

    .line 20
    :cond_0
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/media/u;->c:Z

    if-eqz v0, :cond_3

    .line 21
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result v0

    .line 22
    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    move-result v1

    if-eqz v0, :cond_2

    if-nez v1, :cond_1

    goto :goto_0

    .line 23
    :cond_1
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v2, v0, v1}, Lcom/salesforce/marketingcloud/media/t$a;->a(II)Lcom/salesforce/marketingcloud/media/t$a;

    goto :goto_1

    .line 24
    :cond_2
    :goto_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    new-instance v1, Lcom/salesforce/marketingcloud/media/g;

    invoke-direct {v1, p0, p1, p2}, Lcom/salesforce/marketingcloud/media/g;-><init>(Lcom/salesforce/marketingcloud/media/u;Landroid/widget/ImageView;Lcom/salesforce/marketingcloud/media/f;)V

    invoke-virtual {v0, p1, v1}, Lcom/salesforce/marketingcloud/media/o;->a(Landroid/widget/ImageView;Lcom/salesforce/marketingcloud/media/g;)V

    return-void

    .line 25
    :cond_3
    :goto_1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v0

    .line 26
    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/media/u;->a(J)Lcom/salesforce/marketingcloud/media/t;

    move-result-object v0

    .line 27
    iget v1, v0, Lcom/salesforce/marketingcloud/media/t;->d:I

    invoke-static {v1}, Lcom/salesforce/marketingcloud/media/t$b;->a(I)Z

    move-result v1

    if-eqz v1, :cond_5

    .line 28
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    iget-object v2, v0, Lcom/salesforce/marketingcloud/media/t;->b:Ljava/lang/String;

    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v1

    if-eqz v1, :cond_5

    .line 29
    new-instance v0, Lcom/salesforce/marketingcloud/media/v$b;

    sget-object v2, Lcom/salesforce/marketingcloud/media/o$b;->c:Lcom/salesforce/marketingcloud/media/o$b;

    invoke-direct {v0, v1, v2}, Lcom/salesforce/marketingcloud/media/v$b;-><init>(Landroid/graphics/Bitmap;Lcom/salesforce/marketingcloud/media/o$b;)V

    .line 30
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/o;->a:Landroid/content/Context;

    invoke-static {p1, p0, v0}, Lcom/salesforce/marketingcloud/media/l;->a(Landroid/widget/ImageView;Landroid/content/Context;Lcom/salesforce/marketingcloud/media/v$b;)V

    .line 31
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->c()Lcom/salesforce/marketingcloud/media/o$b;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "IMAGE"

    const-string v0, "onSuccess - Loaded from: %s"

    invoke-static {p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p2, :cond_4

    .line 32
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/media/f;->a()V

    :cond_4
    return-void

    .line 33
    :cond_5
    new-instance v1, Lcom/salesforce/marketingcloud/media/w;

    invoke-direct {v1, p1}, Lcom/salesforce/marketingcloud/media/w;-><init>(Ljava/lang/Object;)V

    .line 34
    new-instance p1, Lcom/salesforce/marketingcloud/media/p;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    invoke-direct {p1, v2, v1, v0, p2}, Lcom/salesforce/marketingcloud/media/p;-><init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/w;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/f;)V

    .line 35
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/media/o;->a(Lcom/salesforce/marketingcloud/media/a;)V

    return-void

    .line 36
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "TODO"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public a(Lcom/salesforce/marketingcloud/media/f;)V
    .locals 4

    .line 6
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    move-result-wide v0

    .line 7
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/media/t$a;->d()Z

    move-result v2

    if-nez v2, :cond_0

    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    sget-object v3, Lcom/salesforce/marketingcloud/media/o$c;->b:Lcom/salesforce/marketingcloud/media/o$c;

    invoke-virtual {v2, v3}, Lcom/salesforce/marketingcloud/media/t$a;->a(Lcom/salesforce/marketingcloud/media/o$c;)Lcom/salesforce/marketingcloud/media/t$a;

    .line 9
    :cond_0
    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/media/u;->a(J)Lcom/salesforce/marketingcloud/media/t;

    move-result-object v0

    .line 10
    iget v1, v0, Lcom/salesforce/marketingcloud/media/t;->d:I

    invoke-static {v1}, Lcom/salesforce/marketingcloud/media/t$b;->a(I)Z

    move-result v1

    if-eqz v1, :cond_2

    .line 11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    iget-object v2, v0, Lcom/salesforce/marketingcloud/media/t;->b:Ljava/lang/String;

    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v1

    if-eqz v1, :cond_2

    const/4 p0, 0x0

    .line 12
    new-array p0, p0, [Ljava/lang/Object;

    const-string v0, "IMAGE"

    const-string v1, "onSuccess - Loaded from: MEMORY"

    invoke-static {v0, v1, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    if-eqz p1, :cond_1

    .line 13
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/media/f;->a()V

    :cond_1
    return-void

    .line 14
    :cond_2
    new-instance v1, Lcom/salesforce/marketingcloud/media/j;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    invoke-direct {v1, v2, v0, p1}, Lcom/salesforce/marketingcloud/media/j;-><init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/f;)V

    .line 15
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/u;->a:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {p0, v1}, Lcom/salesforce/marketingcloud/media/o;->a(Lcom/salesforce/marketingcloud/media/a;)V

    return-void
.end method

.method public b()Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/u;->b:Lcom/salesforce/marketingcloud/media/t$a;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/t$a;->c()Lcom/salesforce/marketingcloud/media/t$a;

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public c()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/media/u;->a(Lcom/salesforce/marketingcloud/media/f;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public d()Lcom/salesforce/marketingcloud/media/u;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/media/u;->c:Z

    .line 3
    .line 4
    return-object p0
.end method
