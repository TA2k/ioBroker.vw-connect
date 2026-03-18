.class public final Let/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Let/e;
.implements Let/f;


# instance fields
.field public final a:Lgs/o;

.field public final b:Landroid/content/Context;

.field public final c:Lgt/b;

.field public final d:Ljava/util/Set;

.field public final e:Ljava/util/concurrent/Executor;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/util/Set;Lgt/b;Ljava/util/concurrent/Executor;)V
    .locals 3

    .line 1
    new-instance v0, Lgs/o;

    .line 2
    .line 3
    new-instance v1, Las/f;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v1, p1, p2, v2}, Las/f;-><init>(Landroid/content/Context;Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, v1}, Lgs/o;-><init>(Lgt/b;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Let/c;->a:Lgs/o;

    .line 16
    .line 17
    iput-object p3, p0, Let/c;->d:Ljava/util/Set;

    .line 18
    .line 19
    iput-object p5, p0, Let/c;->e:Ljava/util/concurrent/Executor;

    .line 20
    .line 21
    iput-object p4, p0, Let/c;->c:Lgt/b;

    .line 22
    .line 23
    iput-object p1, p0, Let/c;->b:Landroid/content/Context;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Let/c;->d:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-gtz v0, :cond_0

    .line 9
    .line 10
    invoke-static {v1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v0, p0, Let/c;->b:Landroid/content/Context;

    .line 15
    .line 16
    invoke-static {v0}, Llp/yf;->a(Landroid/content/Context;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    invoke-static {v1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    new-instance v0, Let/b;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-direct {v0, p0, v1}, Let/b;-><init>(Let/c;I)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Let/c;->e:Ljava/util/concurrent/Executor;

    .line 33
    .line 34
    invoke-static {p0, v0}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 35
    .line 36
    .line 37
    return-void
.end method
