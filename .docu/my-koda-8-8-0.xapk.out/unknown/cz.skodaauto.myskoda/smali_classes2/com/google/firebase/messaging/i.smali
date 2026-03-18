.class public final synthetic Lcom/google/firebase/messaging/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/b;


# instance fields
.field public final synthetic d:Landroid/content/Context;

.field public final synthetic e:Landroid/content/Intent;

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;Landroid/content/Intent;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/firebase/messaging/i;->d:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/firebase/messaging/i;->e:Landroid/content/Intent;

    .line 7
    .line 8
    iput-boolean p3, p0, Lcom/google/firebase/messaging/i;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final w(Laq/j;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/16 v1, 0x192

    .line 12
    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    return-object p1

    .line 16
    :cond_0
    iget-object p1, p0, Lcom/google/firebase/messaging/i;->d:Landroid/content/Context;

    .line 17
    .line 18
    iget-object v0, p0, Lcom/google/firebase/messaging/i;->e:Landroid/content/Intent;

    .line 19
    .line 20
    iget-boolean p0, p0, Lcom/google/firebase/messaging/i;->f:Z

    .line 21
    .line 22
    invoke-static {p1, v0, p0}, Lcom/google/firebase/messaging/j;->a(Landroid/content/Context;Landroid/content/Intent;Z)Laq/t;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    new-instance p1, Lha/c;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, v0}, Lha/c;-><init>(I)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Lc1/y;

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1, v0}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
