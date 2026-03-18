.class public final Lcom/google/firebase/messaging/h0;
.super Landroid/os/Binder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Lbu/c;


# direct methods
.method public constructor <init>(Lbu/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/firebase/messaging/h0;->c:Lbu/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/firebase/messaging/i0;)V
    .locals 3

    .line 1
    invoke-static {}, Landroid/os/Binder;->getCallingUid()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {}, Landroid/os/Process;->myUid()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-ne v0, v1, :cond_1

    .line 10
    .line 11
    const/4 v0, 0x3

    .line 12
    const-string v1, "FirebaseMessaging"

    .line 13
    .line 14
    invoke-static {v1, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const-string v0, "service received new intent via bind strategy"

    .line 21
    .line 22
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object v0, p1, Lcom/google/firebase/messaging/i0;->a:Landroid/content/Intent;

    .line 26
    .line 27
    iget-object p0, p0, Lcom/google/firebase/messaging/h0;->c:Lbu/c;

    .line 28
    .line 29
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lcom/google/firebase/messaging/g;

    .line 32
    .line 33
    invoke-static {p0, v0}, Lcom/google/firebase/messaging/g;->access$000(Lcom/google/firebase/messaging/g;Landroid/content/Intent;)Laq/j;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance v0, Lha/c;

    .line 38
    .line 39
    const/4 v1, 0x0

    .line 40
    invoke-direct {v0, v1}, Lha/c;-><init>(I)V

    .line 41
    .line 42
    .line 43
    new-instance v1, La8/t;

    .line 44
    .line 45
    const/16 v2, 0xe

    .line 46
    .line 47
    invoke-direct {v1, p1, v2}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0, v0, v1}, Laq/j;->b(Ljava/util/concurrent/Executor;Laq/e;)Laq/t;

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_1
    new-instance p0, Ljava/lang/SecurityException;

    .line 55
    .line 56
    const-string p1, "Binding only allowed within app"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0
.end method
