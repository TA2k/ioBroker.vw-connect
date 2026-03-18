.class public final synthetic Lcom/google/firebase/messaging/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/g;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/firebase/messaging/FirebaseMessaging;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/messaging/FirebaseMessaging;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/firebase/messaging/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/firebase/messaging/o;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/o;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/firebase/messaging/o;->e:Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p1, Lio/a;

    .line 9
    .line 10
    sget-object v0, Lcom/google/firebase/messaging/FirebaseMessaging;->k:La0/j;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    iget-object p1, p1, Lio/a;->d:Landroid/content/Intent;

    .line 18
    .line 19
    invoke-static {p1}, Ljp/je;->b(Landroid/content/Intent;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessaging;->h()V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void

    .line 26
    :pswitch_0
    check-cast p1, Lcom/google/firebase/messaging/d0;

    .line 27
    .line 28
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->e:La8/b;

    .line 29
    .line 30
    invoke-virtual {p0}, La8/b;->k()Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    iget-object p0, p1, Lcom/google/firebase/messaging/d0;->h:Lcom/google/firebase/messaging/b0;

    .line 37
    .line 38
    invoke-virtual {p0}, Lcom/google/firebase/messaging/b0;->a()Lcom/google/firebase/messaging/a0;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    monitor-enter p1

    .line 45
    :try_start_0
    iget-boolean p0, p1, Lcom/google/firebase/messaging/d0;->g:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 46
    .line 47
    monitor-exit p1

    .line 48
    if-nez p0, :cond_1

    .line 49
    .line 50
    const-wide/16 v0, 0x0

    .line 51
    .line 52
    invoke-virtual {p1, v0, v1}, Lcom/google/firebase/messaging/d0;->f(J)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 58
    throw p0

    .line 59
    :cond_1
    :goto_0
    return-void

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
