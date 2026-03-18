.class public final synthetic Lcom/google/firebase/messaging/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgs/e;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lgs/s;


# direct methods
.method public synthetic constructor <init>(Lgs/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/firebase/messaging/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/firebase/messaging/p;->e:Lgs/s;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final e(Lin/z1;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lcom/google/firebase/messaging/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/firebase/messaging/p;->e:Lgs/s;

    .line 7
    .line 8
    invoke-static {p0, p1}, Lcom/google/firebase/perf/FirebasePerfRegistrar;->b(Lgs/s;Lin/z1;)Lot/a;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    new-instance v0, Let/c;

    .line 14
    .line 15
    const-class v1, Landroid/content/Context;

    .line 16
    .line 17
    invoke-virtual {p1, v1}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Landroid/content/Context;

    .line 22
    .line 23
    const-class v2, Lsr/f;

    .line 24
    .line 25
    invoke-virtual {p1, v2}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    check-cast v2, Lsr/f;

    .line 30
    .line 31
    invoke-virtual {v2}, Lsr/f;->d()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    const-class v3, Let/d;

    .line 36
    .line 37
    invoke-static {v3}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-virtual {p1, v3}, Lin/z1;->c(Lgs/s;)Ljava/util/Set;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    const-class v4, Lbu/b;

    .line 46
    .line 47
    invoke-virtual {p1, v4}, Lin/z1;->f(Ljava/lang/Class;)Lgt/b;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    iget-object p0, p0, Lcom/google/firebase/messaging/p;->e:Lgs/s;

    .line 52
    .line 53
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    move-object v5, p0

    .line 58
    check-cast v5, Ljava/util/concurrent/Executor;

    .line 59
    .line 60
    invoke-direct/range {v0 .. v5}, Let/c;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/util/Set;Lgt/b;Ljava/util/concurrent/Executor;)V

    .line 61
    .line 62
    .line 63
    return-object v0

    .line 64
    :pswitch_1
    iget-object p0, p0, Lcom/google/firebase/messaging/p;->e:Lgs/s;

    .line 65
    .line 66
    invoke-static {p0, p1}, Lcom/google/firebase/remoteconfig/RemoteConfigRegistrar;->a(Lgs/s;Lin/z1;)Lcu/j;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_2
    iget-object p0, p0, Lcom/google/firebase/messaging/p;->e:Lgs/s;

    .line 72
    .line 73
    invoke-static {p0, p1}, Lcom/google/firebase/messaging/FirebaseMessagingRegistrar;->a(Lgs/s;Lin/z1;)Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
