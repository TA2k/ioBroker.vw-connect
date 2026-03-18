.class public final Lgw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfw0/t;
.implements Lk0/c;
.implements Llo/n;
.implements Laq/e;
.implements Lh1/l;
.implements Lh0/m1;
.implements Lu01/g0;
.implements Lju/b;


# static fields
.field public static h:Lgw0/c;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 4

    iput p1, p0, Lgw0/c;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Lcom/google/android/gms/internal/measurement/b;

    const-string v0, ""

    const-wide/16 v1, 0x0

    const/4 v3, 0x0

    invoke-direct {p1, v0, v1, v2, v3}, Lcom/google/android/gms/internal/measurement/b;-><init>(Ljava/lang/String;JLjava/util/HashMap;)V

    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    new-instance p1, Lcom/google/android/gms/internal/measurement/b;

    .line 4
    invoke-direct {p1, v0, v1, v2, v3}, Lcom/google/android/gms/internal/measurement/b;-><init>(Ljava/lang/String;JLjava/util/HashMap;)V

    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    new-instance p1, Ljava/util/ArrayList;

    .line 5
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void

    .line 6
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    new-instance p1, Landroidx/lifecycle/i0;

    .line 8
    invoke-direct {p1}, Landroidx/lifecycle/g0;-><init>()V

    .line 9
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 10
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    return-void

    .line 11
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    new-instance p1, Landroidx/collection/w;

    const/16 v0, 0x8

    invoke-direct {p1, v0}, Landroidx/collection/w;-><init>(I)V

    .line 13
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    return-void

    .line 14
    :sswitch_2
    sget-object p1, Lf8/k;->d:Lf8/k;

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 17
    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    return-void

    .line 18
    :sswitch_3
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object p1

    const-string v0, "toString(...)"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    sget-object v0, Lu01/i;->g:Lu01/i;

    invoke-static {p1}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    move-result-object p1

    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 21
    sget-object p1, Ld01/f0;->e:Ld01/d0;

    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 22
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0xc -> :sswitch_3
        0xe -> :sswitch_2
        0x12 -> :sswitch_1
        0x15 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(II)V
    .locals 8

    const/16 v0, 0x1a

    iput v0, p0, Lgw0/c;->d:I

    .line 34
    sget-object v5, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 35
    new-instance v6, Ljava/util/concurrent/LinkedBlockingQueue;

    invoke-direct {v6}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 36
    const-string v0, "keepAliveTimeUnit"

    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 39
    new-instance v1, Lh91/b;

    const-string v7, "FWWorker"

    move-object v2, p0

    move v3, p1

    move v4, p2

    invoke-direct/range {v1 .. v7}, Lh91/b;-><init>(Lgw0/c;IILjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/lang/String;)V

    iput-object v1, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 40
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p0, v2, Lgw0/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lgw0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/location/LocationManager;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Lgw0/c;->d:I

    .line 71
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 72
    new-instance v0, Lh/f0;

    .line 73
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 74
    iput-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 75
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 76
    iput-object p2, p0, Lgw0/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/media/AudioTrack;Lc8/f;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lgw0/c;->d:I

    .line 117
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 118
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 119
    iput-object p2, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 120
    new-instance p2, Lc8/v;

    invoke-direct {p2, p0}, Lc8/v;-><init>(Lgw0/c;)V

    iput-object p2, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 121
    new-instance p2, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-direct {p2, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 122
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    check-cast p0, Lc8/v;

    invoke-virtual {p1, p0, p2}, Landroid/media/AudioTrack;->addOnRoutingChangedListener(Landroid/media/AudioRouting$OnRoutingChangedListener;Landroid/os/Handler;)V

    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/a0;)V
    .locals 2

    const/4 v0, 0x2

    iput v0, p0, Lgw0/c;->d:I

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    new-instance v0, Landroidx/lifecycle/z;

    const/4 v1, 0x1

    .line 27
    invoke-direct {v0, p1, v1}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 28
    iput-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 29
    new-instance p1, Landroid/os/Handler;

    invoke-direct {p1}, Landroid/os/Handler;-><init>()V

    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/lifecycle/c1;)V
    .locals 1

    const/16 v0, 0x1c

    iput v0, p0, Lgw0/c;->d:I

    .line 41
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 42
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 43
    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 44
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 45
    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lc8/y;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Lgw0/c;->d:I

    .line 123
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 124
    new-instance p1, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-direct {p1, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 125
    new-instance p1, Lc8/x;

    invoke-direct {p1, p0}, Lc8/x;-><init>(Lgw0/c;)V

    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/b;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Lgw0/c;->d:I

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/b;->a()Lcom/google/android/gms/internal/measurement/b;

    move-result-object p1

    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    new-instance p1, Ljava/util/ArrayList;

    .line 24
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/FirebaseMessagingService;Laq/a;Ljava/util/concurrent/ExecutorService;)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, Lgw0/c;->d:I

    .line 46
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 47
    iput-object p3, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 48
    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 49
    iput-object p2, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lg3/b;)V
    .locals 1

    const/16 v0, 0x11

    iput v0, p0, Lgw0/c;->d:I

    .line 67
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 68
    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 69
    new-instance p1, Lbu/c;

    const/16 v0, 0x17

    invoke-direct {p1, p0, v0}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 70
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh01/g;)V
    .locals 13

    const/16 v0, 0x17

    iput v0, p0, Lgw0/c;->d:I

    .line 89
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 90
    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 91
    new-instance v1, Lh01/e;

    .line 92
    iget-object v0, p1, Lh01/g;->c:Li01/d;

    .line 93
    invoke-interface {v0}, Li01/d;->h()Lu01/g0;

    move-result-object v2

    invoke-interface {v2}, Lu01/g0;->a()Lu01/f0;

    move-result-object v3

    const-wide/16 v4, -0x1

    const/4 v6, 0x1

    move-object v2, p1

    .line 94
    invoke-direct/range {v1 .. v6}, Lh01/e;-><init>(Lh01/g;Lu01/f0;JZ)V

    iput-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 95
    new-instance v7, Lh01/f;

    .line 96
    invoke-interface {v0}, Li01/d;->h()Lu01/g0;

    move-result-object p1

    invoke-interface {p1}, Lu01/g0;->getSource()Lu01/h0;

    move-result-object v9

    const-wide/16 v10, -0x1

    const/4 v12, 0x1

    move-object v8, v2

    .line 97
    invoke-direct/range {v7 .. v12}, Lh01/f;-><init>(Lh01/g;Lu01/h0;JZ)V

    iput-object v7, p0, Lgw0/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh5/e;)V
    .locals 1

    const/16 v0, 0x1d

    iput v0, p0, Lgw0/c;->d:I

    .line 77
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 78
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 79
    new-instance v0, Li5/b;

    .line 80
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 81
    iput-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 82
    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Lgw0/c;->d:I

    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    iput-object p2, p0, Lgw0/c;->f:Ljava/lang/Object;

    iput-object p3, p0, Lgw0/c;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 3

    const/16 v0, 0x13

    iput v0, p0, Lgw0/c;->d:I

    .line 83
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 84
    new-instance v0, Lvp/y1;

    const/4 v1, 0x7

    const/4 v2, 0x0

    .line 85
    invoke-direct {v0, v1, v2}, Lvp/y1;-><init>(IZ)V

    .line 86
    iput-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 87
    iput-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 88
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lay0/a;Lay0/k;)V
    .locals 5

    const/4 v0, 0x0

    iput v0, p0, Lgw0/c;->d:I

    const-string v1, "createConfiguration"

    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 53
    iput-object p2, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 54
    iput-object p3, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 55
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    const-class p3, Lgw0/d;

    invoke-virtual {p2, p3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v1

    .line 56
    :try_start_0
    sget-object v2, Lhy0/d0;->c:Lhy0/d0;

    const-class v2, Lgw0/c;

    .line 57
    invoke-virtual {p2, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v2

    .line 58
    const-string v3, "PluginConfigT"

    sget-object v4, Lhy0/e0;->d:Lhy0/e0;

    .line 59
    invoke-virtual {p2, v2, v3, v4, v0}, Lkotlin/jvm/internal/h0;->typeParameter(Ljava/lang/Object;Ljava/lang/String;Lhy0/e0;Z)Lhy0/b0;

    move-result-object v2

    .line 60
    const-class v3, Ljava/lang/Object;

    invoke-static {v3}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    move-result-object v3

    .line 61
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {p2, v2, v3}, Lkotlin/jvm/internal/h0;->setUpperBounds(Lhy0/b0;Ljava/util/List;)V

    .line 62
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-virtual {p2, v2, v3, v0}, Lkotlin/jvm/internal/h0;->typeOf(Lhy0/e;Ljava/util/List;Z)Lhy0/a0;

    move-result-object p2

    .line 63
    invoke-static {p2}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    move-result-object p2

    invoke-static {p3, p2}, Lkotlin/jvm/internal/g0;->c(Ljava/lang/Class;Lhy0/d0;)Lhy0/a0;

    move-result-object p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    const/4 p2, 0x0

    .line 64
    :goto_0
    new-instance p3, Lzw0/a;

    invoke-direct {p3, v1, p2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 65
    new-instance p2, Lvw0/a;

    invoke-direct {p2, p1, p3}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 66
    iput-object p2, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lo8/r;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lgw0/c;->d:I

    .line 50
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lu01/g0;)V
    .locals 1

    const/16 v0, 0x16

    iput v0, p0, Lgw0/c;->d:I

    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    iput-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 32
    invoke-interface {p1}, Lu01/g0;->getSource()Lu01/h0;

    move-result-object v0

    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    move-result-object v0

    iput-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 33
    invoke-interface {p1}, Lu01/g0;->a()Lu01/f0;

    move-result-object p1

    invoke-static {p1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    move-result-object p1

    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>([Lu7/f;)V
    .locals 5

    const/4 v0, 0x5

    iput v0, p0, Lgw0/c;->d:I

    .line 98
    new-instance v0, Lc8/c0;

    invoke-direct {v0}, Lc8/c0;-><init>()V

    new-instance v1, Lu7/i;

    .line 99
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    const/high16 v2, 0x3f800000    # 1.0f

    .line 100
    iput v2, v1, Lu7/i;->c:F

    .line 101
    iput v2, v1, Lu7/i;->d:F

    .line 102
    sget-object v2, Lu7/d;->e:Lu7/d;

    iput-object v2, v1, Lu7/i;->e:Lu7/d;

    .line 103
    iput-object v2, v1, Lu7/i;->f:Lu7/d;

    .line 104
    iput-object v2, v1, Lu7/i;->g:Lu7/d;

    .line 105
    iput-object v2, v1, Lu7/i;->h:Lu7/d;

    .line 106
    sget-object v2, Lu7/f;->a:Ljava/nio/ByteBuffer;

    iput-object v2, v1, Lu7/i;->k:Ljava/nio/ByteBuffer;

    .line 107
    invoke-virtual {v2}, Ljava/nio/ByteBuffer;->asShortBuffer()Ljava/nio/ShortBuffer;

    move-result-object v3

    iput-object v3, v1, Lu7/i;->l:Ljava/nio/ShortBuffer;

    .line 108
    iput-object v2, v1, Lu7/i;->m:Ljava/nio/ByteBuffer;

    const/4 v2, -0x1

    .line 109
    iput v2, v1, Lu7/i;->b:I

    .line 110
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 111
    array-length v2, p1

    add-int/lit8 v2, v2, 0x2

    new-array v2, v2, [Lu7/f;

    iput-object v2, p0, Lgw0/c;->e:Ljava/lang/Object;

    const/4 v3, 0x0

    .line 112
    array-length v4, p1

    invoke-static {p1, v3, v2, v3, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 113
    iput-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 114
    iput-object v1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 115
    array-length p0, p1

    aput-object v0, v2, p0

    .line 116
    array-length p0, p1

    add-int/lit8 p0, p0, 0x1

    aput-object v1, v2, p0

    return-void
.end method


# virtual methods
.method public A(Lt4/m;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iput-object p1, p0, Lg3/a;->b:Lt4/m;

    .line 8
    .line 9
    return-void
.end method

.method public B(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iput-wide p1, p0, Lg3/a;->d:J

    .line 8
    .line 9
    return-void
.end method

.method public C(Lh5/e;III)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget v0, p1, Lh5/d;->c0:I

    .line 5
    .line 6
    iget v1, p1, Lh5/d;->d0:I

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    iput v2, p1, Lh5/d;->c0:I

    .line 10
    .line 11
    iput v2, p1, Lh5/d;->d0:I

    .line 12
    .line 13
    invoke-virtual {p1, p3}, Lh5/d;->S(I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p4}, Lh5/d;->N(I)V

    .line 17
    .line 18
    .line 19
    if-gez v0, :cond_0

    .line 20
    .line 21
    iput v2, p1, Lh5/d;->c0:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iput v0, p1, Lh5/d;->c0:I

    .line 25
    .line 26
    :goto_0
    if-gez v1, :cond_1

    .line 27
    .line 28
    iput v2, p1, Lh5/d;->d0:I

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    iput v1, p1, Lh5/d;->d0:I

    .line 32
    .line 33
    :goto_1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lh5/e;

    .line 36
    .line 37
    iput p2, p0, Lh5/e;->u0:I

    .line 38
    .line 39
    invoke-virtual {p0}, Lh5/e;->Z()V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public D(Lh5/e;)V
    .locals 8

    .line 1
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 6
    .line 7
    .line 8
    iget-object v0, p1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v1, 0x0

    .line 15
    move v2, v1

    .line 16
    :goto_0
    const/4 v3, 0x1

    .line 17
    if-ge v2, v0, :cond_2

    .line 18
    .line 19
    iget-object v4, p1, Lh5/e;->r0:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    check-cast v4, Lh5/d;

    .line 26
    .line 27
    iget-object v5, v4, Lh5/d;->q0:[I

    .line 28
    .line 29
    aget v6, v5, v1

    .line 30
    .line 31
    const/4 v7, 0x3

    .line 32
    if-eq v6, v7, :cond_0

    .line 33
    .line 34
    aget v3, v5, v3

    .line 35
    .line 36
    if-ne v3, v7, :cond_1

    .line 37
    .line 38
    :cond_0
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    iget-object p0, p1, Lh5/e;->t0:Li5/f;

    .line 45
    .line 46
    iput-boolean v3, p0, Li5/f;->b:Z

    .line 47
    .line 48
    return-void
.end method

.method public a()Lu01/f0;
    .locals 1

    .line 1
    iget v0, p0, Lgw0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh01/e;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lu01/a0;

    .line 14
    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x16
        :pswitch_0
    .end packed-switch
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 9

    .line 1
    check-cast p1, Lcq/t1;

    .line 2
    .line 3
    check-cast p2, Laq/k;

    .line 4
    .line 5
    new-instance v0, Laq/s;

    .line 6
    .line 7
    invoke-direct {v0, p2}, Laq/s;-><init>(Laq/k;)V

    .line 8
    .line 9
    .line 10
    iget-object p2, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p2, Leu0/b;

    .line 13
    .line 14
    iget-object v1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lis/b;

    .line 17
    .line 18
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, [Landroid/content/IntentFilter;

    .line 21
    .line 22
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    new-instance v2, Lcq/u1;

    .line 26
    .line 27
    invoke-direct {v2, p0}, Lcq/u1;-><init>([Landroid/content/IntentFilter;)V

    .line 28
    .line 29
    .line 30
    iput-object v1, v2, Lcq/u1;->d:Lis/b;

    .line 31
    .line 32
    iget-object p0, p1, Lcq/t1;->E:Lev/c;

    .line 33
    .line 34
    const-string v1, "addListener failed, removing listener: "

    .line 35
    .line 36
    const-string v3, "new listener: "

    .line 37
    .line 38
    const-string v4, "duplicate listener: "

    .line 39
    .line 40
    iget-object v5, p0, Lev/c;->a:Ljava/util/HashMap;

    .line 41
    .line 42
    monitor-enter v5

    .line 43
    :try_start_0
    iget-object v6, p0, Lev/c;->a:Ljava/util/HashMap;

    .line 44
    .line 45
    invoke-virtual {v6, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    const/4 v7, 0x2

    .line 50
    if-eqz v6, :cond_1

    .line 51
    .line 52
    const-string p0, "WearableClient"

    .line 53
    .line 54
    invoke-static {p0, v7}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-eqz p0, :cond_0

    .line 59
    .line 60
    const-string p0, "WearableClient"

    .line 61
    .line 62
    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-virtual {v4, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-static {p0, p1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :catchall_0
    move-exception p0

    .line 75
    goto/16 :goto_2

    .line 76
    .line 77
    :cond_0
    :goto_0
    new-instance p0, Lcom/google/android/gms/common/api/Status;

    .line 78
    .line 79
    const/16 p1, 0xfa1

    .line 80
    .line 81
    const/4 p2, 0x0

    .line 82
    invoke-direct {p0, p1, p2, p2, p2}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, p0}, Laq/s;->z(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    monitor-exit v5

    .line 89
    return-void

    .line 90
    :cond_1
    const-string v4, "WearableClient"

    .line 91
    .line 92
    invoke-static {v4, v7}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 93
    .line 94
    .line 95
    move-result v4

    .line 96
    if-eqz v4, :cond_2

    .line 97
    .line 98
    const-string v4, "WearableClient"

    .line 99
    .line 100
    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v6

    .line 104
    invoke-virtual {v3, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-static {v4, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    :cond_2
    iget-object v3, p0, Lev/c;->a:Ljava/util/HashMap;

    .line 112
    .line 113
    invoke-virtual {v3, p2, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 114
    .line 115
    .line 116
    const/4 v3, 0x3

    .line 117
    :try_start_1
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    check-cast p1, Lcq/w0;

    .line 122
    .line 123
    new-instance v4, Lcq/y0;

    .line 124
    .line 125
    iget-object v6, p0, Lev/c;->a:Ljava/util/HashMap;

    .line 126
    .line 127
    invoke-direct {v4, v6, p2, v0}, Lcq/y0;-><init>(Ljava/util/HashMap;Ljava/lang/Object;Laq/s;)V

    .line 128
    .line 129
    .line 130
    iget-object v0, v2, Lcq/u1;->e:[Landroid/content/IntentFilter;

    .line 131
    .line 132
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 133
    .line 134
    .line 135
    move-result-object v6

    .line 136
    iget-object v8, p1, Lbp/a;->e:Ljava/lang/String;

    .line 137
    .line 138
    invoke-virtual {v6, v8}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    sget v8, Lop/e;->a:I

    .line 142
    .line 143
    invoke-virtual {v6, v4}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 144
    .line 145
    .line 146
    const/4 v4, 0x1

    .line 147
    invoke-virtual {v6, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 148
    .line 149
    .line 150
    const/16 v4, 0x4f45

    .line 151
    .line 152
    invoke-static {v6, v4}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    invoke-interface {v2}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    invoke-static {v6, v7, v2}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 161
    .line 162
    .line 163
    const/4 v2, 0x0

    .line 164
    invoke-static {v6, v3, v0, v2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 165
    .line 166
    .line 167
    invoke-static {v6, v4}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 168
    .line 169
    .line 170
    const/16 v0, 0x10

    .line 171
    .line 172
    invoke-virtual {p1, v6, v0}, Lbp/a;->R(Landroid/os/Parcel;I)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 173
    .line 174
    .line 175
    :try_start_2
    monitor-exit v5

    .line 176
    return-void

    .line 177
    :catch_0
    move-exception p1

    .line 178
    const-string v0, "WearableClient"

    .line 179
    .line 180
    invoke-static {v0, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-nez v0, :cond_3

    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_3
    const-string v0, "WearableClient"

    .line 188
    .line 189
    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 198
    .line 199
    .line 200
    :goto_1
    iget-object p0, p0, Lev/c;->a:Ljava/util/HashMap;

    .line 201
    .line 202
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    throw p1

    .line 206
    :goto_2
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 207
    throw p0
.end method

.method public b(Lay0/k;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lay0/a;

    .line 4
    .line 5
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    new-instance p1, Lgw0/d;

    .line 13
    .line 14
    iget-object v1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lvw0/a;

    .line 17
    .line 18
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lay0/k;

    .line 21
    .line 22
    invoke-direct {p1, v1, v0, p0}, Lgw0/d;-><init>(Lvw0/a;Ljava/lang/Object;Lay0/k;)V

    .line 23
    .line 24
    .line 25
    return-object p1
.end method

.method public c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Landroid/view/Surface;

    .line 2
    .line 3
    iget-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 6
    .line 7
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ly4/h;

    .line 10
    .line 11
    invoke-static {p1, p0}, Lk0/h;->e(Lcom/google/common/util/concurrent/ListenableFuture;Ly4/h;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public cancel()V
    .locals 1

    .line 1
    iget v0, p0, Lgw0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh01/g;

    .line 9
    .line 10
    iget-object p0, p0, Lh01/g;->c:Li01/d;

    .line 11
    .line 12
    invoke-interface {p0}, Li01/d;->cancel()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lu01/g0;

    .line 19
    .line 20
    invoke-interface {p0}, Lu01/g0;->cancel()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x16
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic clone()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lgw0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Lgw0/c;

    .line 12
    .line 13
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Lcom/google/android/gms/internal/measurement/b;

    .line 16
    .line 17
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/b;->a()Lcom/google/android/gms/internal/measurement/b;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-direct {v0, v1}, Lgw0/c;-><init>(Lcom/google/android/gms/internal/measurement/b;)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Lcom/google/android/gms/internal/measurement/b;

    .line 43
    .line 44
    iget-object v2, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v2, Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/b;->a()Lcom/google/android/gms/internal/measurement/b;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    return-object v0

    .line 57
    :pswitch_data_0
    .packed-switch 0x8
        :pswitch_0
    .end packed-switch
.end method

.method public d(Ljava/lang/Object;Lzv0/c;)V
    .locals 2

    .line 1
    check-cast p1, Lgw0/d;

    .line 2
    .line 3
    const-string p0, "plugin"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "scope"

    .line 9
    .line 10
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lgw0/b;

    .line 14
    .line 15
    iget-object v0, p1, Lgw0/d;->d:Lvw0/a;

    .line 16
    .line 17
    iget-object v1, p1, Lgw0/d;->e:Ljava/lang/Object;

    .line 18
    .line 19
    invoke-direct {p0, v0, p2, v1}, Lgw0/b;-><init>(Lvw0/a;Lzv0/c;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p1, Lgw0/d;->f:Lay0/k;

    .line 23
    .line 24
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Lgw0/b;->d:Lz81/g;

    .line 28
    .line 29
    iput-object v0, p1, Lgw0/d;->g:Lay0/a;

    .line 30
    .line 31
    iget-object p0, p0, Lgw0/b;->c:Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_0

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lgw0/e;

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    iget-object v0, p1, Lgw0/e;->a:Lgw0/a;

    .line 53
    .line 54
    iget-object p1, p1, Lgw0/e;->b:Lrx0/i;

    .line 55
    .line 56
    invoke-interface {v0, p2, p1}, Lgw0/a;->a(Lzv0/c;Lrx0/i;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    return-void
.end method

.method public e(Ljava/lang/Object;Ljava/io/ByteArrayOutputStream;)V
    .locals 3

    .line 1
    new-instance v0, Lct/f;

    .line 2
    .line 3
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ljava/util/HashMap;

    .line 6
    .line 7
    iget-object v2, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Ljava/util/HashMap;

    .line 10
    .line 11
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lzs/d;

    .line 14
    .line 15
    invoke-direct {v0, p2, v1, v2, p0}, Lct/f;-><init>(Ljava/io/ByteArrayOutputStream;Ljava/util/HashMap;Ljava/util/HashMap;Lzs/d;)V

    .line 16
    .line 17
    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {v1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Lzs/d;

    .line 30
    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    invoke-interface {p0, p1, v0}, Lzs/a;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_1
    new-instance p0, Lzs/b;

    .line 38
    .line 39
    new-instance p2, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v0, "No encoder for "

    .line 42
    .line 43
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0
.end method

.method public f(Lh0/l1;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    iget-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/util/HashMap;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    new-instance v1, Lh0/f1;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-direct {v1, p0, v2}, Lh0/f1;-><init>(Lgw0/c;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, v1}, Lj0/c;->execute(Ljava/lang/Runnable;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    monitor-exit v0

    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0
.end method

.method public g(F)F
    .locals 9

    .line 1
    iget-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lg1/q;

    .line 4
    .line 5
    invoke-virtual {v0}, Lg1/q;->k()F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    iget-object v3, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, Lay0/k;

    .line 16
    .line 17
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Ld2/g;

    .line 20
    .line 21
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-nez v4, :cond_a

    .line 26
    .line 27
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    const/4 v5, 0x0

    .line 32
    cmpl-float v4, v4, v5

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    const/4 v7, 0x1

    .line 36
    if-lez v4, :cond_0

    .line 37
    .line 38
    move v4, v7

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    move v4, v6

    .line 41
    :goto_0
    if-eqz v4, :cond_1

    .line 42
    .line 43
    cmpl-float v5, p1, v5

    .line 44
    .line 45
    if-lez v5, :cond_1

    .line 46
    .line 47
    move v5, v7

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v5, v6

    .line 50
    :goto_1
    if-nez v4, :cond_2

    .line 51
    .line 52
    invoke-virtual {v2, v1}, Lg1/z;->a(F)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_4

    .line 60
    :cond_2
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    check-cast p0, Ljava/lang/Number;

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    cmpl-float p0, p1, p0

    .line 79
    .line 80
    if-ltz p0, :cond_3

    .line 81
    .line 82
    invoke-virtual {v2, v1, v5}, Lg1/z;->b(FZ)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_3
    invoke-virtual {v2, v1, v6}, Lg1/z;->b(FZ)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2, p0}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    invoke-virtual {v2, v1, v7}, Lg1/z;->b(FZ)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v2, v4}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    sub-float v8, p1, v2

    .line 113
    .line 114
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 115
    .line 116
    .line 117
    move-result v8

    .line 118
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 119
    .line 120
    .line 121
    move-result-object v8

    .line 122
    invoke-interface {v3, v8}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    check-cast v3, Ljava/lang/Number;

    .line 127
    .line 128
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    if-eqz v5, :cond_4

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_4
    move p1, v2

    .line 140
    :goto_2
    sub-float/2addr p1, v1

    .line 141
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    cmpl-float p1, p1, v3

    .line 146
    .line 147
    if-ltz p1, :cond_5

    .line 148
    .line 149
    move v6, v7

    .line 150
    :cond_5
    if-ne v6, v7, :cond_6

    .line 151
    .line 152
    if-eqz v5, :cond_8

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_6
    if-nez v6, :cond_9

    .line 156
    .line 157
    if-eqz v5, :cond_7

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_7
    :goto_3
    move-object p0, v4

    .line 161
    :cond_8
    :goto_4
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    invoke-virtual {p1, p0}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 166
    .line 167
    .line 168
    move-result p0

    .line 169
    sub-float/2addr p0, v1

    .line 170
    return p0

    .line 171
    :cond_9
    new-instance p0, La8/r0;

    .line 172
    .line 173
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 174
    .line 175
    .line 176
    throw p0

    .line 177
    :cond_a
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 178
    .line 179
    const-string p1, "The offset provided to computeTarget must not be NaN."

    .line 180
    .line 181
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0
.end method

.method public get()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lj1/a;

    .line 4
    .line 5
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroid/content/Context;

    .line 8
    .line 9
    iget-object v1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lkx0/a;

    .line 12
    .line 13
    invoke-interface {v1}, Lkx0/a;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lpx0/g;

    .line 18
    .line 19
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lju/c;

    .line 22
    .line 23
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lhu/f0;

    .line 28
    .line 29
    const-string v2, "appContext"

    .line 30
    .line 31
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string v2, "blockingDispatcher"

    .line 35
    .line 36
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v2, "sessionDataSerializer"

    .line 40
    .line 41
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v2, Lb3/g;

    .line 45
    .line 46
    new-instance v3, Le81/w;

    .line 47
    .line 48
    const/16 v4, 0x18

    .line 49
    .line 50
    invoke-direct {v3, p0, v4}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    invoke-direct {v2, v3}, Lb3/g;-><init>(Lay0/k;)V

    .line 54
    .line 55
    .line 56
    invoke-static {v1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    new-instance v3, Laa/x;

    .line 61
    .line 62
    const/4 v4, 0x2

    .line 63
    invoke-direct {v3, v0, v4}, Laa/x;-><init>(Landroid/content/Context;I)V

    .line 64
    .line 65
    .line 66
    invoke-static {p0, v2, v1, v3}, Lhu/o;->b(Lm6/u0;Lb3/g;Lpw0/a;Lay0/a;)Lm6/w;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method

.method public getKey()Lvw0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvw0/a;

    .line 4
    .line 5
    return-object p0
.end method

.method public getSource()Lu01/h0;
    .locals 1

    .line 1
    iget v0, p0, Lgw0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh01/f;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lu01/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x16
        :pswitch_0
    .end packed-switch
.end method

.method public h()Le3/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iget-object p0, p0, Lg3/a;->c:Le3/r;

    .line 8
    .line 9
    return-object p0
.end method

.method public i()J
    .locals 2

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/l;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    iget-wide v0, p0, Lo8/l;->g:J

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    const-wide/16 v0, -0x1

    .line 11
    .line 12
    return-wide v0
.end method

.method public j(FF)F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public k()Lt4/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iget-object p0, p0, Lg3/a;->a:Lt4/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public l()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iget-object p0, p0, Lg3/a;->b:Lt4/m;

    .line 8
    .line 9
    return-object p0
.end method

.method public m(Ljava/util/concurrent/Executor;Lh0/l1;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-object v1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Ljava/util/HashMap;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    iget-object v2, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-virtual {v2, p2, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    new-instance p2, Lh0/f1;

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-direct {p2, p0, v1}, Lh0/f1;-><init>(Lgw0/c;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, p2}, Lj0/c;->execute(Ljava/lang/Runnable;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    new-instance v1, Lh0/h0;

    .line 38
    .line 39
    check-cast p2, Lw0/c;

    .line 40
    .line 41
    const/4 v2, 0x2

    .line 42
    invoke-direct {v1, v2, p0, p2}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    invoke-interface {p1, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 46
    .line 47
    .line 48
    :goto_0
    monitor-exit v0

    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    throw p0
.end method

.method public n(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lc51/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lc51/b;

    .line 7
    .line 8
    iget v1, v0, Lc51/b;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lc51/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lc51/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lc51/b;-><init>(Lgw0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lc51/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lc51/b;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p2, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Le51/e;

    .line 58
    .line 59
    iput v3, v0, Lc51/b;->f:I

    .line 60
    .line 61
    invoke-virtual {p0, p1, v0}, Le51/e;->a(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    if-ne p0, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    return-object p0
.end method

.method public o()J
    .locals 2

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iget-wide v0, p0, Lg3/a;->d:J

    .line 8
    .line 9
    return-wide v0
.end method

.method public onComplete(Laq/j;)V
    .locals 10

    .line 1
    const-string v0, "task"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Leu0/d;

    .line 9
    .line 10
    iget-object v1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lau0/h;

    .line 13
    .line 14
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eqz v2, :cond_4

    .line 20
    .line 21
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const-string v4, "getResult(...)"

    .line 26
    .line 27
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    check-cast v2, Ljava/lang/Iterable;

    .line 31
    .line 32
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_1

    .line 41
    .line 42
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    move-object v5, v4

    .line 47
    check-cast v5, Lbq/b;

    .line 48
    .line 49
    invoke-interface {v5}, Lbq/b;->getUri()Landroid/net/Uri;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-virtual {v5}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    iget-object v6, v1, Lau0/j;->a:Ljava/lang/String;

    .line 58
    .line 59
    new-instance v7, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    const-string v8, "/wearable-data/"

    .line 62
    .line 63
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    if-eqz v5, :cond_0

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_1
    move-object v4, v3

    .line 81
    :goto_0
    check-cast v4, Lbq/b;

    .line 82
    .line 83
    if-eqz v4, :cond_2

    .line 84
    .line 85
    new-instance p1, Lne0/e;

    .line 86
    .line 87
    invoke-interface {v4}, Lbq/b;->getData()[B

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-direct {p1, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_2
    new-instance v2, Ljava/lang/Exception;

    .line 96
    .line 97
    new-instance v4, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v5, "Failed to get "

    .line 100
    .line 101
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    const-string v1, "."

    .line 108
    .line 109
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-direct {v2, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    new-instance v4, Lne0/c;

    .line 120
    .line 121
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    if-nez p1, :cond_3

    .line 126
    .line 127
    move-object v5, v2

    .line 128
    goto :goto_1

    .line 129
    :cond_3
    move-object v5, p1

    .line 130
    :goto_1
    const/4 v8, 0x0

    .line 131
    const/16 v9, 0x1e

    .line 132
    .line 133
    const/4 v6, 0x0

    .line 134
    const/4 v7, 0x0

    .line 135
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 136
    .line 137
    .line 138
    :goto_2
    move-object p1, v4

    .line 139
    goto :goto_4

    .line 140
    :cond_4
    new-instance v2, Ljava/lang/Exception;

    .line 141
    .line 142
    new-instance v4, Ljava/lang/StringBuilder;

    .line 143
    .line 144
    const-string v5, "Get "

    .line 145
    .line 146
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string v1, " task was not successful."

    .line 153
    .line 154
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-direct {v2, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    new-instance v4, Lne0/c;

    .line 165
    .line 166
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    if-nez p1, :cond_5

    .line 171
    .line 172
    move-object v5, v2

    .line 173
    goto :goto_3

    .line 174
    :cond_5
    move-object v5, p1

    .line 175
    :goto_3
    const/4 v8, 0x0

    .line 176
    const/16 v9, 0x1e

    .line 177
    .line 178
    const/4 v6, 0x0

    .line 179
    const/4 v7, 0x0

    .line 180
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 181
    .line 182
    .line 183
    goto :goto_2

    .line 184
    :goto_4
    instance-of v1, p1, Lne0/c;

    .line 185
    .line 186
    if-eqz v1, :cond_6

    .line 187
    .line 188
    move-object v1, p1

    .line 189
    check-cast v1, Lne0/c;

    .line 190
    .line 191
    new-instance v2, Lam0/y;

    .line 192
    .line 193
    const/4 v4, 0x2

    .line 194
    invoke-direct {v2, v1, v4}, Lam0/y;-><init>(Lne0/c;I)V

    .line 195
    .line 196
    .line 197
    invoke-static {v3, v0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    invoke-static {v0}, Llp/nd;->d(Lkj0/f;)V

    .line 202
    .line 203
    .line 204
    :cond_6
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast p0, Lvy0/l;

    .line 207
    .line 208
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    return-void
.end method

.method public p()Z
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Laq/a;

    .line 6
    .line 7
    const-string v2, "gcm.n.noui"

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Laq/a;->l(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v2, 0x1

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    return v2

    .line 17
    :cond_0
    iget-object v0, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lcom/google/firebase/messaging/FirebaseMessagingService;

    .line 20
    .line 21
    const-string v3, "keyguard"

    .line 22
    .line 23
    invoke-virtual {v0, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Landroid/app/KeyguardManager;

    .line 28
    .line 29
    invoke-virtual {v3}, Landroid/app/KeyguardManager;->inKeyguardRestrictedInputMode()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    const/4 v4, 0x0

    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    invoke-static {}, Landroid/os/Process;->myPid()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    const-string v5, "activity"

    .line 42
    .line 43
    invoke-virtual {v0, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Landroid/app/ActivityManager;

    .line 48
    .line 49
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getRunningAppProcesses()Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    if-eqz v5, :cond_3

    .line 64
    .line 65
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    check-cast v5, Landroid/app/ActivityManager$RunningAppProcessInfo;

    .line 70
    .line 71
    iget v6, v5, Landroid/app/ActivityManager$RunningAppProcessInfo;->pid:I

    .line 72
    .line 73
    if-ne v6, v3, :cond_2

    .line 74
    .line 75
    iget v0, v5, Landroid/app/ActivityManager$RunningAppProcessInfo;->importance:I

    .line 76
    .line 77
    const/16 v3, 0x64

    .line 78
    .line 79
    if-ne v0, v3, :cond_3

    .line 80
    .line 81
    return v4

    .line 82
    :cond_3
    :goto_0
    iget-object v0, v1, Lgw0/c;->g:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Laq/a;

    .line 85
    .line 86
    const-string v3, "gcm.n.image"

    .line 87
    .line 88
    invoke-virtual {v0, v3}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    const-string v6, "FirebaseMessaging"

    .line 97
    .line 98
    if-eqz v3, :cond_4

    .line 99
    .line 100
    :goto_1
    const/4 v3, 0x0

    .line 101
    goto :goto_2

    .line 102
    :cond_4
    :try_start_0
    new-instance v3, Lcom/google/firebase/messaging/q;

    .line 103
    .line 104
    new-instance v7, Ljava/net/URL;

    .line 105
    .line 106
    invoke-direct {v7, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    invoke-direct {v3, v7}, Lcom/google/firebase/messaging/q;-><init>(Ljava/net/URL;)V
    :try_end_0
    .catch Ljava/net/MalformedURLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 110
    .line 111
    .line 112
    goto :goto_2

    .line 113
    :catch_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 114
    .line 115
    const-string v7, "Not downloading image, bad URL: "

    .line 116
    .line 117
    invoke-direct {v3, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :goto_2
    if-eqz v3, :cond_5

    .line 132
    .line 133
    iget-object v0, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v0, Ljava/util/concurrent/ExecutorService;

    .line 136
    .line 137
    new-instance v7, Laq/k;

    .line 138
    .line 139
    invoke-direct {v7}, Laq/k;-><init>()V

    .line 140
    .line 141
    .line 142
    new-instance v8, La8/z;

    .line 143
    .line 144
    const/16 v9, 0x12

    .line 145
    .line 146
    invoke-direct {v8, v9, v3, v7}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    invoke-interface {v0, v8}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    iput-object v0, v3, Lcom/google/firebase/messaging/q;->e:Ljava/util/concurrent/Future;

    .line 154
    .line 155
    iget-object v0, v7, Laq/k;->a:Laq/t;

    .line 156
    .line 157
    iput-object v0, v3, Lcom/google/firebase/messaging/q;->f:Laq/t;

    .line 158
    .line 159
    :cond_5
    iget-object v0, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 160
    .line 161
    move-object v7, v0

    .line 162
    check-cast v7, Lcom/google/firebase/messaging/FirebaseMessagingService;

    .line 163
    .line 164
    iget-object v0, v1, Lgw0/c;->g:Ljava/lang/Object;

    .line 165
    .line 166
    move-object v8, v0

    .line 167
    check-cast v8, Laq/a;

    .line 168
    .line 169
    sget-object v0, Lcom/google/firebase/messaging/e;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 170
    .line 171
    const-string v9, "Couldn\'t get own application info: "

    .line 172
    .line 173
    invoke-virtual {v7}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v10

    .line 181
    const/16 v11, 0x80

    .line 182
    .line 183
    :try_start_1
    invoke-virtual {v0, v10, v11}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    if-eqz v0, :cond_6

    .line 188
    .line 189
    iget-object v0, v0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_1

    .line 190
    .line 191
    if-eqz v0, :cond_6

    .line 192
    .line 193
    :goto_3
    move-object v10, v0

    .line 194
    goto :goto_4

    .line 195
    :catch_1
    move-exception v0

    .line 196
    new-instance v10, Ljava/lang/StringBuilder;

    .line 197
    .line 198
    invoke-direct {v10, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 209
    .line 210
    .line 211
    :cond_6
    sget-object v0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :goto_4
    const-string v0, "gcm.n.android_channel_id"

    .line 215
    .line 216
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    const/4 v11, 0x3

    .line 221
    :try_start_2
    invoke-virtual {v7}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 222
    .line 223
    .line 224
    move-result-object v12

    .line 225
    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v13

    .line 229
    invoke-virtual {v12, v13, v4}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 230
    .line 231
    .line 232
    move-result-object v12

    .line 233
    iget v12, v12, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_2

    .line 234
    .line 235
    const/16 v13, 0x1a

    .line 236
    .line 237
    if-ge v12, v13, :cond_7

    .line 238
    .line 239
    :catch_2
    const/4 v0, 0x0

    .line 240
    goto/16 :goto_7

    .line 241
    .line 242
    :cond_7
    const-class v12, Landroid/app/NotificationManager;

    .line 243
    .line 244
    invoke-virtual {v7, v12}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v12

    .line 248
    check-cast v12, Landroid/app/NotificationManager;

    .line 249
    .line 250
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 251
    .line 252
    .line 253
    move-result v13

    .line 254
    if-nez v13, :cond_9

    .line 255
    .line 256
    invoke-virtual {v12, v0}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    .line 257
    .line 258
    .line 259
    move-result-object v13

    .line 260
    if-eqz v13, :cond_8

    .line 261
    .line 262
    goto :goto_7

    .line 263
    :cond_8
    new-instance v13, Ljava/lang/StringBuilder;

    .line 264
    .line 265
    const-string v14, "Notification Channel requested ("

    .line 266
    .line 267
    invoke-direct {v13, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    const-string v0, ") has not been created by the app. Manifest configuration, or default, value will be used."

    .line 274
    .line 275
    invoke-virtual {v13, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 283
    .line 284
    .line 285
    :cond_9
    const-string v0, "com.google.firebase.messaging.default_notification_channel_id"

    .line 286
    .line 287
    invoke-virtual {v10, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 292
    .line 293
    .line 294
    move-result v13

    .line 295
    if-nez v13, :cond_b

    .line 296
    .line 297
    invoke-virtual {v12, v0}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    .line 298
    .line 299
    .line 300
    move-result-object v13

    .line 301
    if-eqz v13, :cond_a

    .line 302
    .line 303
    goto :goto_7

    .line 304
    :cond_a
    const-string v0, "Notification Channel set in AndroidManifest.xml has not been created by the app. Default value will be used."

    .line 305
    .line 306
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 307
    .line 308
    .line 309
    goto :goto_5

    .line 310
    :cond_b
    const-string v0, "Missing Default Notification Channel metadata in AndroidManifest. Default value will be used."

    .line 311
    .line 312
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 313
    .line 314
    .line 315
    :goto_5
    const-string v0, "fcm_fallback_notification_channel"

    .line 316
    .line 317
    invoke-virtual {v12, v0}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    .line 318
    .line 319
    .line 320
    move-result-object v13

    .line 321
    if-nez v13, :cond_d

    .line 322
    .line 323
    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 324
    .line 325
    .line 326
    move-result-object v13

    .line 327
    const-string v14, "string"

    .line 328
    .line 329
    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v15

    .line 333
    const-string v5, "fcm_fallback_notification_channel_label"

    .line 334
    .line 335
    invoke-virtual {v13, v5, v14, v15}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 336
    .line 337
    .line 338
    move-result v5

    .line 339
    if-nez v5, :cond_c

    .line 340
    .line 341
    const-string v5, "String resource \"fcm_fallback_notification_channel_label\" is not found. Using default string channel name."

    .line 342
    .line 343
    invoke-static {v6, v5}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 344
    .line 345
    .line 346
    const-string v5, "Misc"

    .line 347
    .line 348
    goto :goto_6

    .line 349
    :cond_c
    invoke-virtual {v7, v5}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v5

    .line 353
    :goto_6
    new-instance v13, Landroid/app/NotificationChannel;

    .line 354
    .line 355
    invoke-direct {v13, v0, v5, v11}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v12, v13}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 359
    .line 360
    .line 361
    :cond_d
    :goto_7
    sget-object v5, Lcom/google/firebase/messaging/e;->a:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 362
    .line 363
    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v12

    .line 367
    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 368
    .line 369
    .line 370
    move-result-object v13

    .line 371
    invoke-virtual {v7}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 372
    .line 373
    .line 374
    move-result-object v14

    .line 375
    new-instance v15, Landroidx/core/app/x;

    .line 376
    .line 377
    invoke-direct {v15, v7, v0}, Landroidx/core/app/x;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    const-string v0, "gcm.n.title"

    .line 381
    .line 382
    invoke-virtual {v8, v13, v12, v0}, Laq/a;->u(Landroid/content/res/Resources;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object v0

    .line 386
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 387
    .line 388
    .line 389
    move-result v16

    .line 390
    if-nez v16, :cond_e

    .line 391
    .line 392
    invoke-static {v0}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    iput-object v0, v15, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 397
    .line 398
    :cond_e
    const-string v0, "gcm.n.body"

    .line 399
    .line 400
    invoke-virtual {v8, v13, v12, v0}, Laq/a;->u(Landroid/content/res/Resources;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 401
    .line 402
    .line 403
    move-result-object v0

    .line 404
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 405
    .line 406
    .line 407
    move-result v16

    .line 408
    if-nez v16, :cond_f

    .line 409
    .line 410
    invoke-virtual {v15, v0}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 411
    .line 412
    .line 413
    new-instance v11, Landroidx/core/app/v;

    .line 414
    .line 415
    invoke-direct {v11}, Landroidx/core/app/a0;-><init>()V

    .line 416
    .line 417
    .line 418
    invoke-static {v0}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    iput-object v0, v11, Landroidx/core/app/v;->e:Ljava/lang/CharSequence;

    .line 423
    .line 424
    invoke-virtual {v15, v11}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 425
    .line 426
    .line 427
    :cond_f
    const-string v0, "gcm.n.icon"

    .line 428
    .line 429
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 434
    .line 435
    .line 436
    move-result v11

    .line 437
    if-nez v11, :cond_12

    .line 438
    .line 439
    const-string v11, "drawable"

    .line 440
    .line 441
    invoke-virtual {v13, v0, v11, v12}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 442
    .line 443
    .line 444
    move-result v11

    .line 445
    if-eqz v11, :cond_10

    .line 446
    .line 447
    :goto_8
    move/from16 v17, v2

    .line 448
    .line 449
    goto :goto_b

    .line 450
    :cond_10
    const-string v11, "mipmap"

    .line 451
    .line 452
    invoke-virtual {v13, v0, v11, v12}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 453
    .line 454
    .line 455
    move-result v11

    .line 456
    if-eqz v11, :cond_11

    .line 457
    .line 458
    goto :goto_8

    .line 459
    :cond_11
    new-instance v11, Ljava/lang/StringBuilder;

    .line 460
    .line 461
    move/from16 v17, v2

    .line 462
    .line 463
    const-string v2, "Icon resource "

    .line 464
    .line 465
    invoke-direct {v11, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 469
    .line 470
    .line 471
    const-string v0, " not found. Notification will use default icon."

    .line 472
    .line 473
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 474
    .line 475
    .line 476
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 481
    .line 482
    .line 483
    goto :goto_9

    .line 484
    :cond_12
    move/from16 v17, v2

    .line 485
    .line 486
    :goto_9
    const-string v0, "com.google.firebase.messaging.default_notification_icon"

    .line 487
    .line 488
    invoke-virtual {v10, v0, v4}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 489
    .line 490
    .line 491
    move-result v2

    .line 492
    if-eqz v2, :cond_13

    .line 493
    .line 494
    goto :goto_a

    .line 495
    :cond_13
    :try_start_3
    invoke-virtual {v14, v12, v4}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    iget v2, v0, Landroid/content/pm/ApplicationInfo;->icon:I
    :try_end_3
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_3 .. :try_end_3} :catch_3

    .line 500
    .line 501
    goto :goto_a

    .line 502
    :catch_3
    move-exception v0

    .line 503
    new-instance v11, Ljava/lang/StringBuilder;

    .line 504
    .line 505
    invoke-direct {v11, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 506
    .line 507
    .line 508
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 509
    .line 510
    .line 511
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 516
    .line 517
    .line 518
    :goto_a
    if-eqz v2, :cond_14

    .line 519
    .line 520
    move v11, v2

    .line 521
    goto :goto_b

    .line 522
    :cond_14
    const v0, 0x1080093

    .line 523
    .line 524
    .line 525
    move v11, v0

    .line 526
    :goto_b
    iget-object v0, v15, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 527
    .line 528
    iput v11, v0, Landroid/app/Notification;->icon:I

    .line 529
    .line 530
    const-string v0, "gcm.n.sound2"

    .line 531
    .line 532
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 533
    .line 534
    .line 535
    move-result-object v0

    .line 536
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 537
    .line 538
    .line 539
    move-result v2

    .line 540
    if-eqz v2, :cond_15

    .line 541
    .line 542
    const-string v0, "gcm.n.sound"

    .line 543
    .line 544
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    :cond_15
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 549
    .line 550
    .line 551
    move-result v2

    .line 552
    const/4 v9, 0x2

    .line 553
    if-eqz v2, :cond_16

    .line 554
    .line 555
    const/4 v0, 0x0

    .line 556
    goto :goto_c

    .line 557
    :cond_16
    const-string v2, "default"

    .line 558
    .line 559
    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 560
    .line 561
    .line 562
    move-result v2

    .line 563
    if-nez v2, :cond_17

    .line 564
    .line 565
    const-string v2, "raw"

    .line 566
    .line 567
    invoke-virtual {v13, v0, v2, v12}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 568
    .line 569
    .line 570
    move-result v2

    .line 571
    if-eqz v2, :cond_17

    .line 572
    .line 573
    new-instance v2, Ljava/lang/StringBuilder;

    .line 574
    .line 575
    const-string v11, "android.resource://"

    .line 576
    .line 577
    invoke-direct {v2, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 581
    .line 582
    .line 583
    const-string v11, "/raw/"

    .line 584
    .line 585
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 586
    .line 587
    .line 588
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 589
    .line 590
    .line 591
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 592
    .line 593
    .line 594
    move-result-object v0

    .line 595
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 596
    .line 597
    .line 598
    move-result-object v0

    .line 599
    goto :goto_c

    .line 600
    :cond_17
    invoke-static {v9}, Landroid/media/RingtoneManager;->getDefaultUri(I)Landroid/net/Uri;

    .line 601
    .line 602
    .line 603
    move-result-object v0

    .line 604
    :goto_c
    if-eqz v0, :cond_18

    .line 605
    .line 606
    invoke-virtual {v15, v0}, Landroidx/core/app/x;->e(Landroid/net/Uri;)V

    .line 607
    .line 608
    .line 609
    :cond_18
    const-string v0, "gcm.n.click_action"

    .line 610
    .line 611
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 612
    .line 613
    .line 614
    move-result-object v0

    .line 615
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 616
    .line 617
    .line 618
    move-result v2

    .line 619
    if-nez v2, :cond_19

    .line 620
    .line 621
    new-instance v2, Landroid/content/Intent;

    .line 622
    .line 623
    invoke-direct {v2, v0}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 624
    .line 625
    .line 626
    invoke-virtual {v2, v12}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 627
    .line 628
    .line 629
    const/high16 v0, 0x10000000

    .line 630
    .line 631
    invoke-virtual {v2, v0}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 632
    .line 633
    .line 634
    goto :goto_e

    .line 635
    :cond_19
    const-string v0, "gcm.n.link_android"

    .line 636
    .line 637
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 638
    .line 639
    .line 640
    move-result-object v0

    .line 641
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 642
    .line 643
    .line 644
    move-result v2

    .line 645
    if-eqz v2, :cond_1a

    .line 646
    .line 647
    const-string v0, "gcm.n.link"

    .line 648
    .line 649
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 650
    .line 651
    .line 652
    move-result-object v0

    .line 653
    :cond_1a
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 654
    .line 655
    .line 656
    move-result v2

    .line 657
    if-nez v2, :cond_1b

    .line 658
    .line 659
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 660
    .line 661
    .line 662
    move-result-object v0

    .line 663
    goto :goto_d

    .line 664
    :cond_1b
    const/4 v0, 0x0

    .line 665
    :goto_d
    if-eqz v0, :cond_1c

    .line 666
    .line 667
    new-instance v2, Landroid/content/Intent;

    .line 668
    .line 669
    const-string v11, "android.intent.action.VIEW"

    .line 670
    .line 671
    invoke-direct {v2, v11}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 672
    .line 673
    .line 674
    invoke-virtual {v2, v12}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 675
    .line 676
    .line 677
    invoke-virtual {v2, v0}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 678
    .line 679
    .line 680
    goto :goto_e

    .line 681
    :cond_1c
    invoke-virtual {v14, v12}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 682
    .line 683
    .line 684
    move-result-object v2

    .line 685
    if-nez v2, :cond_1d

    .line 686
    .line 687
    const-string v0, "No activity found to launch app"

    .line 688
    .line 689
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 690
    .line 691
    .line 692
    :cond_1d
    :goto_e
    const/high16 v0, 0x44000000    # 512.0f

    .line 693
    .line 694
    const-string v11, "google.c.a.e"

    .line 695
    .line 696
    if-nez v2, :cond_1e

    .line 697
    .line 698
    const/4 v2, 0x0

    .line 699
    goto :goto_10

    .line 700
    :cond_1e
    const/high16 v12, 0x4000000

    .line 701
    .line 702
    invoke-virtual {v2, v12}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 703
    .line 704
    .line 705
    new-instance v12, Landroid/os/Bundle;

    .line 706
    .line 707
    iget-object v13, v8, Laq/a;->e:Ljava/lang/Object;

    .line 708
    .line 709
    check-cast v13, Landroid/os/Bundle;

    .line 710
    .line 711
    invoke-direct {v12, v13}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 712
    .line 713
    .line 714
    invoke-virtual {v13}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 715
    .line 716
    .line 717
    move-result-object v13

    .line 718
    invoke-interface {v13}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 719
    .line 720
    .line 721
    move-result-object v13

    .line 722
    :goto_f
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 723
    .line 724
    .line 725
    move-result v14

    .line 726
    if-eqz v14, :cond_21

    .line 727
    .line 728
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 729
    .line 730
    .line 731
    move-result-object v14

    .line 732
    check-cast v14, Ljava/lang/String;

    .line 733
    .line 734
    const-string v9, "google.c."

    .line 735
    .line 736
    invoke-virtual {v14, v9}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 737
    .line 738
    .line 739
    move-result v9

    .line 740
    if-nez v9, :cond_1f

    .line 741
    .line 742
    const-string v9, "gcm.n."

    .line 743
    .line 744
    invoke-virtual {v14, v9}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 745
    .line 746
    .line 747
    move-result v9

    .line 748
    if-nez v9, :cond_1f

    .line 749
    .line 750
    const-string v9, "gcm.notification."

    .line 751
    .line 752
    invoke-virtual {v14, v9}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 753
    .line 754
    .line 755
    move-result v9

    .line 756
    if-eqz v9, :cond_20

    .line 757
    .line 758
    :cond_1f
    invoke-virtual {v12, v14}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 759
    .line 760
    .line 761
    :cond_20
    const/4 v9, 0x2

    .line 762
    goto :goto_f

    .line 763
    :cond_21
    invoke-virtual {v2, v12}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    .line 764
    .line 765
    .line 766
    invoke-virtual {v8, v11}, Laq/a;->l(Ljava/lang/String;)Z

    .line 767
    .line 768
    .line 769
    move-result v9

    .line 770
    if-eqz v9, :cond_22

    .line 771
    .line 772
    const-string v9, "gcm.n.analytics_data"

    .line 773
    .line 774
    invoke-virtual {v8}, Laq/a;->D()Landroid/os/Bundle;

    .line 775
    .line 776
    .line 777
    move-result-object v12

    .line 778
    invoke-virtual {v2, v9, v12}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;

    .line 779
    .line 780
    .line 781
    :cond_22
    invoke-virtual {v5}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 782
    .line 783
    .line 784
    move-result v9

    .line 785
    invoke-static {v7, v9, v2, v0}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 786
    .line 787
    .line 788
    move-result-object v2

    .line 789
    :goto_10
    iput-object v2, v15, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 790
    .line 791
    invoke-virtual {v8, v11}, Laq/a;->l(Ljava/lang/String;)Z

    .line 792
    .line 793
    .line 794
    move-result v2

    .line 795
    if-nez v2, :cond_23

    .line 796
    .line 797
    const/4 v0, 0x0

    .line 798
    goto :goto_11

    .line 799
    :cond_23
    new-instance v2, Landroid/content/Intent;

    .line 800
    .line 801
    const-string v9, "com.google.firebase.messaging.NOTIFICATION_DISMISS"

    .line 802
    .line 803
    invoke-direct {v2, v9}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 804
    .line 805
    .line 806
    invoke-virtual {v8}, Laq/a;->D()Landroid/os/Bundle;

    .line 807
    .line 808
    .line 809
    move-result-object v9

    .line 810
    invoke-virtual {v2, v9}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    .line 811
    .line 812
    .line 813
    move-result-object v2

    .line 814
    invoke-virtual {v5}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 815
    .line 816
    .line 817
    move-result v5

    .line 818
    new-instance v9, Landroid/content/Intent;

    .line 819
    .line 820
    const-string v11, "com.google.android.c2dm.intent.RECEIVE"

    .line 821
    .line 822
    invoke-direct {v9, v11}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 823
    .line 824
    .line 825
    invoke-virtual {v7}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 826
    .line 827
    .line 828
    move-result-object v11

    .line 829
    invoke-virtual {v9, v11}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 830
    .line 831
    .line 832
    move-result-object v9

    .line 833
    const-string v11, "wrapped_intent"

    .line 834
    .line 835
    invoke-virtual {v9, v11, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 836
    .line 837
    .line 838
    move-result-object v2

    .line 839
    invoke-static {v7, v5, v2, v0}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 840
    .line 841
    .line 842
    move-result-object v0

    .line 843
    :goto_11
    if-eqz v0, :cond_24

    .line 844
    .line 845
    iget-object v2, v15, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 846
    .line 847
    iput-object v0, v2, Landroid/app/Notification;->deleteIntent:Landroid/app/PendingIntent;

    .line 848
    .line 849
    :cond_24
    const-string v0, "gcm.n.color"

    .line 850
    .line 851
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 852
    .line 853
    .line 854
    move-result-object v0

    .line 855
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 856
    .line 857
    .line 858
    move-result v2

    .line 859
    if-nez v2, :cond_25

    .line 860
    .line 861
    :try_start_4
    invoke-static {v0}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    .line 862
    .line 863
    .line 864
    move-result v2

    .line 865
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 866
    .line 867
    .line 868
    move-result-object v0
    :try_end_4
    .catch Ljava/lang/IllegalArgumentException; {:try_start_4 .. :try_end_4} :catch_4

    .line 869
    goto :goto_12

    .line 870
    :catch_4
    new-instance v2, Ljava/lang/StringBuilder;

    .line 871
    .line 872
    const-string v5, "Color is invalid: "

    .line 873
    .line 874
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 878
    .line 879
    .line 880
    const-string v0, ". Notification will use default color."

    .line 881
    .line 882
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 883
    .line 884
    .line 885
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 886
    .line 887
    .line 888
    move-result-object v0

    .line 889
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 890
    .line 891
    .line 892
    :cond_25
    const-string v0, "com.google.firebase.messaging.default_notification_color"

    .line 893
    .line 894
    invoke-virtual {v10, v0, v4}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 895
    .line 896
    .line 897
    move-result v0

    .line 898
    if-eqz v0, :cond_26

    .line 899
    .line 900
    :try_start_5
    invoke-virtual {v7, v0}, Landroid/content/Context;->getColor(I)I

    .line 901
    .line 902
    .line 903
    move-result v0

    .line 904
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 905
    .line 906
    .line 907
    move-result-object v0
    :try_end_5
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_5 .. :try_end_5} :catch_5

    .line 908
    goto :goto_12

    .line 909
    :catch_5
    const-string v0, "Cannot find the color resource referenced in AndroidManifest."

    .line 910
    .line 911
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 912
    .line 913
    .line 914
    :cond_26
    const/4 v0, 0x0

    .line 915
    :goto_12
    if-eqz v0, :cond_27

    .line 916
    .line 917
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 918
    .line 919
    .line 920
    move-result v0

    .line 921
    iput v0, v15, Landroidx/core/app/x;->q:I

    .line 922
    .line 923
    :cond_27
    const-string v0, "gcm.n.sticky"

    .line 924
    .line 925
    invoke-virtual {v8, v0}, Laq/a;->l(Ljava/lang/String;)Z

    .line 926
    .line 927
    .line 928
    move-result v0

    .line 929
    xor-int/lit8 v0, v0, 0x1

    .line 930
    .line 931
    const/16 v2, 0x10

    .line 932
    .line 933
    invoke-virtual {v15, v2, v0}, Landroidx/core/app/x;->d(IZ)V

    .line 934
    .line 935
    .line 936
    const-string v0, "gcm.n.local_only"

    .line 937
    .line 938
    invoke-virtual {v8, v0}, Laq/a;->l(Ljava/lang/String;)Z

    .line 939
    .line 940
    .line 941
    move-result v0

    .line 942
    iput-boolean v0, v15, Landroidx/core/app/x;->o:Z

    .line 943
    .line 944
    const-string v0, "gcm.n.ticker"

    .line 945
    .line 946
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 947
    .line 948
    .line 949
    move-result-object v0

    .line 950
    if-eqz v0, :cond_28

    .line 951
    .line 952
    invoke-virtual {v15, v0}, Landroidx/core/app/x;->g(Ljava/lang/CharSequence;)V

    .line 953
    .line 954
    .line 955
    :cond_28
    const-string v0, "gcm.n.notification_priority"

    .line 956
    .line 957
    invoke-virtual {v8, v0}, Laq/a;->p(Ljava/lang/String;)Ljava/lang/Integer;

    .line 958
    .line 959
    .line 960
    move-result-object v0

    .line 961
    const/4 v2, -0x2

    .line 962
    if-nez v0, :cond_29

    .line 963
    .line 964
    :goto_13
    const/4 v0, 0x0

    .line 965
    goto :goto_14

    .line 966
    :cond_29
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 967
    .line 968
    .line 969
    move-result v5

    .line 970
    if-lt v5, v2, :cond_2a

    .line 971
    .line 972
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 973
    .line 974
    .line 975
    move-result v5

    .line 976
    const/4 v7, 0x2

    .line 977
    if-le v5, v7, :cond_2b

    .line 978
    .line 979
    :cond_2a
    new-instance v5, Ljava/lang/StringBuilder;

    .line 980
    .line 981
    const-string v7, "notificationPriority is invalid "

    .line 982
    .line 983
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 984
    .line 985
    .line 986
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 987
    .line 988
    .line 989
    const-string v0, ". Skipping setting notificationPriority."

    .line 990
    .line 991
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 992
    .line 993
    .line 994
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 995
    .line 996
    .line 997
    move-result-object v0

    .line 998
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 999
    .line 1000
    .line 1001
    goto :goto_13

    .line 1002
    :cond_2b
    :goto_14
    if-eqz v0, :cond_2c

    .line 1003
    .line 1004
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1005
    .line 1006
    .line 1007
    move-result v0

    .line 1008
    iput v0, v15, Landroidx/core/app/x;->j:I

    .line 1009
    .line 1010
    :cond_2c
    const-string v0, "gcm.n.visibility"

    .line 1011
    .line 1012
    invoke-virtual {v8, v0}, Laq/a;->p(Ljava/lang/String;)Ljava/lang/Integer;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v0

    .line 1016
    const-string v5, "NotificationParams"

    .line 1017
    .line 1018
    if-nez v0, :cond_2d

    .line 1019
    .line 1020
    :goto_15
    const/4 v0, 0x0

    .line 1021
    goto :goto_16

    .line 1022
    :cond_2d
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1023
    .line 1024
    .line 1025
    move-result v7

    .line 1026
    const/4 v9, -0x1

    .line 1027
    if-lt v7, v9, :cond_2e

    .line 1028
    .line 1029
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1030
    .line 1031
    .line 1032
    move-result v7

    .line 1033
    move/from16 v9, v17

    .line 1034
    .line 1035
    if-le v7, v9, :cond_2f

    .line 1036
    .line 1037
    :cond_2e
    new-instance v7, Ljava/lang/StringBuilder;

    .line 1038
    .line 1039
    const-string v9, "visibility is invalid: "

    .line 1040
    .line 1041
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1042
    .line 1043
    .line 1044
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1045
    .line 1046
    .line 1047
    const-string v0, ". Skipping setting visibility."

    .line 1048
    .line 1049
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1050
    .line 1051
    .line 1052
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v0

    .line 1056
    invoke-static {v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1057
    .line 1058
    .line 1059
    goto :goto_15

    .line 1060
    :cond_2f
    :goto_16
    if-eqz v0, :cond_30

    .line 1061
    .line 1062
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1063
    .line 1064
    .line 1065
    move-result v0

    .line 1066
    iput v0, v15, Landroidx/core/app/x;->r:I

    .line 1067
    .line 1068
    :cond_30
    const-string v0, "gcm.n.notification_count"

    .line 1069
    .line 1070
    invoke-virtual {v8, v0}, Laq/a;->p(Ljava/lang/String;)Ljava/lang/Integer;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v0

    .line 1074
    if-nez v0, :cond_31

    .line 1075
    .line 1076
    :goto_17
    const/4 v0, 0x0

    .line 1077
    goto :goto_18

    .line 1078
    :cond_31
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1079
    .line 1080
    .line 1081
    move-result v7

    .line 1082
    if-gez v7, :cond_32

    .line 1083
    .line 1084
    new-instance v7, Ljava/lang/StringBuilder;

    .line 1085
    .line 1086
    const-string v9, "notificationCount is invalid: "

    .line 1087
    .line 1088
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1089
    .line 1090
    .line 1091
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1092
    .line 1093
    .line 1094
    const-string v0, ". Skipping setting notificationCount."

    .line 1095
    .line 1096
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1097
    .line 1098
    .line 1099
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v0

    .line 1103
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1104
    .line 1105
    .line 1106
    goto :goto_17

    .line 1107
    :cond_32
    :goto_18
    if-eqz v0, :cond_33

    .line 1108
    .line 1109
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1110
    .line 1111
    .line 1112
    move-result v0

    .line 1113
    iput v0, v15, Landroidx/core/app/x;->i:I

    .line 1114
    .line 1115
    :cond_33
    const-string v0, "gcm.n.event_time"

    .line 1116
    .line 1117
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v7

    .line 1121
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1122
    .line 1123
    .line 1124
    move-result v9

    .line 1125
    if-nez v9, :cond_34

    .line 1126
    .line 1127
    :try_start_6
    invoke-static {v7}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 1128
    .line 1129
    .line 1130
    move-result-wide v9

    .line 1131
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1132
    .line 1133
    .line 1134
    move-result-object v0
    :try_end_6
    .catch Ljava/lang/NumberFormatException; {:try_start_6 .. :try_end_6} :catch_6

    .line 1135
    goto :goto_19

    .line 1136
    :catch_6
    new-instance v9, Ljava/lang/StringBuilder;

    .line 1137
    .line 1138
    const-string v10, "Couldn\'t parse value of "

    .line 1139
    .line 1140
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1141
    .line 1142
    .line 1143
    invoke-static {v0}, Laq/a;->G(Ljava/lang/String;)Ljava/lang/String;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v0

    .line 1147
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1148
    .line 1149
    .line 1150
    const-string v0, "("

    .line 1151
    .line 1152
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1153
    .line 1154
    .line 1155
    invoke-virtual {v9, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1156
    .line 1157
    .line 1158
    const-string v0, ") into a long"

    .line 1159
    .line 1160
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1161
    .line 1162
    .line 1163
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1164
    .line 1165
    .line 1166
    move-result-object v0

    .line 1167
    invoke-static {v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1168
    .line 1169
    .line 1170
    :cond_34
    const/4 v0, 0x0

    .line 1171
    :goto_19
    if-eqz v0, :cond_35

    .line 1172
    .line 1173
    const/4 v9, 0x1

    .line 1174
    iput-boolean v9, v15, Landroidx/core/app/x;->k:Z

    .line 1175
    .line 1176
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 1177
    .line 1178
    .line 1179
    move-result-wide v9

    .line 1180
    iget-object v0, v15, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 1181
    .line 1182
    iput-wide v9, v0, Landroid/app/Notification;->when:J

    .line 1183
    .line 1184
    :cond_35
    const-string v0, "gcm.n.vibrate_timings"

    .line 1185
    .line 1186
    invoke-virtual {v8, v0}, Laq/a;->r(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 1187
    .line 1188
    .line 1189
    move-result-object v0

    .line 1190
    if-nez v0, :cond_36

    .line 1191
    .line 1192
    :goto_1a
    const/4 v9, 0x0

    .line 1193
    goto :goto_1c

    .line 1194
    :cond_36
    :try_start_7
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    .line 1195
    .line 1196
    .line 1197
    move-result v7

    .line 1198
    const/4 v9, 0x1

    .line 1199
    if-le v7, v9, :cond_37

    .line 1200
    .line 1201
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    .line 1202
    .line 1203
    .line 1204
    move-result v7

    .line 1205
    new-array v9, v7, [J

    .line 1206
    .line 1207
    move v10, v4

    .line 1208
    :goto_1b
    if-ge v10, v7, :cond_38

    .line 1209
    .line 1210
    invoke-virtual {v0, v10}, Lorg/json/JSONArray;->optLong(I)J

    .line 1211
    .line 1212
    .line 1213
    move-result-wide v11

    .line 1214
    aput-wide v11, v9, v10

    .line 1215
    .line 1216
    add-int/lit8 v10, v10, 0x1

    .line 1217
    .line 1218
    goto :goto_1b

    .line 1219
    :cond_37
    new-instance v7, Lorg/json/JSONException;

    .line 1220
    .line 1221
    const-string v9, "vibrateTimings have invalid length"

    .line 1222
    .line 1223
    invoke-direct {v7, v9}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 1224
    .line 1225
    .line 1226
    throw v7
    :try_end_7
    .catch Lorg/json/JSONException; {:try_start_7 .. :try_end_7} :catch_7
    .catch Ljava/lang/NumberFormatException; {:try_start_7 .. :try_end_7} :catch_7

    .line 1227
    :catch_7
    new-instance v7, Ljava/lang/StringBuilder;

    .line 1228
    .line 1229
    const-string v9, "User defined vibrateTimings is invalid: "

    .line 1230
    .line 1231
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1232
    .line 1233
    .line 1234
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1235
    .line 1236
    .line 1237
    const-string v0, ". Skipping setting vibrateTimings."

    .line 1238
    .line 1239
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1240
    .line 1241
    .line 1242
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1243
    .line 1244
    .line 1245
    move-result-object v0

    .line 1246
    invoke-static {v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1247
    .line 1248
    .line 1249
    goto :goto_1a

    .line 1250
    :cond_38
    :goto_1c
    if-eqz v9, :cond_39

    .line 1251
    .line 1252
    iget-object v0, v15, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 1253
    .line 1254
    iput-object v9, v0, Landroid/app/Notification;->vibrate:[J

    .line 1255
    .line 1256
    :cond_39
    const-string v7, ". Skipping setting LightSettings"

    .line 1257
    .line 1258
    const-string v9, "LightSettings is invalid: "

    .line 1259
    .line 1260
    const-string v0, "gcm.n.light_settings"

    .line 1261
    .line 1262
    invoke-virtual {v8, v0}, Laq/a;->r(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 1263
    .line 1264
    .line 1265
    move-result-object v10

    .line 1266
    if-nez v10, :cond_3a

    .line 1267
    .line 1268
    :goto_1d
    const/4 v0, 0x0

    .line 1269
    goto :goto_1f

    .line 1270
    :cond_3a
    const/4 v11, 0x3

    .line 1271
    new-array v0, v11, [I

    .line 1272
    .line 1273
    :try_start_8
    invoke-virtual {v10}, Lorg/json/JSONArray;->length()I

    .line 1274
    .line 1275
    .line 1276
    move-result v12

    .line 1277
    if-ne v12, v11, :cond_3c

    .line 1278
    .line 1279
    invoke-virtual {v10, v4}, Lorg/json/JSONArray;->optString(I)Ljava/lang/String;

    .line 1280
    .line 1281
    .line 1282
    move-result-object v11

    .line 1283
    invoke-static {v11}, Landroid/graphics/Color;->parseColor(Ljava/lang/String;)I

    .line 1284
    .line 1285
    .line 1286
    move-result v11

    .line 1287
    const/high16 v12, -0x1000000

    .line 1288
    .line 1289
    if-eq v11, v12, :cond_3b

    .line 1290
    .line 1291
    aput v11, v0, v4

    .line 1292
    .line 1293
    const/4 v11, 0x1

    .line 1294
    invoke-virtual {v10, v11}, Lorg/json/JSONArray;->optInt(I)I

    .line 1295
    .line 1296
    .line 1297
    move-result v12

    .line 1298
    aput v12, v0, v11

    .line 1299
    .line 1300
    const/4 v11, 0x2

    .line 1301
    invoke-virtual {v10, v11}, Lorg/json/JSONArray;->optInt(I)I

    .line 1302
    .line 1303
    .line 1304
    move-result v12

    .line 1305
    aput v12, v0, v11

    .line 1306
    .line 1307
    goto :goto_1f

    .line 1308
    :catch_8
    move-exception v0

    .line 1309
    goto :goto_1e

    .line 1310
    :cond_3b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1311
    .line 1312
    const-string v11, "Transparent color is invalid"

    .line 1313
    .line 1314
    invoke-direct {v0, v11}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1315
    .line 1316
    .line 1317
    throw v0

    .line 1318
    :cond_3c
    new-instance v0, Lorg/json/JSONException;

    .line 1319
    .line 1320
    const-string v11, "lightSettings don\'t have all three fields"

    .line 1321
    .line 1322
    invoke-direct {v0, v11}, Lorg/json/JSONException;-><init>(Ljava/lang/String;)V

    .line 1323
    .line 1324
    .line 1325
    throw v0
    :try_end_8
    .catch Lorg/json/JSONException; {:try_start_8 .. :try_end_8} :catch_9
    .catch Ljava/lang/IllegalArgumentException; {:try_start_8 .. :try_end_8} :catch_8

    .line 1326
    :goto_1e
    new-instance v11, Ljava/lang/StringBuilder;

    .line 1327
    .line 1328
    invoke-direct {v11, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1329
    .line 1330
    .line 1331
    invoke-virtual {v11, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1332
    .line 1333
    .line 1334
    const-string v9, ". "

    .line 1335
    .line 1336
    invoke-virtual {v11, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1337
    .line 1338
    .line 1339
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1340
    .line 1341
    .line 1342
    move-result-object v0

    .line 1343
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1344
    .line 1345
    .line 1346
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1347
    .line 1348
    .line 1349
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v0

    .line 1353
    invoke-static {v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1354
    .line 1355
    .line 1356
    goto :goto_1d

    .line 1357
    :catch_9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1358
    .line 1359
    invoke-direct {v0, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1360
    .line 1361
    .line 1362
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1363
    .line 1364
    .line 1365
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1366
    .line 1367
    .line 1368
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v0

    .line 1372
    invoke-static {v5, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1373
    .line 1374
    .line 1375
    goto :goto_1d

    .line 1376
    :goto_1f
    if-eqz v0, :cond_3e

    .line 1377
    .line 1378
    aget v5, v0, v4

    .line 1379
    .line 1380
    const/16 v17, 0x1

    .line 1381
    .line 1382
    aget v7, v0, v17

    .line 1383
    .line 1384
    const/16 v18, 0x2

    .line 1385
    .line 1386
    aget v0, v0, v18

    .line 1387
    .line 1388
    iget-object v9, v15, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 1389
    .line 1390
    iput v5, v9, Landroid/app/Notification;->ledARGB:I

    .line 1391
    .line 1392
    iput v7, v9, Landroid/app/Notification;->ledOnMS:I

    .line 1393
    .line 1394
    iput v0, v9, Landroid/app/Notification;->ledOffMS:I

    .line 1395
    .line 1396
    if-eqz v7, :cond_3d

    .line 1397
    .line 1398
    if-eqz v0, :cond_3d

    .line 1399
    .line 1400
    const/4 v0, 0x1

    .line 1401
    goto :goto_20

    .line 1402
    :cond_3d
    move v0, v4

    .line 1403
    :goto_20
    iget v5, v9, Landroid/app/Notification;->flags:I

    .line 1404
    .line 1405
    and-int/2addr v2, v5

    .line 1406
    or-int/2addr v0, v2

    .line 1407
    iput v0, v9, Landroid/app/Notification;->flags:I

    .line 1408
    .line 1409
    :cond_3e
    const-string v0, "gcm.n.default_sound"

    .line 1410
    .line 1411
    invoke-virtual {v8, v0}, Laq/a;->l(Ljava/lang/String;)Z

    .line 1412
    .line 1413
    .line 1414
    move-result v0

    .line 1415
    const-string v2, "gcm.n.default_vibrate_timings"

    .line 1416
    .line 1417
    invoke-virtual {v8, v2}, Laq/a;->l(Ljava/lang/String;)Z

    .line 1418
    .line 1419
    .line 1420
    move-result v2

    .line 1421
    if-eqz v2, :cond_3f

    .line 1422
    .line 1423
    or-int/lit8 v0, v0, 0x2

    .line 1424
    .line 1425
    :cond_3f
    const-string v2, "gcm.n.default_light_settings"

    .line 1426
    .line 1427
    invoke-virtual {v8, v2}, Laq/a;->l(Ljava/lang/String;)Z

    .line 1428
    .line 1429
    .line 1430
    move-result v2

    .line 1431
    if-eqz v2, :cond_40

    .line 1432
    .line 1433
    or-int/lit8 v0, v0, 0x4

    .line 1434
    .line 1435
    :cond_40
    iget-object v2, v15, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 1436
    .line 1437
    iput v0, v2, Landroid/app/Notification;->defaults:I

    .line 1438
    .line 1439
    and-int/lit8 v0, v0, 0x4

    .line 1440
    .line 1441
    if-eqz v0, :cond_41

    .line 1442
    .line 1443
    iget v0, v2, Landroid/app/Notification;->flags:I

    .line 1444
    .line 1445
    const/16 v17, 0x1

    .line 1446
    .line 1447
    or-int/lit8 v0, v0, 0x1

    .line 1448
    .line 1449
    iput v0, v2, Landroid/app/Notification;->flags:I

    .line 1450
    .line 1451
    :cond_41
    const-string v0, "gcm.n.tag"

    .line 1452
    .line 1453
    invoke-virtual {v8, v0}, Laq/a;->x(Ljava/lang/String;)Ljava/lang/String;

    .line 1454
    .line 1455
    .line 1456
    move-result-object v0

    .line 1457
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1458
    .line 1459
    .line 1460
    move-result v2

    .line 1461
    if-nez v2, :cond_42

    .line 1462
    .line 1463
    :goto_21
    move-object v2, v0

    .line 1464
    goto :goto_22

    .line 1465
    :cond_42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1466
    .line 1467
    const-string v2, "FCM-Notification:"

    .line 1468
    .line 1469
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1470
    .line 1471
    .line 1472
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 1473
    .line 1474
    .line 1475
    move-result-wide v7

    .line 1476
    invoke-virtual {v0, v7, v8}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 1477
    .line 1478
    .line 1479
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1480
    .line 1481
    .line 1482
    move-result-object v0

    .line 1483
    goto :goto_21

    .line 1484
    :goto_22
    if-nez v3, :cond_43

    .line 1485
    .line 1486
    goto :goto_25

    .line 1487
    :cond_43
    :try_start_9
    iget-object v0, v3, Lcom/google/firebase/messaging/q;->f:Laq/t;

    .line 1488
    .line 1489
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 1490
    .line 1491
    .line 1492
    sget-object v5, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 1493
    .line 1494
    const-wide/16 v7, 0x5

    .line 1495
    .line 1496
    invoke-static {v0, v7, v8, v5}, Ljp/l1;->b(Laq/j;JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    .line 1497
    .line 1498
    .line 1499
    move-result-object v0

    .line 1500
    check-cast v0, Landroid/graphics/Bitmap;

    .line 1501
    .line 1502
    if-nez v0, :cond_44

    .line 1503
    .line 1504
    const/4 v5, 0x0

    .line 1505
    goto :goto_23

    .line 1506
    :cond_44
    new-instance v5, Landroidx/core/graphics/drawable/IconCompat;

    .line 1507
    .line 1508
    const/4 v9, 0x1

    .line 1509
    invoke-direct {v5, v9}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 1510
    .line 1511
    .line 1512
    iput-object v0, v5, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 1513
    .line 1514
    :goto_23
    iput-object v5, v15, Landroidx/core/app/x;->h:Landroidx/core/graphics/drawable/IconCompat;

    .line 1515
    .line 1516
    new-instance v5, Landroidx/core/app/u;

    .line 1517
    .line 1518
    invoke-direct {v5}, Landroidx/core/app/a0;-><init>()V

    .line 1519
    .line 1520
    .line 1521
    if-nez v0, :cond_45

    .line 1522
    .line 1523
    const/4 v7, 0x0

    .line 1524
    const/4 v9, 0x1

    .line 1525
    goto :goto_24

    .line 1526
    :cond_45
    new-instance v7, Landroidx/core/graphics/drawable/IconCompat;

    .line 1527
    .line 1528
    const/4 v9, 0x1

    .line 1529
    invoke-direct {v7, v9}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 1530
    .line 1531
    .line 1532
    iput-object v0, v7, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 1533
    .line 1534
    :goto_24
    iput-object v7, v5, Landroidx/core/app/u;->e:Landroidx/core/graphics/drawable/IconCompat;

    .line 1535
    .line 1536
    const/4 v7, 0x0

    .line 1537
    iput-object v7, v5, Landroidx/core/app/u;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 1538
    .line 1539
    iput-boolean v9, v5, Landroidx/core/app/u;->g:Z

    .line 1540
    .line 1541
    invoke-virtual {v15, v5}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V
    :try_end_9
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_9 .. :try_end_9} :catch_a
    .catch Ljava/lang/InterruptedException; {:try_start_9 .. :try_end_9} :catch_c
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_9 .. :try_end_9} :catch_b

    .line 1542
    .line 1543
    .line 1544
    :goto_25
    const/4 v11, 0x3

    .line 1545
    goto :goto_27

    .line 1546
    :catch_a
    move-exception v0

    .line 1547
    goto :goto_26

    .line 1548
    :catch_b
    const-string v0, "Failed to download image in time, showing notification without it"

    .line 1549
    .line 1550
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1551
    .line 1552
    .line 1553
    invoke-virtual {v3}, Lcom/google/firebase/messaging/q;->close()V

    .line 1554
    .line 1555
    .line 1556
    goto :goto_25

    .line 1557
    :catch_c
    const-string v0, "Interrupted while downloading image, showing notification without it"

    .line 1558
    .line 1559
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1560
    .line 1561
    .line 1562
    invoke-virtual {v3}, Lcom/google/firebase/messaging/q;->close()V

    .line 1563
    .line 1564
    .line 1565
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 1566
    .line 1567
    .line 1568
    move-result-object v0

    .line 1569
    invoke-virtual {v0}, Ljava/lang/Thread;->interrupt()V

    .line 1570
    .line 1571
    .line 1572
    goto :goto_25

    .line 1573
    :goto_26
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1574
    .line 1575
    const-string v5, "Failed to download image: "

    .line 1576
    .line 1577
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1578
    .line 1579
    .line 1580
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1581
    .line 1582
    .line 1583
    move-result-object v0

    .line 1584
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1585
    .line 1586
    .line 1587
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v0

    .line 1591
    invoke-static {v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1592
    .line 1593
    .line 1594
    goto :goto_25

    .line 1595
    :goto_27
    invoke-static {v6, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1596
    .line 1597
    .line 1598
    move-result v0

    .line 1599
    if-eqz v0, :cond_46

    .line 1600
    .line 1601
    const-string v0, "Showing notification"

    .line 1602
    .line 1603
    invoke-static {v6, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 1604
    .line 1605
    .line 1606
    :cond_46
    iget-object v0, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 1607
    .line 1608
    check-cast v0, Lcom/google/firebase/messaging/FirebaseMessagingService;

    .line 1609
    .line 1610
    const-string v1, "notification"

    .line 1611
    .line 1612
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 1613
    .line 1614
    .line 1615
    move-result-object v0

    .line 1616
    check-cast v0, Landroid/app/NotificationManager;

    .line 1617
    .line 1618
    invoke-virtual {v15}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 1619
    .line 1620
    .line 1621
    move-result-object v1

    .line 1622
    invoke-virtual {v0, v2, v4, v1}, Landroid/app/NotificationManager;->notify(Ljava/lang/String;ILandroid/app/Notification;)V

    .line 1623
    .line 1624
    .line 1625
    const/16 v17, 0x1

    .line 1626
    .line 1627
    return v17
.end method

.method public q(Ly7/h;Landroid/net/Uri;Ljava/util/Map;JJLh8/r0;)V
    .locals 7

    .line 1
    new-instance v1, Lo8/l;

    .line 2
    .line 3
    move-object v2, p1

    .line 4
    move-wide v3, p4

    .line 5
    move-wide v5, p6

    .line 6
    invoke-direct/range {v1 .. v6}, Lo8/l;-><init>(Lt7/g;JJ)V

    .line 7
    .line 8
    .line 9
    iput-object v1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p1, Lo8/o;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Lo8/r;

    .line 21
    .line 22
    invoke-interface {p1, p2, p3}, Lo8/r;->c(Landroid/net/Uri;Ljava/util/Map;)[Lo8/o;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    array-length p3, p1

    .line 27
    sget-object p4, Lhr/h0;->e:Lhr/f0;

    .line 28
    .line 29
    const-string p4, "expectedSize"

    .line 30
    .line 31
    invoke-static {p3, p4}, Lhr/q;->c(ILjava/lang/String;)V

    .line 32
    .line 33
    .line 34
    new-instance p4, Lhr/e0;

    .line 35
    .line 36
    invoke-direct {p4, p3}, Lhr/b0;-><init>(I)V

    .line 37
    .line 38
    .line 39
    array-length p3, p1

    .line 40
    const/4 p5, 0x1

    .line 41
    const/4 p6, 0x0

    .line 42
    if-ne p3, p5, :cond_1

    .line 43
    .line 44
    aget-object p1, p1, p6

    .line 45
    .line 46
    iput-object p1, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 47
    .line 48
    goto/16 :goto_7

    .line 49
    .line 50
    :cond_1
    array-length p3, p1

    .line 51
    move p7, p6

    .line 52
    :goto_0
    if-ge p7, p3, :cond_7

    .line 53
    .line 54
    aget-object v0, p1, p7

    .line 55
    .line 56
    :try_start_0
    invoke-interface {v0, v1}, Lo8/o;->a(Lo8/p;)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_2

    .line 61
    .line 62
    iput-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 63
    .line 64
    iput p6, v1, Lo8/l;->i:I

    .line 65
    .line 66
    goto :goto_6

    .line 67
    :catchall_0
    move-exception v0

    .line 68
    move-object p1, v0

    .line 69
    goto :goto_3

    .line 70
    :cond_2
    :try_start_1
    invoke-interface {v0}, Lo8/o;->j()Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-virtual {p4, v0}, Lhr/b0;->d(Ljava/lang/Iterable;)V
    :try_end_1
    .catch Ljava/io/EOFException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 75
    .line 76
    .line 77
    iget-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Lo8/o;

    .line 80
    .line 81
    if-nez v0, :cond_4

    .line 82
    .line 83
    iget-wide v5, v1, Lo8/l;->g:J

    .line 84
    .line 85
    cmp-long v0, v5, v3

    .line 86
    .line 87
    if-nez v0, :cond_3

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_3
    move v0, p6

    .line 91
    goto :goto_2

    .line 92
    :cond_4
    :goto_1
    move v0, p5

    .line 93
    :goto_2
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 94
    .line 95
    .line 96
    iput p6, v1, Lo8/l;->i:I

    .line 97
    .line 98
    goto :goto_5

    .line 99
    :goto_3
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast p0, Lo8/o;

    .line 102
    .line 103
    if-nez p0, :cond_6

    .line 104
    .line 105
    iget-wide p2, v1, Lo8/l;->g:J

    .line 106
    .line 107
    cmp-long p0, p2, v3

    .line 108
    .line 109
    if-nez p0, :cond_5

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_5
    move p5, p6

    .line 113
    :cond_6
    :goto_4
    invoke-static {p5}, Lw7/a;->j(Z)V

    .line 114
    .line 115
    .line 116
    iput p6, v1, Lo8/l;->i:I

    .line 117
    .line 118
    throw p1

    .line 119
    :catch_0
    iget-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v0, Lo8/o;

    .line 122
    .line 123
    if-nez v0, :cond_4

    .line 124
    .line 125
    iget-wide v5, v1, Lo8/l;->g:J

    .line 126
    .line 127
    cmp-long v0, v5, v3

    .line 128
    .line 129
    if-nez v0, :cond_3

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :goto_5
    add-int/lit8 p7, p7, 0x1

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_7
    :goto_6
    iget-object p3, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p3, Lo8/o;

    .line 138
    .line 139
    if-eqz p3, :cond_8

    .line 140
    .line 141
    :goto_7
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p0, Lo8/o;

    .line 144
    .line 145
    invoke-interface {p0, p8}, Lo8/o;->c(Lo8/q;)V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_8
    new-instance p0, Lh8/f1;

    .line 150
    .line 151
    new-instance p3, Ljava/lang/StringBuilder;

    .line 152
    .line 153
    const-string p7, "None of the available extractors ("

    .line 154
    .line 155
    invoke-direct {p3, p7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    new-instance p7, Lgr/f;

    .line 159
    .line 160
    const-string p8, ", "

    .line 161
    .line 162
    invoke-direct {p7, p8, p6}, Lgr/f;-><init>(Ljava/lang/String;I)V

    .line 163
    .line 164
    .line 165
    invoke-static {p1}, Lhr/h0;->r([Ljava/lang/Object;)Lhr/x0;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    new-instance p8, Lf3/d;

    .line 170
    .line 171
    const/16 v0, 0x9

    .line 172
    .line 173
    invoke-direct {p8, v0}, Lf3/d;-><init>(I)V

    .line 174
    .line 175
    .line 176
    invoke-static {p1, p8}, Lhr/q;->s(Ljava/util/List;Lgr/e;)Ljava/util/AbstractList;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    new-instance p8, Ljava/lang/StringBuilder;

    .line 185
    .line 186
    invoke-direct {p8}, Ljava/lang/StringBuilder;-><init>()V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p7, p8, p1}, Lgr/f;->a(Ljava/lang/StringBuilder;Ljava/util/Iterator;)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {p8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    const-string p1, ") could read the stream."

    .line 200
    .line 201
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 209
    .line 210
    .line 211
    invoke-virtual {p4}, Lhr/e0;->i()Lhr/x0;

    .line 212
    .line 213
    .line 214
    move-result-object p2

    .line 215
    const/4 p3, 0x0

    .line 216
    invoke-direct {p0, p1, p3, p6, p5}, Lt7/e0;-><init>(Ljava/lang/String;Ljava/lang/Throwable;ZI)V

    .line 217
    .line 218
    .line 219
    invoke-static {p2}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 220
    .line 221
    .line 222
    throw p0
.end method

.method public r(ILh5/d;Li5/c;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Li5/b;

    .line 4
    .line 5
    iget-object v0, p2, Lh5/d;->q0:[I

    .line 6
    .line 7
    iget-object v1, p2, Lh5/d;->u:[I

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    aget v3, v0, v2

    .line 11
    .line 12
    iput v3, p0, Li5/b;->a:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    aget v0, v0, v3

    .line 16
    .line 17
    iput v0, p0, Li5/b;->b:I

    .line 18
    .line 19
    invoke-virtual {p2}, Lh5/d;->r()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iput v0, p0, Li5/b;->c:I

    .line 24
    .line 25
    invoke-virtual {p2}, Lh5/d;->l()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iput v0, p0, Li5/b;->d:I

    .line 30
    .line 31
    iput-boolean v2, p0, Li5/b;->i:Z

    .line 32
    .line 33
    iput p1, p0, Li5/b;->j:I

    .line 34
    .line 35
    iget p1, p0, Li5/b;->a:I

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    if-ne p1, v0, :cond_0

    .line 39
    .line 40
    move p1, v3

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move p1, v2

    .line 43
    :goto_0
    iget v4, p0, Li5/b;->b:I

    .line 44
    .line 45
    if-ne v4, v0, :cond_1

    .line 46
    .line 47
    move v0, v3

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move v0, v2

    .line 50
    :goto_1
    const/4 v4, 0x0

    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    iget p1, p2, Lh5/d;->X:F

    .line 54
    .line 55
    cmpl-float p1, p1, v4

    .line 56
    .line 57
    if-lez p1, :cond_2

    .line 58
    .line 59
    move p1, v3

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    move p1, v2

    .line 62
    :goto_2
    if-eqz v0, :cond_3

    .line 63
    .line 64
    iget v0, p2, Lh5/d;->X:F

    .line 65
    .line 66
    cmpl-float v0, v0, v4

    .line 67
    .line 68
    if-lez v0, :cond_3

    .line 69
    .line 70
    move v0, v3

    .line 71
    goto :goto_3

    .line 72
    :cond_3
    move v0, v2

    .line 73
    :goto_3
    const/4 v4, 0x4

    .line 74
    if-eqz p1, :cond_4

    .line 75
    .line 76
    aget p1, v1, v2

    .line 77
    .line 78
    if-ne p1, v4, :cond_4

    .line 79
    .line 80
    iput v3, p0, Li5/b;->a:I

    .line 81
    .line 82
    :cond_4
    if-eqz v0, :cond_5

    .line 83
    .line 84
    aget p1, v1, v3

    .line 85
    .line 86
    if-ne p1, v4, :cond_5

    .line 87
    .line 88
    iput v3, p0, Li5/b;->b:I

    .line 89
    .line 90
    :cond_5
    invoke-interface {p3, p2, p0}, Li5/c;->b(Lh5/d;Li5/b;)V

    .line 91
    .line 92
    .line 93
    iget p1, p0, Li5/b;->e:I

    .line 94
    .line 95
    invoke-virtual {p2, p1}, Lh5/d;->S(I)V

    .line 96
    .line 97
    .line 98
    iget p1, p0, Li5/b;->f:I

    .line 99
    .line 100
    invoke-virtual {p2, p1}, Lh5/d;->N(I)V

    .line 101
    .line 102
    .line 103
    iget-boolean p1, p0, Li5/b;->h:Z

    .line 104
    .line 105
    iput-boolean p1, p2, Lh5/d;->F:Z

    .line 106
    .line 107
    iget p1, p0, Li5/b;->g:I

    .line 108
    .line 109
    invoke-virtual {p2, p1}, Lh5/d;->J(I)V

    .line 110
    .line 111
    .line 112
    iput v2, p0, Li5/b;->j:I

    .line 113
    .line 114
    iget-boolean p0, p0, Li5/b;->i:Z

    .line 115
    .line 116
    return p0
.end method

.method public s(Ljava/lang/String;Lz41/g;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lrx0/c;)Ljava/io/Serializable;
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p4

    .line 4
    .line 5
    iget-object v2, v1, Lgw0/c;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lb81/c;

    .line 8
    .line 9
    instance-of v3, v0, Lc51/c;

    .line 10
    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lc51/c;

    .line 15
    .line 16
    iget v4, v3, Lc51/c;->h:I

    .line 17
    .line 18
    const/high16 v5, -0x80000000

    .line 19
    .line 20
    and-int v6, v4, v5

    .line 21
    .line 22
    if-eqz v6, :cond_0

    .line 23
    .line 24
    sub-int/2addr v4, v5

    .line 25
    iput v4, v3, Lc51/c;->h:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v3, Lc51/c;

    .line 29
    .line 30
    invoke-direct {v3, v1, v0}, Lc51/c;-><init>(Lgw0/c;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v0, v3, Lc51/c;->f:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v5, v3, Lc51/c;->h:I

    .line 38
    .line 39
    const/4 v6, 0x6

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x3

    .line 42
    const/4 v9, 0x2

    .line 43
    const/4 v10, 0x1

    .line 44
    if-eqz v5, :cond_4

    .line 45
    .line 46
    if-eq v5, v10, :cond_3

    .line 47
    .line 48
    if-eq v5, v9, :cond_2

    .line 49
    .line 50
    if-ne v5, v8, :cond_1

    .line 51
    .line 52
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto/16 :goto_9

    .line 56
    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto/16 :goto_6

    .line 69
    .line 70
    :cond_3
    iget-object v5, v3, Lc51/c;->e:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 71
    .line 72
    iget-object v11, v3, Lc51/c;->d:Lz41/g;

    .line 73
    .line 74
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    check-cast v0, Llx0/o;

    .line 78
    .line 79
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 86
    .line 87
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    iget-object v5, v0, Lx51/b;->d:La61/a;

    .line 91
    .line 92
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    new-instance v11, Lc00/f1;

    .line 100
    .line 101
    const/4 v12, 0x2

    .line 102
    invoke-direct {v11, v12}, Lc00/f1;-><init>(I)V

    .line 103
    .line 104
    .line 105
    invoke-static {v0, v5, v11, v6}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 106
    .line 107
    .line 108
    move-object/from16 v0, p2

    .line 109
    .line 110
    iput-object v0, v3, Lc51/c;->d:Lz41/g;

    .line 111
    .line 112
    move-object/from16 v5, p3

    .line 113
    .line 114
    iput-object v5, v3, Lc51/c;->e:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 115
    .line 116
    iput v10, v3, Lc51/c;->h:I

    .line 117
    .line 118
    move-object/from16 v11, p1

    .line 119
    .line 120
    invoke-virtual {v1, v11, v3}, Lgw0/c;->n(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v11

    .line 124
    if-ne v11, v4, :cond_5

    .line 125
    .line 126
    goto/16 :goto_8

    .line 127
    .line 128
    :cond_5
    move-object/from16 v18, v11

    .line 129
    .line 130
    move-object v11, v0

    .line 131
    move-object/from16 v0, v18

    .line 132
    .line 133
    :goto_1
    instance-of v12, v0, Llx0/n;

    .line 134
    .line 135
    if-nez v12, :cond_6

    .line 136
    .line 137
    check-cast v0, Le51/h;

    .line 138
    .line 139
    iget-object v0, v0, Le51/h;->a:Ljava/lang/String;

    .line 140
    .line 141
    :cond_6
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 142
    .line 143
    .line 144
    move-result-object v12

    .line 145
    if-nez v12, :cond_c

    .line 146
    .line 147
    move-object v13, v0

    .line 148
    check-cast v13, Ljava/lang/String;

    .line 149
    .line 150
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 151
    .line 152
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v12

    .line 156
    new-instance v14, Lc00/f1;

    .line 157
    .line 158
    const/4 v15, 0x3

    .line 159
    invoke-direct {v14, v15}, Lc00/f1;-><init>(I)V

    .line 160
    .line 161
    .line 162
    invoke-static {v0, v12, v14, v6}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 163
    .line 164
    .line 165
    iget-object v12, v0, Lx51/b;->d:La61/a;

    .line 166
    .line 167
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v14

    .line 171
    new-instance v15, Lc00/f1;

    .line 172
    .line 173
    const/4 v8, 0x4

    .line 174
    invoke-direct {v15, v8}, Lc00/f1;-><init>(I)V

    .line 175
    .line 176
    .line 177
    invoke-static {v0, v14, v15, v6}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 178
    .line 179
    .line 180
    iget-object v0, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 181
    .line 182
    move-object v8, v0

    .line 183
    check-cast v8, Lb81/b;

    .line 184
    .line 185
    iput-object v7, v3, Lc51/c;->d:Lz41/g;

    .line 186
    .line 187
    iput-object v7, v3, Lc51/c;->e:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 188
    .line 189
    iput v9, v3, Lc51/c;->h:I

    .line 190
    .line 191
    invoke-static {v8}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 195
    .line 196
    .line 197
    iget-object v0, v8, Lb81/b;->e:Ljava/lang/Object;

    .line 198
    .line 199
    move-object v14, v0

    .line 200
    check-cast v14, Lj51/h;

    .line 201
    .line 202
    iget-object v0, v11, Lz41/g;->d:Ljava/lang/String;

    .line 203
    .line 204
    iget-object v11, v8, Lb81/b;->f:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v11, Ljava/util/EnumSet;

    .line 207
    .line 208
    const-string v15, "allowedCapabilities"

    .line 209
    .line 210
    invoke-static {v11, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    const-string v15, "pairingPassword"

    .line 214
    .line 215
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    const-string v15, "activity"

    .line 219
    .line 220
    invoke-static {v5, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    invoke-static {v14}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 227
    .line 228
    .line 229
    :try_start_0
    iget-object v12, v14, Lj51/h;->a:Lxo/g;

    .line 230
    .line 231
    new-instance v15, Ljava/util/LinkedHashSet;

    .line 232
    .line 233
    invoke-direct {v15}, Ljava/util/LinkedHashSet;-><init>()V

    .line 234
    .line 235
    .line 236
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 237
    .line 238
    .line 239
    move-result-object v11

    .line 240
    :goto_2
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 241
    .line 242
    .line 243
    move-result v16

    .line 244
    const/4 v7, 0x0

    .line 245
    if-eqz v16, :cond_a

    .line 246
    .line 247
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v16

    .line 251
    check-cast v16, La51/b;

    .line 252
    .line 253
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Enum;->ordinal()I

    .line 254
    .line 255
    .line 256
    move-result v6

    .line 257
    if-eqz v6, :cond_9

    .line 258
    .line 259
    if-eq v6, v10, :cond_8

    .line 260
    .line 261
    if-ne v6, v9, :cond_7

    .line 262
    .line 263
    move v7, v10

    .line 264
    goto :goto_3

    .line 265
    :cond_7
    new-instance v0, La8/r0;

    .line 266
    .line 267
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 268
    .line 269
    .line 270
    throw v0

    .line 271
    :cond_8
    move v7, v9

    .line 272
    :cond_9
    :goto_3
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 273
    .line 274
    .line 275
    move-result-object v6

    .line 276
    invoke-interface {v15, v6}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    const/4 v6, 0x6

    .line 280
    const/4 v7, 0x0

    .line 281
    goto :goto_2

    .line 282
    :catch_0
    move-exception v0

    .line 283
    move-object v5, v14

    .line 284
    goto :goto_4

    .line 285
    :cond_a
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 286
    .line 287
    .line 288
    move-result-object v6

    .line 289
    sget-object v9, Lwo/g;->b:Ljo/d;

    .line 290
    .line 291
    filled-new-array {v9}, [Ljo/d;

    .line 292
    .line 293
    .line 294
    move-result-object v9

    .line 295
    iput-object v9, v6, Lh6/i;->e:Ljava/lang/Object;

    .line 296
    .line 297
    move-object v9, v12

    .line 298
    new-instance v12, Lun/a;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 299
    .line 300
    const/16 v17, 0x7

    .line 301
    .line 302
    move-object/from16 v16, v5

    .line 303
    .line 304
    move-object v5, v14

    .line 305
    move-object v14, v0

    .line 306
    :try_start_1
    invoke-direct/range {v12 .. v17}, Lun/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 307
    .line 308
    .line 309
    iput-object v12, v6, Lh6/i;->d:Ljava/lang/Object;

    .line 310
    .line 311
    const v0, 0x8859

    .line 312
    .line 313
    .line 314
    iput v0, v6, Lh6/i;->b:I

    .line 315
    .line 316
    invoke-virtual {v6}, Lh6/i;->a()Lbp/s;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    invoke-virtual {v9, v7, v0}, Lko/i;->e(ILhr/b0;)Laq/t;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 321
    .line 322
    .line 323
    const/4 v0, 0x0

    .line 324
    goto :goto_5

    .line 325
    :catch_1
    move-exception v0

    .line 326
    :goto_4
    sget-object v6, Lx51/c;->o1:Lx51/b;

    .line 327
    .line 328
    invoke-static {v5}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 329
    .line 330
    .line 331
    iget-object v5, v6, Lx51/b;->d:La61/a;

    .line 332
    .line 333
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 334
    .line 335
    .line 336
    new-instance v5, Lz41/a;

    .line 337
    .line 338
    const-string v6, "Key creation could not be started by DigitalKeyLibrary due to an exception."

    .line 339
    .line 340
    invoke-direct {v5, v6, v0}, Lz41/e;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 341
    .line 342
    .line 343
    move-object v0, v5

    .line 344
    :goto_5
    sget-object v5, Lx51/c;->o1:Lx51/b;

    .line 345
    .line 346
    invoke-static {v8}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    iget-object v5, v5, Lx51/b;->d:La61/a;

    .line 350
    .line 351
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 352
    .line 353
    .line 354
    if-ne v0, v4, :cond_b

    .line 355
    .line 356
    goto :goto_8

    .line 357
    :cond_b
    :goto_6
    check-cast v0, Lz41/e;

    .line 358
    .line 359
    goto :goto_7

    .line 360
    :cond_c
    move-object v0, v12

    .line 361
    check-cast v0, Lz41/e;

    .line 362
    .line 363
    :goto_7
    if-nez v0, :cond_f

    .line 364
    .line 365
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 366
    .line 367
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object v5

    .line 371
    new-instance v6, Lc00/f1;

    .line 372
    .line 373
    const/4 v7, 0x5

    .line 374
    invoke-direct {v6, v7}, Lc00/f1;-><init>(I)V

    .line 375
    .line 376
    .line 377
    const/4 v7, 0x6

    .line 378
    invoke-static {v0, v5, v6, v7}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 379
    .line 380
    .line 381
    iget-object v0, v2, Lb81/c;->f:Ljava/lang/Object;

    .line 382
    .line 383
    check-cast v0, Lyy0/l1;

    .line 384
    .line 385
    new-instance v5, Lrz/k;

    .line 386
    .line 387
    const/16 v6, 0x15

    .line 388
    .line 389
    invoke-direct {v5, v0, v6}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 390
    .line 391
    .line 392
    const/4 v6, 0x0

    .line 393
    iput-object v6, v3, Lc51/c;->d:Lz41/g;

    .line 394
    .line 395
    iput-object v6, v3, Lc51/c;->e:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 396
    .line 397
    const/4 v6, 0x3

    .line 398
    iput v6, v3, Lc51/c;->h:I

    .line 399
    .line 400
    invoke-static {v5, v3}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v0

    .line 404
    if-ne v0, v4, :cond_d

    .line 405
    .line 406
    :goto_8
    return-object v4

    .line 407
    :cond_d
    :goto_9
    check-cast v0, Llx0/o;

    .line 408
    .line 409
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 410
    .line 411
    sget-object v3, Lx51/c;->o1:Lx51/b;

    .line 412
    .line 413
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 414
    .line 415
    .line 416
    iget-object v4, v3, Lx51/b;->d:La61/a;

    .line 417
    .line 418
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 419
    .line 420
    .line 421
    invoke-static {v2}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    iget-object v4, v3, Lx51/b;->d:La61/a;

    .line 425
    .line 426
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 427
    .line 428
    .line 429
    iget-object v2, v2, Lb81/c;->e:Ljava/lang/Object;

    .line 430
    .line 431
    check-cast v2, Lyy0/c2;

    .line 432
    .line 433
    const/4 v6, 0x0

    .line 434
    invoke-virtual {v2, v6}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 435
    .line 436
    .line 437
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    instance-of v2, v0, Lz41/e;

    .line 442
    .line 443
    if-eqz v2, :cond_e

    .line 444
    .line 445
    move-object v7, v0

    .line 446
    check-cast v7, Lz41/e;

    .line 447
    .line 448
    goto :goto_a

    .line 449
    :cond_e
    move-object v7, v6

    .line 450
    :goto_a
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v0

    .line 454
    new-instance v1, Lc51/a;

    .line 455
    .line 456
    const/4 v2, 0x0

    .line 457
    invoke-direct {v1, v7, v2}, Lc51/a;-><init>(Lz41/e;I)V

    .line 458
    .line 459
    .line 460
    const/4 v2, 0x6

    .line 461
    invoke-static {v3, v0, v1, v2}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 462
    .line 463
    .line 464
    move-object v0, v7

    .line 465
    goto :goto_b

    .line 466
    :cond_f
    const/4 v2, 0x6

    .line 467
    sget-object v3, Lx51/c;->o1:Lx51/b;

    .line 468
    .line 469
    invoke-static {v1}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 470
    .line 471
    .line 472
    move-result-object v1

    .line 473
    new-instance v4, Lc51/a;

    .line 474
    .line 475
    const/4 v5, 0x1

    .line 476
    invoke-direct {v4, v0, v5}, Lc51/a;-><init>(Lz41/e;I)V

    .line 477
    .line 478
    .line 479
    invoke-static {v3, v1, v4, v2}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 480
    .line 481
    .line 482
    :goto_b
    return-object v0
.end method

.method public t(Landroidx/lifecycle/p;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/lifecycle/a1;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Landroidx/lifecycle/a1;->run()V

    .line 8
    .line 9
    .line 10
    :cond_0
    new-instance v0, Landroidx/lifecycle/a1;

    .line 11
    .line 12
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Landroidx/lifecycle/z;

    .line 15
    .line 16
    invoke-direct {v0, v1, p1}, Landroidx/lifecycle/a1;-><init>(Landroidx/lifecycle/z;Landroidx/lifecycle/p;)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 20
    .line 21
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Landroid/os/Handler;

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Landroid/os/Handler;->postAtFrontOfQueue(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lgw0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const/16 v1, 0x20

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const/16 v1, 0x7b

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lvp/y1;

    .line 33
    .line 34
    iget-object p0, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lvp/y1;

    .line 37
    .line 38
    const-string v1, ""

    .line 39
    .line 40
    :goto_0
    if-eqz p0, :cond_1

    .line 41
    .line 42
    iget-object v2, p0, Lvp/y1;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v2, Lvp/y1;

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    if-eqz v2, :cond_0

    .line 50
    .line 51
    const-class v1, Lvp/y1;

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/Class;->isArray()Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-eqz v1, :cond_0

    .line 58
    .line 59
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-static {v1}, Ljava/util/Arrays;->deepToString([Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    const/4 v3, 0x1

    .line 72
    sub-int/2addr v2, v3

    .line 73
    invoke-virtual {v0, v1, v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_0
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    :goto_1
    iget-object p0, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast p0, Lvp/y1;

    .line 83
    .line 84
    const-string v1, ", "

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_1
    const/16 p0, 0x7d

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :pswitch_data_0
    .packed-switch 0x13
        :pswitch_0
    .end packed-switch
.end method

.method public u(Landroid/media/MediaCodec;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashSet;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Landroid/media/LoudnessCodecController;

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-static {p0, p1}, Lf8/a;->f(Landroid/media/LoudnessCodecController;Landroid/media/MediaCodec;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public v(Lh21/a;Lhy0/d;Lh21/a;Lu/x0;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "clazz"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "scopeQualifier"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    const/16 v1, 0x3a

    .line 17
    .line 18
    invoke-static {p2, v0, v1}, Lia/b;->s(Lhy0/d;Ljava/lang/StringBuilder;C)V

    .line 19
    .line 20
    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    invoke-interface {p1}, Lh21/a;->getValue()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    :cond_0
    const-string p1, ""

    .line 30
    .line 31
    :cond_1
    invoke-static {v0, p1, v1, p3}, Lia/b;->h(Ljava/lang/StringBuilder;Ljava/lang/String;CLh21/a;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Lc21/b;

    .line 44
    .line 45
    const/4 p1, 0x0

    .line 46
    if-eqz p0, :cond_2

    .line 47
    .line 48
    invoke-virtual {p0, p4}, Lc21/b;->c(Lu/x0;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    goto :goto_0

    .line 53
    :cond_2
    move-object p0, p1

    .line 54
    :goto_0
    if-nez p0, :cond_3

    .line 55
    .line 56
    return-object p1

    .line 57
    :cond_3
    return-object p0
.end method

.method public w(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/media/LoudnessCodecController;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {v0}, Lf8/a;->e(Landroid/media/LoudnessCodecController;)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 12
    .line 13
    :cond_0
    new-instance v0, Lf8/j;

    .line 14
    .line 15
    invoke-direct {v0, p0}, Lf8/j;-><init>(Lgw0/c;)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1, v0}, Lf8/a;->c(ILf8/j;)Landroid/media/LoudnessCodecController;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 23
    .line 24
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Ljava/util/HashSet;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_2

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Landroid/media/MediaCodec;

    .line 43
    .line 44
    invoke-static {p1, v0}, Lf8/a;->k(Landroid/media/LoudnessCodecController;Landroid/media/MediaCodec;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_1

    .line 49
    .line 50
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    return-void
.end method

.method public x(Le3/r;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iput-object p1, p0, Lg3/a;->c:Le3/r;

    .line 8
    .line 9
    return-void
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ly4/h;

    .line 4
    .line 5
    instance-of v1, p1, Ljava/util/concurrent/CancellationException;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    new-instance v1, Lb0/v1;

    .line 11
    .line 12
    new-instance v3, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Ljava/lang/String;

    .line 20
    .line 21
    const-string v4, " cancelled."

    .line 22
    .line 23
    invoke-static {v3, p0, v4}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-direct {v1, p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    invoke-static {v2, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    invoke-virtual {v0, v2}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public z(Lt4/c;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg3/b;

    .line 4
    .line 5
    iget-object p0, p0, Lg3/b;->d:Lg3/a;

    .line 6
    .line 7
    iput-object p1, p0, Lg3/a;->a:Lt4/c;

    .line 8
    .line 9
    return-void
.end method
