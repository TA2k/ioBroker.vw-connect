.class public final synthetic Lu/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lu/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private final a()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    .line 1
    iget p0, p0, Lu/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget p0, Lcom/google/android/datatransport/runtime/scheduling/jobscheduling/AlarmManagerSchedulerBroadcastReceiver;->a:I

    .line 7
    .line 8
    return-void

    .line 9
    :pswitch_0
    sget-object p0, Lw3/t;->W1:Landroidx/collection/l0;

    .line 10
    .line 11
    monitor-enter p0

    .line 12
    :try_start_0
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 13
    .line 14
    const/16 v1, 0x1e

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    if-ge v0, v1, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 20
    .line 21
    iget v1, p0, Landroidx/collection/l0;->b:I

    .line 22
    .line 23
    :goto_0
    if-ge v2, v1, :cond_2

    .line 24
    .line 25
    aget-object v3, v0, v2

    .line 26
    .line 27
    check-cast v3, Lw3/t;

    .line 28
    .line 29
    invoke-virtual {v3}, Lw3/t;->getShowLayoutBounds()Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    sget-object v5, Lw3/t;->T1:Ljava/lang/Class;

    .line 34
    .line 35
    invoke-static {}, Lw3/h0;->u()Z

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    invoke-virtual {v3, v5}, Lw3/t;->setShowLayoutBounds(Z)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v3}, Lw3/t;->getShowLayoutBounds()Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    if-eq v4, v5, :cond_0

    .line 47
    .line 48
    invoke-virtual {v3}, Lw3/t;->getRoot()Lv3/h0;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-static {v3}, Lw3/t;->k(Lv3/h0;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_0
    move-exception v0

    .line 59
    goto :goto_2

    .line 60
    :cond_1
    iget-object v0, p0, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 61
    .line 62
    iget v1, p0, Landroidx/collection/l0;->b:I

    .line 63
    .line 64
    :goto_1
    if-ge v2, v1, :cond_2

    .line 65
    .line 66
    aget-object v3, v0, v2

    .line 67
    .line 68
    check-cast v3, Lw3/t;

    .line 69
    .line 70
    invoke-virtual {v3}, Lw3/t;->getRoot()Lv3/h0;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-static {v3}, Lw3/t;->k(Lv3/h0;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    .line 76
    .line 77
    add-int/lit8 v2, v2, 0x1

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_2
    monitor-exit p0

    .line 81
    return-void

    .line 82
    :goto_2
    monitor-exit p0

    .line 83
    throw v0

    .line 84
    :pswitch_1
    return-void

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
