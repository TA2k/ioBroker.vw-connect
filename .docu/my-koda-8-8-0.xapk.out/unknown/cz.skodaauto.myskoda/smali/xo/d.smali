.class public final Lxo/d;
.super Llo/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/ref/WeakReference;

.field public final e:I


# direct methods
.method public constructor <init>(Landroid/app/Activity;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Llo/h;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 5
    .line 6
    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lxo/d;->d:Ljava/lang/ref/WeakReference;

    .line 10
    .line 11
    const p1, 0x8000

    .line 12
    .line 13
    .line 14
    iput p1, p0, Lxo/d;->e:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final A(Lcom/google/android/gms/common/api/Status;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lxo/d;->d:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/app/Activity;

    .line 8
    .line 9
    const-string v1, "DigitalKeyFramework"

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    const-string p0, "Ignoring onHandlePendingIntent, Activity is gone"

    .line 14
    .line 15
    invoke-static {v1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object v2, p1, Lcom/google/android/gms/common/api/Status;->f:Landroid/app/PendingIntent;

    .line 20
    .line 21
    iget p0, p0, Lxo/d;->e:I

    .line 22
    .line 23
    if-eqz v2, :cond_1

    .line 24
    .line 25
    :try_start_0
    invoke-virtual {p1, v0, p0}, Lcom/google/android/gms/common/api/Status;->y0(Landroid/app/Activity;I)V
    :try_end_0
    .catch Landroid/content/IntentSender$SendIntentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :catch_0
    move-exception v2

    .line 30
    const-string v3, "Exception starting pending intent"

    .line 31
    .line 32
    invoke-static {v1, v3, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 33
    .line 34
    .line 35
    :cond_1
    new-instance v2, Landroid/content/Intent;

    .line 36
    .line 37
    invoke-direct {v2}, Landroid/content/Intent;-><init>()V

    .line 38
    .line 39
    .line 40
    const/high16 v3, 0x40000000    # 2.0f

    .line 41
    .line 42
    invoke-virtual {v0, p0, v2, v3}, Landroid/app/Activity;->createPendingResult(ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-nez p0, :cond_2

    .line 47
    .line 48
    const-string p0, "Null pending result returned for onHandleStatusPendingIntent"

    .line 49
    .line 50
    invoke-static {v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :cond_2
    :try_start_1
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    const/4 p1, -0x1

    .line 61
    goto :goto_0

    .line 62
    :cond_3
    iget p1, p1, Lcom/google/android/gms/common/api/Status;->d:I

    .line 63
    .line 64
    :goto_0
    invoke-virtual {p0, p1}, Landroid/app/PendingIntent;->send(I)V
    :try_end_1
    .catch Landroid/app/PendingIntent$CanceledException; {:try_start_1 .. :try_end_1} :catch_1

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :catch_1
    move-exception p0

    .line 69
    const-string p1, "Exception setting pending result"

    .line 70
    .line 71
    invoke-static {v1, p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 72
    .line 73
    .line 74
    return-void
.end method
