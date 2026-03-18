.class public final Lhg0/e;
.super Ljava/util/TimerTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhg0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhg0/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/util/TimerTask;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lhg0/e;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lhg0/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/lang/Runnable;

    .line 9
    .line 10
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p0, Lhg0/g;

    .line 15
    .line 16
    iget-object v0, p0, Lhg0/g;->i:Landroid/location/LocationManager;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    sget v2, Lw5/a;->a:I

    .line 22
    .line 23
    invoke-virtual {v0}, Landroid/location/LocationManager;->isLocationEnabled()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    sget-object v0, Lgg0/b;->d:Lgg0/b;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    sget-object v0, Lgg0/b;->e:Lgg0/b;

    .line 33
    .line 34
    :goto_0
    iget-object p0, p0, Lhg0/g;->a:Ldg0/a;

    .line 35
    .line 36
    iget-object v2, p0, Ldg0/a;->e:Lyy0/c2;

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    sget-object v2, Lgg0/b;->e:Lgg0/b;

    .line 45
    .line 46
    if-ne v0, v2, :cond_1

    .line 47
    .line 48
    iget-object p0, p0, Ldg0/a;->a:Lyy0/c2;

    .line 49
    .line 50
    invoke-virtual {p0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    return-void

    .line 54
    :cond_2
    const-string p0, "locationManager"

    .line 55
    .line 56
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw v1

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
