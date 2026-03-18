.class public final synthetic Lcf/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lcf/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcf/a;->f:Lay0/a;

    iput-object p2, p0, Lcf/a;->e:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lay0/a;I)V
    .locals 0

    .line 2
    iput p3, p0, Lcf/a;->d:I

    iput-object p1, p0, Lcf/a;->e:Lay0/k;

    iput-object p2, p0, Lcf/a;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lcf/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lcom/google/android/gms/maps/model/LatLng;

    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lxj0/h;

    .line 14
    .line 15
    new-instance v1, Lxj0/f;

    .line 16
    .line 17
    iget-wide v2, p1, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 18
    .line 19
    iget-wide v4, p1, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 20
    .line 21
    invoke-direct {v1, v2, v3, v4, v5}, Lxj0/f;-><init>(DD)V

    .line 22
    .line 23
    .line 24
    invoke-direct {v0, v1}, Lxj0/h;-><init>(Lxj0/f;)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lcf/a;->e:Lay0/k;

    .line 28
    .line 29
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lcf/a;->f:Lay0/a;

    .line 33
    .line 34
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    check-cast p1, Lcom/google/android/gms/maps/model/LatLng;

    .line 41
    .line 42
    const-string v0, "it"

    .line 43
    .line 44
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Lxj0/g;

    .line 48
    .line 49
    new-instance v1, Lxj0/f;

    .line 50
    .line 51
    iget-wide v2, p1, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 52
    .line 53
    iget-wide v4, p1, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 54
    .line 55
    invoke-direct {v1, v2, v3, v4, v5}, Lxj0/f;-><init>(DD)V

    .line 56
    .line 57
    .line 58
    invoke-direct {v0, v1}, Lxj0/g;-><init>(Lxj0/f;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p0, Lcf/a;->e:Lay0/k;

    .line 62
    .line 63
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Lcf/a;->f:Lay0/a;

    .line 67
    .line 68
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_1
    check-cast p1, Lhi/a;

    .line 73
    .line 74
    const-string v0, "$this$sdkViewModel"

    .line 75
    .line 76
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    new-instance p1, Lcf/e;

    .line 80
    .line 81
    iget-object v0, p0, Lcf/a;->f:Lay0/a;

    .line 82
    .line 83
    iget-object p0, p0, Lcf/a;->e:Lay0/k;

    .line 84
    .line 85
    invoke-direct {p1, v0, p0}, Lcf/e;-><init>(Lay0/a;Lay0/k;)V

    .line 86
    .line 87
    .line 88
    return-object p1

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
