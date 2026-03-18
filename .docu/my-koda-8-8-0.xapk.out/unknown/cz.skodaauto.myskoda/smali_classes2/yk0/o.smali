.class public final synthetic Lyk0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxj0/f;


# direct methods
.method public synthetic constructor <init>(Lxj0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyk0/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyk0/o;->e:Lxj0/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lyk0/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Luu/g;

    .line 7
    .line 8
    const-string v0, "$this$rememberCameraPositionState"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lyk0/o;->e:Lxj0/f;

    .line 14
    .line 15
    invoke-static {p0}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    new-instance v0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    const v2, 0x417b3333    # 15.7f

    .line 23
    .line 24
    .line 25
    invoke-direct {v0, p0, v2, v1, v1}, Lcom/google/android/gms/maps/model/CameraPosition;-><init>(Lcom/google/android/gms/maps/model/LatLng;FFF)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1, v0}, Luu/g;->g(Lcom/google/android/gms/maps/model/CameraPosition;)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/PlaceDto;

    .line 35
    .line 36
    const-string v0, "$this$request"

    .line 37
    .line 38
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance v1, Lbl0/n;

    .line 42
    .line 43
    invoke-virtual {p1}, Lcz/myskoda/api/bff_maps/v3/PlaceDto;->getId()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {p1}, Lcz/myskoda/api/bff_maps/v3/PlaceDto;->getShortAddress()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    if-nez v0, :cond_0

    .line 52
    .line 53
    const-string v0, ""

    .line 54
    .line 55
    :cond_0
    move-object v3, v0

    .line 56
    invoke-virtual {p1}, Lcz/myskoda/api/bff_maps/v3/PlaceDto;->getFormattedAddress()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    invoke-virtual {p1}, Lcz/myskoda/api/bff_maps/v3/PlaceDto;->getTravelData()Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-eqz v0, :cond_1

    .line 65
    .line 66
    invoke-static {v0}, Llp/zf;->d(Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)Loo0/b;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    :goto_0
    move-object v7, v0

    .line 71
    goto :goto_1

    .line 72
    :cond_1
    const/4 v0, 0x0

    .line 73
    goto :goto_0

    .line 74
    :goto_1
    invoke-virtual {p1}, Lcz/myskoda/api/bff_maps/v3/PlaceDto;->getFavouritePlaceId()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    const/4 v4, 0x0

    .line 79
    iget-object v6, p0, Lyk0/o;->e:Lxj0/f;

    .line 80
    .line 81
    invoke-direct/range {v1 .. v8}, Lbl0/n;-><init>(Ljava/lang/String;Ljava/lang/String;Lbl0/a;Ljava/lang/String;Lxj0/f;Loo0/b;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    return-object v1

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
