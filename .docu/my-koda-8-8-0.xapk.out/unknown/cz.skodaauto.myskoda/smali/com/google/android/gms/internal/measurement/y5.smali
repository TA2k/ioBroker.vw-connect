.class public final Lcom/google/android/gms/internal/measurement/y5;
.super Lcom/google/android/gms/internal/measurement/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/gms/internal/measurement/y5;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/i;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/firebase/messaging/w;Ljava/util/List;)Lcom/google/android/gms/internal/measurement/o;
    .locals 0

    .line 1
    iget p1, p0, Lcom/google/android/gms/internal/measurement/y5;->f:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-instance p0, Lcom/google/android/gms/internal/measurement/h;

    .line 10
    .line 11
    const-wide/16 p1, 0x0

    .line 12
    .line 13
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 18
    .line 19
    .line 20
    :pswitch_1
    return-object p0

    .line 21
    :pswitch_2
    sget-object p0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 22
    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
