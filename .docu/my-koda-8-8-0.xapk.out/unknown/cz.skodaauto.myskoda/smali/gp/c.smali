.class public final Lgp/c;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgp/u;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Laq/k;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.location.internal.IFusedLocationProviderCallback"

    const/4 v1, 0x5

    invoke-direct {p0, v0, v1}, Lbp/j;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public constructor <init>(Laq/k;Lgp/e;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lgp/c;->d:I

    .line 2
    iput-object p1, p0, Lgp/c;->e:Laq/k;

    iput-object p2, p0, Lgp/c;->f:Ljava/lang/Object;

    invoke-direct {p0}, Lgp/c;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Boolean;Laq/k;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lgp/c;->d:I

    .line 3
    iput-object p1, p0, Lgp/c;->f:Ljava/lang/Object;

    iput-object p2, p0, Lgp/c;->e:Laq/k;

    invoke-direct {p0}, Lgp/c;-><init>()V

    return-void
.end method

.method private final T()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final C(Lgp/s;)V
    .locals 1

    .line 1
    iget v0, p0, Lgp/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p1, Lgp/s;->d:Lcom/google/android/gms/common/api/Status;

    .line 7
    .line 8
    iget-object v0, p0, Lgp/c;->f:Ljava/lang/Object;

    .line 9
    .line 10
    iget-object p0, p0, Lgp/c;->e:Laq/k;

    .line 11
    .line 12
    invoke-static {p1, v0, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object p1, p1, Lgp/s;->d:Lcom/google/android/gms/common/api/Status;

    .line 17
    .line 18
    iget-object p0, p0, Lgp/c;->e:Laq/k;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-static {p1, v0, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final S(Landroid/os/Parcel;I)Z
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p2, v0, :cond_1

    .line 3
    .line 4
    const/4 p1, 0x2

    .line 5
    if-eq p2, p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-interface {p0}, Lgp/u;->k()V

    .line 10
    .line 11
    .line 12
    return v0

    .line 13
    :cond_1
    sget-object p2, Lgp/s;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 14
    .line 15
    invoke-static {p1, p2}, Lgp/b;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    check-cast p2, Lgp/s;

    .line 20
    .line 21
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p0, p2}, Lgp/u;->C(Lgp/s;)V

    .line 25
    .line 26
    .line 27
    return v0
.end method

.method public final k()V
    .locals 1

    .line 1
    iget v0, p0, Lgp/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lgp/c;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lgp/e;

    .line 10
    .line 11
    invoke-virtual {p0}, Lgp/e;->T()V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
