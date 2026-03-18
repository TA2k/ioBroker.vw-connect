.class public final Lcq/n0;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcq/n0;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcq/v0;

.field public final e:[Landroid/content/IntentFilter;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcq/x0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lcq/x0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcq/n0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/os/IBinder;[Landroid/content/IntentFilter;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_1

    .line 2
    const-string v0, "com.google.android.gms.wearable.internal.IWearableListener"

    .line 3
    invoke-interface {p1, v0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    move-result-object v0

    instance-of v1, v0, Lcq/v0;

    if-eqz v1, :cond_0

    .line 4
    check-cast v0, Lcq/v0;

    goto :goto_0

    :cond_0
    new-instance v0, Lcq/u0;

    .line 5
    const-string v1, "com.google.android.gms.wearable.internal.IWearableListener"

    const/16 v2, 0x8

    invoke-direct {v0, p1, v1, v2}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    .line 6
    :goto_0
    iput-object v0, p0, Lcq/n0;->d:Lcq/v0;

    iput-object p2, p0, Lcq/n0;->e:[Landroid/content/IntentFilter;

    iput-object p3, p0, Lcq/n0;->f:Ljava/lang/String;

    iput-object p4, p0, Lcq/n0;->g:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Lcq/u1;)V
    .locals 0

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lcq/n0;->d:Lcq/v0;

    .line 9
    iget-object p1, p1, Lcq/u1;->e:[Landroid/content/IntentFilter;

    .line 10
    iput-object p1, p0, Lcq/n0;->e:[Landroid/content/IntentFilter;

    const/4 p1, 0x0

    .line 11
    iput-object p1, p0, Lcq/n0;->f:Ljava/lang/String;

    iput-object p1, p0, Lcq/n0;->g:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcq/n0;->d:Lcq/v0;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-interface {v1}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :goto_0
    const/4 v2, 0x2

    .line 18
    invoke-static {p1, v2, v1}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 19
    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    iget-object v2, p0, Lcq/n0;->e:[Landroid/content/IntentFilter;

    .line 23
    .line 24
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 25
    .line 26
    .line 27
    const/4 p2, 0x4

    .line 28
    iget-object v1, p0, Lcq/n0;->f:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {p1, v1, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    const/4 p2, 0x5

    .line 34
    iget-object p0, p0, Lcq/n0;->g:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {p1, p0, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 40
    .line 41
    .line 42
    return-void
.end method
