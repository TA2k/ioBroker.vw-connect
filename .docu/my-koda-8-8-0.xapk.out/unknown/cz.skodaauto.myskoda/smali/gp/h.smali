.class public final Lgp/h;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lgp/h;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:Landroid/os/IBinder;

.field public final f:Landroid/os/IBinder;

.field public final g:Landroid/app/PendingIntent;

.field public final h:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgl/c;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Lgl/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lgp/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(ILandroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lgp/h;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Lgp/h;->e:Landroid/os/IBinder;

    .line 7
    .line 8
    iput-object p3, p0, Lgp/h;->f:Landroid/os/IBinder;

    .line 9
    .line 10
    iput-object p4, p0, Lgp/h;->g:Landroid/app/PendingIntent;

    .line 11
    .line 12
    iput-object p5, p0, Lgp/h;->h:Ljava/lang/String;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

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
    const/4 v1, 0x1

    .line 8
    const/4 v2, 0x4

    .line 9
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 10
    .line 11
    .line 12
    iget v1, p0, Lgp/h;->d:I

    .line 13
    .line 14
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    iget-object v3, p0, Lgp/h;->e:Landroid/os/IBinder;

    .line 19
    .line 20
    invoke-static {p1, v1, v3}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 21
    .line 22
    .line 23
    const/4 v1, 0x3

    .line 24
    iget-object v3, p0, Lgp/h;->f:Landroid/os/IBinder;

    .line 25
    .line 26
    invoke-static {p1, v1, v3}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Lgp/h;->g:Landroid/app/PendingIntent;

    .line 30
    .line 31
    invoke-static {p1, v2, v1, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 32
    .line 33
    .line 34
    const/4 p2, 0x6

    .line 35
    iget-object p0, p0, Lgp/h;->h:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {p1, p0, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 41
    .line 42
    .line 43
    return-void
.end method
