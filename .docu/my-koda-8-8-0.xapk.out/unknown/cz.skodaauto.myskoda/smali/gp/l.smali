.class public final Lgp/l;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lgp/l;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lgp/q;

.field public final e:Landroid/app/PendingIntent;

.field public final f:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgl/c;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgl/c;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lgp/l;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/util/List;Landroid/app/PendingIntent;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    sget-object p1, Lgp/q;->e:Lgp/o;

    .line 7
    .line 8
    sget-object p1, Lgp/r;->h:Lgp/r;

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    check-cast p1, Ljava/util/List;

    .line 12
    .line 13
    invoke-static {p1}, Lgp/q;->n(Ljava/util/List;)Lgp/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    :goto_0
    iput-object p1, p0, Lgp/l;->d:Lgp/q;

    .line 18
    .line 19
    iput-object p2, p0, Lgp/l;->e:Landroid/app/PendingIntent;

    .line 20
    .line 21
    iput-object p3, p0, Lgp/l;->f:Ljava/lang/String;

    .line 22
    .line 23
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
    const/4 v1, 0x1

    .line 8
    iget-object v2, p0, Lgp/l;->d:Lgp/q;

    .line 9
    .line 10
    invoke-static {p1, v1, v2}, Ljp/dc;->p(Landroid/os/Parcel;ILjava/util/List;)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    iget-object v2, p0, Lgp/l;->e:Landroid/app/PendingIntent;

    .line 15
    .line 16
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 17
    .line 18
    .line 19
    const/4 p2, 0x3

    .line 20
    iget-object p0, p0, Lgp/l;->f:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p1, p0, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
