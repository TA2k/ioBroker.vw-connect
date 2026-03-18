.class public final Lbq/i;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lbq/i;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/util/List;

.field public final e:Ljava/util/List;

.field public final f:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsp/w;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lsp/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lbq/i;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbq/i;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Lbq/i;->e:Ljava/util/List;

    .line 7
    .line 8
    iput-object p3, p0, Lbq/i;->f:Ljava/util/List;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lil/g;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-direct {v1, v0}, Lil/g;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "allowedDataItemFilters"

    .line 15
    .line 16
    iget-object v2, p0, Lbq/i;->d:Ljava/util/List;

    .line 17
    .line 18
    invoke-virtual {v1, v2, v0}, Lil/g;->a0(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "allowedCapabilities"

    .line 22
    .line 23
    iget-object v2, p0, Lbq/i;->e:Ljava/util/List;

    .line 24
    .line 25
    invoke-virtual {v1, v2, v0}, Lil/g;->a0(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v0, "allowedPackages"

    .line 29
    .line 30
    iget-object p0, p0, Lbq/i;->f:Ljava/util/List;

    .line 31
    .line 32
    invoke-virtual {v1, p0, v0}, Lil/g;->a0(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1}, Lil/g;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const/16 p2, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    const/4 v0, 0x1

    .line 8
    iget-object v1, p0, Lbq/i;->d:Ljava/util/List;

    .line 9
    .line 10
    invoke-static {p1, v0, v1}, Ljp/dc;->r(Landroid/os/Parcel;ILjava/util/List;)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    iget-object v1, p0, Lbq/i;->e:Ljava/util/List;

    .line 15
    .line 16
    invoke-static {p1, v0, v1}, Ljp/dc;->p(Landroid/os/Parcel;ILjava/util/List;)V

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    iget-object p0, p0, Lbq/i;->f:Ljava/util/List;

    .line 21
    .line 22
    invoke-static {p1, v0, p0}, Ljp/dc;->p(Landroid/os/Parcel;ILjava/util/List;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
