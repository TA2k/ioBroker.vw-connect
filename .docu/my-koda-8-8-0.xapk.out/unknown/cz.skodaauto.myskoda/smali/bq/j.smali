.class public final Lbq/j;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lbq/j;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Landroid/net/Uri;

.field public final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsp/w;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lsp/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lbq/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Landroid/net/Uri;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbq/j;->d:Landroid/net/Uri;

    .line 5
    .line 6
    iput p2, p0, Lbq/j;->e:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lbq/j;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lbq/j;

    .line 8
    .line 9
    iget-object v0, p0, Lbq/j;->d:Landroid/net/Uri;

    .line 10
    .line 11
    iget-object v2, p1, Lbq/j;->d:Landroid/net/Uri;

    .line 12
    .line 13
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    iget p0, p0, Lbq/j;->e:I

    .line 20
    .line 21
    iget p1, p1, Lbq/j;->e:I

    .line 22
    .line 23
    if-ne p0, p1, :cond_1

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_1
    return v1
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lbq/j;->e:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lbq/j;->d:Landroid/net/Uri;

    .line 8
    .line 9
    filled-new-array {p0, v0}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

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
    const-string v0, "uri"

    .line 15
    .line 16
    iget-object v2, p0, Lbq/j;->d:Landroid/net/Uri;

    .line 17
    .line 18
    invoke-virtual {v1, v2, v0}, Lil/g;->a0(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget p0, p0, Lbq/j;->e:I

    .line 22
    .line 23
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    new-instance v0, Lop/a;

    .line 28
    .line 29
    const/16 v2, 0x16

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    invoke-direct {v0, v2, v3}, Lil/g;-><init>(IZ)V

    .line 33
    .line 34
    .line 35
    iget-object v2, v1, Lil/g;->g:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v2, Lil/g;

    .line 38
    .line 39
    iput-object v0, v2, Lil/g;->g:Ljava/lang/Object;

    .line 40
    .line 41
    iput-object v0, v1, Lil/g;->g:Ljava/lang/Object;

    .line 42
    .line 43
    iput-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 44
    .line 45
    const-string p0, "filterType"

    .line 46
    .line 47
    iput-object p0, v0, Lil/g;->e:Ljava/lang/Object;

    .line 48
    .line 49
    invoke-virtual {v1}, Lil/g;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method

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
    iget-object v2, p0, Lbq/j;->d:Landroid/net/Uri;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x4

    .line 14
    const/4 v1, 0x2

    .line 15
    invoke-static {p1, v1, p2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 16
    .line 17
    .line 18
    iget p0, p0, Lbq/j;->e:I

    .line 19
    .line 20
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
