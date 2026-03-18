.class public final Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

.field public final h:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

.field public final i:[Ljava/lang/String;

.field public final j:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;Ljava/lang/String;Ljava/lang/String;[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;[Ljava/lang/String;[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->d:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->g:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

    .line 11
    .line 12
    iput-object p5, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->h:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

    .line 13
    .line 14
    iput-object p6, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->i:[Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->j:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;

    .line 17
    .line 18
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
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->d:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/n;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {p1, v2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x3

    .line 20
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->f:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p1, v2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    const/4 v1, 0x4

    .line 26
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->g:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/o;

    .line 27
    .line 28
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x5

    .line 32
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->h:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l;

    .line 33
    .line 34
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 35
    .line 36
    .line 37
    const/4 v1, 0x6

    .line 38
    iget-object v2, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->i:[Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p1, v1, v2}, Ljp/dc;->o(Landroid/os/Parcel;I[Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const/4 v1, 0x7

    .line 44
    iget-object p0, p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j;->j:[Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/g;

    .line 45
    .line 46
    invoke-static {p1, v1, p0, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 47
    .line 48
    .line 49
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 50
    .line 51
    .line 52
    return-void
.end method
